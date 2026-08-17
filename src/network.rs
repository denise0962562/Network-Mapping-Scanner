use crate::error::ScannerError;
use crate::types::NetworkConfig;
use reqwest::Client;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct NetworkCapabilities {
    pub(crate) ipv4: NetworkFamilyCapability,
    pub(crate) ipv6: NetworkFamilyCapability,
}

#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct NetworkFamilyCapability {
    supported: bool,
    ready: bool,
    public_ip: Option<String>,
    reason: Option<String>,
}

impl NetworkCapabilities {
    pub(crate) fn is_ready(&self, address_family: &str) -> bool {
        match address_family {
            "ipv4" => self.ipv4.supported && self.ipv4.ready,
            "ipv6" => self.ipv6.supported && self.ipv6.ready,
            _ => false,
        }
    }
}

#[derive(Clone)]
pub(crate) struct SharedNetworkCapabilities(Arc<RwLock<NetworkCapabilities>>);

impl SharedNetworkCapabilities {
    pub(crate) fn new(capabilities: NetworkCapabilities) -> Self {
        Self(Arc::new(RwLock::new(capabilities)))
    }

    pub(crate) async fn get(&self) -> NetworkCapabilities {
        self.0.read().await.clone()
    }

    async fn set(&self, capabilities: NetworkCapabilities) {
        *self.0.write().await = capabilities;
    }
}

#[derive(Clone)]
pub(crate) struct NetworkDetector {
    config: NetworkConfig,
    ipv4_client: Client,
    ipv6_client: Client,
}

impl NetworkDetector {
    pub(crate) fn new(config: NetworkConfig, verify_tls: bool) -> Result<Self, ScannerError> {
        let timeout = Duration::from_secs(config.probe_timeout_seconds.max(1));
        let client = |local_address| {
            Client::builder()
                .danger_accept_invalid_certs(!verify_tls)
                .connect_timeout(timeout)
                .timeout(timeout)
                .local_address(local_address)
                .build()
        };
        Ok(Self {
            config,
            ipv4_client: client(IpAddr::V4(Ipv4Addr::UNSPECIFIED))?,
            ipv6_client: client(IpAddr::V6(Ipv6Addr::UNSPECIFIED))?,
        })
    }

    pub(crate) async fn detect(&self) -> NetworkCapabilities {
        let (ipv4, ipv6) = tokio::join!(
            probe_family(
                &self.ipv4_client,
                &self.config.ipv4_probe_url,
                self.config.ipv4_enabled,
                false,
            ),
            probe_family(
                &self.ipv6_client,
                &self.config.ipv6_probe_url,
                self.config.ipv6_enabled,
                true,
            )
        );
        tracing::info!(
            event = "NetworkCapabilitiesDetected",
            ipv4_supported = ipv4.supported,
            ipv4_ready = ipv4.ready,
            ipv4 = ipv4.public_ip.as_deref().unwrap_or("-"),
            ipv4_reason = ipv4.reason.as_deref().unwrap_or("-"),
            ipv6_supported = ipv6.supported,
            ipv6_ready = ipv6.ready,
            ipv6 = ipv6.public_ip.as_deref().unwrap_or("-"),
            ipv6_reason = ipv6.reason.as_deref().unwrap_or("-"),
            "network protocol detection completed"
        );
        NetworkCapabilities { ipv4, ipv6 }
    }

    pub(crate) fn spawn(self, state: SharedNetworkCapabilities) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let interval = Duration::from_secs(self.config.probe_interval_seconds.max(30));
            loop {
                tokio::time::sleep(interval).await;
                state.set(self.detect().await).await;
            }
        })
    }
}

async fn probe_family(
    client: &Client,
    url: &str,
    enabled: bool,
    expect_ipv6: bool,
) -> NetworkFamilyCapability {
    if !enabled {
        return NetworkFamilyCapability {
            supported: false,
            ready: false,
            public_ip: None,
            reason: Some("disabled_by_configuration".into()),
        };
    }
    if url.trim().is_empty() {
        return unavailable("probe_url_not_configured");
    }
    let response = match client.get(url).send().await {
        Ok(response) => response,
        Err(error) => return unavailable(&format!("probe_request_failed: {error}")),
    };
    if !response.status().is_success() {
        return unavailable(&format!("probe_http_status: {}", response.status()));
    }
    let body = match response.text().await {
        Ok(body) => body,
        Err(error) => return unavailable(&format!("probe_body_failed: {error}")),
    };
    let value = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|json| {
            json.get("ip")
                .and_then(|value| value.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| body.trim().to_owned());
    let address: IpAddr = match value.parse() {
        Ok(address) => address,
        Err(_) => return unavailable("probe_returned_invalid_ip"),
    };
    if address.is_ipv6() != expect_ipv6 {
        return unavailable("probe_returned_wrong_address_family");
    }
    NetworkFamilyCapability {
        supported: true,
        ready: true,
        public_ip: Some(address.to_string()),
        reason: None,
    }
}

fn unavailable(reason: &str) -> NetworkFamilyCapability {
    NetworkFamilyCapability {
        supported: true,
        ready: false,
        public_ip: None,
        reason: Some(reason.chars().take(256).collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::probe_family;
    use reqwest::Client;

    #[tokio::test]
    async fn disabled_family_does_not_probe() {
        let result = probe_family(&Client::new(), "not-a-url", false, true).await;
        assert!(!result.supported);
        assert!(!result.ready);
        assert_eq!(result.reason.as_deref(), Some("disabled_by_configuration"));
    }
}
