use std::net::Ipv4Addr;
use uuid::Uuid;

// ---- Cache data model ---------------------------------------------------

/// In-memory scan result cache. Accumulates results until flushed.
#[derive(Debug, Default)]
pub(crate) struct CacheManager {
    pub(crate) task_id: Option<Uuid>,
    pub(crate) upload_id: Option<Uuid>,
    pub(crate) observations: Vec<crate::scan::ScanObservation>,
    pub(crate) next_batch_index: u32,
}

impl CacheManager {
    pub(crate) fn clear(&mut self) {
        self.task_id = None;
        self.upload_id = None;
        self.observations.clear();
        self.next_batch_index = 0;
    }
}

/// Task assigned by the server.
#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct AssignedTask {
    pub(crate) task_id: Uuid,
    pub(crate) task_target: Vec<String>,
    pub(crate) task_port: String,
    #[serde(default = "default_address_family")]
    pub(crate) address_family: String,
    #[serde(default)]
    pub(crate) scan_plan: Option<crate::scan::ScanPlan>,
    #[serde(default)]
    pub(crate) lease_expires_at_ms: Option<i64>,
    #[serde(default = "default_task_lease_ttl_ms")]
    pub(crate) lease_ttl_ms: u64,
}

impl AssignedTask {
    pub(crate) fn validate_targets(&self) -> Result<(), String> {
        for target in &self.task_target {
            let address = target
                .split_once('/')
                .map_or(target.as_str(), |(address, _)| address)
                .trim();
            if address
                .parse::<Ipv4Addr>()
                .is_ok_and(|address| address.octets()[0] == 0)
            {
                return Err(format!(
                    "task target {target} belongs to the non-routable 0.0.0.0/8 network"
                ));
            }
        }
        Ok(())
    }
}

fn default_address_family() -> String {
    "ipv4".into()
}

fn default_task_lease_ttl_ms() -> u64 {
    90_000
}

/// Parameters passed to masscan after applying local scanner settings.
#[derive(Debug, Clone)]
pub(crate) struct TargetParams {
    pub(crate) ip: String,
    pub(crate) port: String,
    pub(crate) rate: i32,
    pub(crate) address_family: String,
}

// ---- Upload payload -----------------------------------------------------

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ScannerResultBatchUpload {
    pub(crate) protocol_version: u16,
    pub(crate) scanner_id: Uuid,
    pub(crate) task_id: Uuid,
    pub(crate) upload_id: Uuid,
    pub(crate) batch_index: u32,
    pub(crate) is_final: bool,
    pub(crate) observations: Vec<crate::scan::ScanObservation>,
}

// ---- Configuration structures -------------------------------------------

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct AppConfig {
    pub(crate) scanner: ScannerConfig,
    pub(crate) upload: UploadConfig,
    #[serde(default)]
    pub(crate) network: NetworkConfig,
    #[serde(default)]
    pub(crate) service_detection: ServiceDetectionConfig,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
pub(crate) struct ServiceDetectionConfig {
    pub(crate) enabled: bool,
    pub(crate) required: bool,
    pub(crate) strategy: ServiceDetectionStrategy,
    pub(crate) max_probes_per_endpoint: usize,
    pub(crate) confidence_threshold: u8,
    pub(crate) zgrab_path: String,
    pub(crate) senders: u32,
    pub(crate) server_rate_limit: u32,
    pub(crate) connect_timeout_seconds: u64,
    pub(crate) target_timeout_seconds: u64,
    pub(crate) max_result_bytes: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ServiceDetectionStrategy {
    #[default]
    Standard,
    Adaptive,
    Exhaustive,
}

impl ServiceDetectionStrategy {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Adaptive => "adaptive",
            Self::Exhaustive => "exhaustive",
        }
    }
}

impl Default for ServiceDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            required: false,
            strategy: ServiceDetectionStrategy::Standard,
            max_probes_per_endpoint: 8,
            confidence_threshold: 80,
            zgrab_path: "zgrab2".into(),
            senders: 200,
            server_rate_limit: 20,
            connect_timeout_seconds: 5,
            target_timeout_seconds: 15,
            max_result_bytes: 65_536,
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
pub(crate) struct NetworkConfig {
    pub(crate) ipv4_enabled: bool,
    pub(crate) ipv6_enabled: bool,
    pub(crate) ipv4_probe_url: String,
    pub(crate) ipv6_probe_url: String,
    pub(crate) probe_interval_seconds: u64,
    pub(crate) probe_timeout_seconds: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            ipv4_enabled: true,
            ipv6_enabled: true,
            ipv4_probe_url: "https://api.ipify.org?format=json".into(),
            ipv6_probe_url: "https://api6.ipify.org?format=json".into(),
            probe_interval_seconds: 300,
            probe_timeout_seconds: 5,
        }
    }
}

fn default_scanner_path() -> String {
    "./a".into()
}

fn default_scanner_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct ScannerConfig {
    pub(crate) c_server: String,
    pub(crate) c_port: i64,
    pub(crate) rate: i64,
    #[serde(default)]
    pub(crate) verify_tls: bool,
    #[serde(default = "default_scanner_path")]
    pub(crate) scanner_path: String,
    /// Scanner identity — auto-generated UUIDv7 on first run.
    #[serde(default = "default_scanner_id")]
    pub(crate) scanner_id: String,
    /// Runtime token returned after one-time registration.
    #[serde(default)]
    pub(crate) runtime_token: String,
    #[serde(default = "default_heartbeat_interval")]
    pub(crate) heartbeat_interval_seconds: u64,
    #[serde(default = "default_connect_timeout")]
    pub(crate) connect_timeout_seconds: u64,
    #[serde(default = "default_request_timeout")]
    pub(crate) request_timeout_seconds: u64,
    #[serde(default = "default_reconnect_initial_delay")]
    pub(crate) reconnect_initial_delay_seconds: u64,
    #[serde(default = "default_reconnect_max_delay")]
    pub(crate) reconnect_max_delay_seconds: u64,
    #[serde(default = "default_active_task_reconnect_max_delay")]
    pub(crate) active_task_reconnect_max_delay_seconds: u64,
    #[serde(default = "default_lease_safety_margin")]
    pub(crate) lease_safety_margin_seconds: u64,
}

impl ScannerConfig {
    pub(crate) fn task_url(&self, dry_run: bool) -> String {
        let mut url = format!(
            "https://{}:{}/api/task/apply?scannerid={}",
            self.c_server, self.c_port, self.scanner_id
        );
        if dry_run {
            url.push_str("&dryrun=true");
        }
        url
    }

    pub(crate) fn heartbeat_url(&self) -> String {
        format!(
            "https://{}:{}/api/scanner/heartbeat",
            self.c_server, self.c_port
        )
    }

    pub(crate) fn task_failure_url(&self) -> String {
        format!(
            "https://{}:{}/api/scanner/task/fail",
            self.c_server, self.c_port
        )
    }

    pub(crate) fn task_cancelled_url(&self) -> String {
        format!(
            "https://{}:{}/api/scanner/task/cancelled",
            self.c_server, self.c_port
        )
    }
}

fn default_heartbeat_interval() -> u64 {
    30
}

fn default_connect_timeout() -> u64 {
    5
}

fn default_request_timeout() -> u64 {
    15
}

fn default_reconnect_initial_delay() -> u64 {
    1
}

fn default_reconnect_max_delay() -> u64 {
    60
}

fn default_active_task_reconnect_max_delay() -> u64 {
    10
}

fn default_lease_safety_margin() -> u64 {
    10
}

#[cfg(test)]
mod tests {
    use super::{AssignedTask, ScannerConfig};

    #[test]
    fn assigned_task_matches_server_response() {
        let task: AssignedTask = serde_json::from_str(
            r#"{
                "user_id": 7,
                "task_id": "019c0000-0000-7000-8000-000000000001",
                "task_target": ["192.0.2.0/24", "198.51.100.10"],
                "task_port": "80,443"
            }"#,
        )
        .expect("server task response must deserialize");

        assert_eq!(task.task_target.len(), 2);
        assert_eq!(task.task_port, "80,443");
        assert_eq!(task.address_family, "ipv4");
        assert_eq!(task.lease_ttl_ms, 90_000);
        assert_eq!(task.lease_expires_at_ms, None);
    }

    #[test]
    fn assigned_task_accepts_explicit_server_lease() {
        let task: AssignedTask = serde_json::from_str(
            r#"{
                "task_id": "019c0000-0000-7000-8000-000000000001",
                "task_target": ["192.0.2.1"],
                "task_port": "443",
                "lease_expires_at_ms": 1770000000000,
                "lease_ttl_ms": 120000
            }"#,
        )
        .unwrap();

        assert_eq!(task.lease_expires_at_ms, Some(1_770_000_000_000));
        assert_eq!(task.lease_ttl_ms, 120_000);
    }

    #[test]
    fn task_url_contains_scanner_identity_and_dry_run_flag() {
        let config = ScannerConfig {
            c_server: "scanner.example".into(),
            c_port: 443,
            rate: 1_000,
            verify_tls: true,
            scanner_path: "masscan".into(),
            scanner_id: "019c0000-0000-7000-8000-000000000001".into(),
            runtime_token: "secret".into(),
            heartbeat_interval_seconds: 30,
            connect_timeout_seconds: 5,
            request_timeout_seconds: 15,
            reconnect_initial_delay_seconds: 1,
            reconnect_max_delay_seconds: 60,
            active_task_reconnect_max_delay_seconds: 10,
            lease_safety_margin_seconds: 10,
        };

        assert_eq!(
            config.task_url(true),
            "https://scanner.example:443/api/task/apply?scannerid=019c0000-0000-7000-8000-000000000001&dryrun=true"
        );
        assert_eq!(
            config.heartbeat_url(),
            "https://scanner.example:443/api/scanner/heartbeat"
        );
        assert_eq!(
            config.task_failure_url(),
            "https://scanner.example:443/api/scanner/task/fail"
        );
    }

    #[test]
    fn legacy_registration_token_is_not_used_as_runtime_token() {
        let config: ScannerConfig = serde_json::from_str(
            r#"{
                "c_server": "scanner.example",
                "c_port": 443,
                "rate": 1000,
                "source_port": 61000,
                "scanner_id": "019c0000-0000-7000-8000-000000000001",
                "token": "one-time-secret"
            }"#,
        )
        .expect("legacy scanner config must remain readable");

        assert!(config.runtime_token.is_empty());
        assert_eq!(config.connect_timeout_seconds, 5);
        assert_eq!(config.request_timeout_seconds, 15);
        assert_eq!(config.reconnect_max_delay_seconds, 60);
    }

    #[test]
    fn assigned_task_rejects_zero_network_targets() {
        let mut task: AssignedTask = serde_json::from_str(
            r#"{
                "task_id": "019c0000-0000-7000-8000-000000000001",
                "task_target": ["0.0.17.0/24"],
                "task_port": "80"
            }"#,
        )
        .unwrap();

        assert!(task.validate_targets().is_err());
        task.task_target = vec!["1.0.0.0/24".into()];
        assert!(task.validate_targets().is_ok());
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct UploadConfig {
    /// Full HTTPS URL where scan results are POSTed as JSON.
    pub(crate) endpoint: String,
}
