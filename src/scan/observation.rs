use serde_json::Value;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ScanObservation {
    Port(PortObservation),
    Service(ServiceObservation),
    Dns(DnsObservation),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct PortObservation {
    pub(crate) ip: String,
    pub(crate) port: u16,
    pub(crate) protocol: String,
    pub(crate) state: String,
    pub(crate) source: String,
    pub(crate) observed_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ServiceObservation {
    pub(crate) ip: String,
    pub(crate) port: u16,
    pub(crate) protocol: String,
    pub(crate) service: Option<String>,
    pub(crate) banner: Option<String>,
    pub(crate) source: String,
    pub(crate) data: Option<Value>,
    pub(crate) observed_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct DnsObservation {
    pub(crate) observed_at: i64,
    pub(crate) question: DnsQuestion,
    pub(crate) response_code: String,
    #[serde(default)]
    pub(crate) authoritative: bool,
    #[serde(default)]
    pub(crate) truncated: bool,
    #[serde(default)]
    pub(crate) dnssec_authenticated: bool,
    #[serde(default)]
    pub(crate) answers: Vec<DnsAnswer>,
    #[serde(default)]
    pub(crate) authority: Vec<DnsAnswer>,
    #[serde(default)]
    pub(crate) additional: Vec<DnsAnswer>,
    pub(crate) resolver_ip: Option<String>,
    pub(crate) resolver_transport: Option<String>,
    pub(crate) latency_ms: Option<u32>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct DnsQuestion {
    pub(crate) name: String,
    #[serde(rename = "type")]
    pub(crate) record_type: String,
    #[serde(default = "default_dns_class")]
    pub(crate) class: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct DnsAnswer {
    #[serde(rename = "type")]
    pub(crate) record_type: String,
    pub(crate) value: String,
    pub(crate) ttl: u32,
    pub(crate) priority: Option<u16>,
    pub(crate) weight: Option<u16>,
    pub(crate) port: Option<u16>,
}

fn default_dns_class() -> String {
    "IN".into()
}

impl ScanObservation {
    pub(crate) fn identity(&self) -> String {
        match self {
            Self::Port(item) => format!("port|{}|{}|{}", item.ip, item.port, item.protocol),
            Self::Service(item) => format!(
                "service|{}|{}|{}|{}|{}",
                item.ip,
                item.port,
                item.protocol,
                item.service.as_deref().unwrap_or(""),
                item.source
            ),
            Self::Dns(item) => format!(
                "dns|{}|{}|{}|{}",
                item.question.name, item.question.record_type, item.response_code, item.observed_at
            ),
        }
    }
}
