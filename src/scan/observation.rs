use serde_json::Value;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ScanObservation {
    Port(PortObservation),
    Service(ServiceObservation),
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
        }
    }
}
