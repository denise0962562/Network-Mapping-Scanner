use serde_json::Value;

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ScanObservation {
    Port(PortObservation),
    Service(ServiceObservation),
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct PortObservation {
    pub(crate) ip: String,
    pub(crate) port: u16,
    pub(crate) protocol: String,
    pub(crate) state: &'static str,
    pub(crate) source: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ServiceObservation {
    pub(crate) ip: String,
    pub(crate) port: u16,
    pub(crate) protocol: String,
    pub(crate) service: Option<String>,
    pub(crate) banner: Option<String>,
    pub(crate) source: &'static str,
    pub(crate) data: Option<Value>,
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
