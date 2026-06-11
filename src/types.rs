use std::collections::HashMap;

// ---- Cache data model ---------------------------------------------------

/// A single service entry: service name and optional banner.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ServiceInfo {
    pub(crate) name: Option<String>,
    pub(crate) banner: Option<String>,
}

impl ServiceInfo {
    pub(crate) fn is_placeholder(&self) -> bool {
        self.name.is_none()
    }
}

/// Per-port information: port number, protocol, and associated services.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct PortInfo {
    pub(crate) port: u16,
    pub(crate) protocol: String,
    pub(crate) services: Vec<ServiceInfo>,
}

/// An IP-scoped entry in the scan cache.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct IpEntry {
    pub(crate) scanner_name: String,
    pub(crate) ports: Vec<PortInfo>,
}

/// In-memory scan result cache. Accumulates results until flushed.
#[derive(Debug, Default)]
pub(crate) struct CacheManager {
    pub(crate) ip_table: HashMap<String, IpEntry>,
    pub(crate) total_records: u32,
}

impl CacheManager {
    pub(crate) fn clear(&mut self) {
        self.ip_table.clear();
        self.total_records = 0;
    }
}

/// A single parsed line from masscan stdout.
#[derive(Debug, Clone)]
pub(crate) struct ScanResult {
    pub(crate) ip: String,
    pub(crate) port: u16,
    pub(crate) protocol: String,
    pub(crate) service: Option<String>,
    pub(crate) banner: Option<String>,
}

/// Target parameters received from the HTTP target API.
#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct TargetParams {
    pub(crate) ip: String,
    pub(crate) port: String,
    pub(crate) rate: i32,
    #[serde(rename = "source-port")]
    pub(crate) source_port: i32,
}

// ---- Upload payload -----------------------------------------------------

/// Flat upload entry — one per (ip, port, service) tuple.
/// Designed so the server can consume each entry independently.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct UploadEntry {
    pub(crate) ip: String,
    pub(crate) port: u16,
    pub(crate) protocol: String,
    pub(crate) scanner_name: String,
    pub(crate) service: Option<String>,
    pub(crate) banner: Option<String>,
    pub(crate) scan_time: i64,
}

// ---- Configuration structures -------------------------------------------

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct AppConfig {
    pub(crate) scanner: ScannerConfig,
    pub(crate) upload: UploadConfig,
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
    /// Registration token issued by the server.
    #[serde(default)]
    pub(crate) token: String,
}

impl ScannerConfig {
    /// Build the HTTPS target URL from configured server and port.
    pub(crate) fn target_url(&self) -> String {
        format!("https://{}:{}/scanner/target", self.c_server, self.c_port)
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct UploadConfig {
    /// Full HTTPS URL where scan results are POSTed as JSON.
    pub(crate) endpoint: String,
}
