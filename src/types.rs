use std::collections::HashMap;

/// Database connection parameters.
#[derive(Debug, Clone)]
pub(crate) struct DbConnectInfo {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) db_name: String,
    pub(crate) username: String,
    pub(crate) password: String,
}

impl DbConnectInfo {
    pub(crate) fn conn_string(&self) -> String {
        format!(
            "host={} port={} dbname={} user={} password={} client_encoding=UTF8",
            self.host, self.port, self.db_name, self.username, self.password
        )
    }
}

/// A single service entry: service name and optional banner.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub(crate) struct PortInfo {
    pub(crate) port: u16,
    pub(crate) protocol: String,
    pub(crate) services: Vec<ServiceInfo>,
}

/// An IP-scoped entry in the scan cache.
#[derive(Debug, Clone)]
pub(crate) struct IpEntry {
    pub(crate) scanner_name: String,
    pub(crate) ports: Vec<PortInfo>,
}

/// In-memory scan result cache. Accumulates results until flushed to the database.
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

// ---- Configuration structures (matching config.toml) ----

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct AppConfig {
    pub(crate) scanner: ScannerConfig,
    pub(crate) email_notify: EmailNotifyConfig,
    pub(crate) database: DatabaseConfig,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct ScannerConfig {
    pub(crate) c_server: String,
    pub(crate) c_port: i64,
    pub(crate) rate: i64,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct EmailNotifyConfig {
    pub(crate) api: String,
    pub(crate) send_email: String,
    pub(crate) email: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct DatabaseConfig {
    pub(crate) host: String,
    pub(crate) port: i64,
    pub(crate) db_name: String,
    pub(crate) username: String,
    pub(crate) password: String,
}

impl From<&DatabaseConfig> for DbConnectInfo {
    fn from(cfg: &DatabaseConfig) -> Self {
        Self {
            host: cfg.host.clone(),
            port: cfg.port as u16,
            db_name: cfg.db_name.clone(),
            username: cfg.username.clone(),
            password: cfg.password.clone(),
        }
    }
}
