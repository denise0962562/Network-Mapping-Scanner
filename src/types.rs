use std::collections::HashMap;

/// Database connection information
#[derive(Debug, Clone)]
pub struct DbConnectInfo {
    pub ip: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub db_name: String,
    /// 0 = PostgreSQL (reserved for future multi-DB support)
    #[allow(dead_code)]
    pub db_type: u32,
}

/// An IP entry in the cache — keyed by IP address.
/// The `ip` field mirrors the HashMap key for convenience.
#[derive(Debug, Clone)]
pub struct IpEntry {
    #[allow(dead_code)]
    pub ip: String,
    pub scanner_name: String,
    pub ports: Vec<PortInfo>,
}

/// A single service entry (service name + optional banner)
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    /// Service name (e.g. "ssh", "http"). NULL/None means undiscovered.
    pub service: Option<String>,
    /// Banner text, if any
    pub banner: Option<String>,
}

/// Port information — a port with its protocol and multiple services
#[derive(Debug, Clone)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    pub services: Vec<ServiceInfo>,
}

/// In-memory cache manager for scan results (replaces uthash-based CacheManager)
#[derive(Debug, Default)]
pub struct CacheManager {
    /// IP address → IpEntry mapping
    pub ip_table: HashMap<String, IpEntry>,
    /// Total accumulated records (trigger for batch write)
    pub total_records: u32,
}

/// Parsed scan result from a single masscan output line
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub service: Option<String>,
    pub banner: Option<String>,
}

/// Target parameters received from the HTTP API
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TargetParams {
    pub ip: String,
    pub port: String,
    pub rate: i32,
    #[serde(rename = "source-port")]
    pub source_port: i32,
}

/// Configuration parsed from config.toml
#[derive(Debug, Clone, serde::Deserialize)]
pub struct AppConfig {
    pub scanner: ScannerConfig,
    pub email_notify: EmailNotifyConfig,
    pub database: DatabaseConfig,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ScannerConfig {
    pub c_server: String,
    pub c_port: i64,
    pub rate: i64,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct EmailNotifyConfig {
    pub api: String,
    pub send_email: String,
    pub email: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: i64,
    pub db_name: String,
    pub username: String,
    pub password: String,
}
