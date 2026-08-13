use std::collections::HashMap;
use uuid::Uuid;

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
    pub(crate) ports: Vec<PortInfo>,
}

/// In-memory scan result cache. Accumulates results until flushed.
#[derive(Debug, Default)]
pub(crate) struct CacheManager {
    pub(crate) task_id: Option<Uuid>,
    pub(crate) ip_table: HashMap<String, IpEntry>,
    pub(crate) total_records: u32,
}

impl CacheManager {
    pub(crate) fn clear(&mut self) {
        self.task_id = None;
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

/// Task assigned by the server.
#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct AssignedTask {
    pub(crate) task_id: Uuid,
    pub(crate) task_target: Vec<String>,
    pub(crate) task_port: String,
    #[serde(default = "default_address_family")]
    pub(crate) address_family: String,
}

fn default_address_family() -> String {
    "ipv4".into()
}

/// Parameters passed to masscan after applying local scanner settings.
#[derive(Debug, Clone)]
pub(crate) struct TargetParams {
    pub(crate) ip: String,
    pub(crate) port: String,
    pub(crate) rate: i32,
    pub(crate) source_port: i32,
}

// ---- Upload payload -----------------------------------------------------

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ScannerResultItem {
    pub(crate) ip: String,
    pub(crate) port: u16,
    pub(crate) protocol: Option<String>,
    pub(crate) service: Option<String>,
    pub(crate) banner: Option<String>,
    pub(crate) other: Option<serde_json::Value>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ScannerResultUpload {
    pub(crate) scanner_id: Uuid,
    pub(crate) task_id: Uuid,
    pub(crate) results: Vec<ScannerResultItem>,
}

// ---- Configuration structures -------------------------------------------

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct AppConfig {
    pub(crate) scanner: ScannerConfig,
    pub(crate) upload: UploadConfig,
    #[serde(default)]
    pub(crate) network: NetworkConfig,
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
    #[serde(default = "default_source_port")]
    pub(crate) source_port: i32,
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

fn default_source_port() -> i32 {
    61_000
}

fn default_heartbeat_interval() -> u64 {
    30
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
    }

    #[test]
    fn task_url_contains_scanner_identity_and_dry_run_flag() {
        let config = ScannerConfig {
            c_server: "scanner.example".into(),
            c_port: 443,
            rate: 1_000,
            source_port: 61_000,
            verify_tls: true,
            scanner_path: "masscan".into(),
            scanner_id: "019c0000-0000-7000-8000-000000000001".into(),
            runtime_token: "secret".into(),
            heartbeat_interval_seconds: 30,
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
                "scanner_id": "019c0000-0000-7000-8000-000000000001",
                "token": "one-time-secret"
            }"#,
        )
        .expect("legacy scanner config must remain readable");

        assert!(config.runtime_token.is_empty());
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct UploadConfig {
    /// Full HTTPS URL where scan results are POSTed as JSON.
    pub(crate) endpoint: String,
}
