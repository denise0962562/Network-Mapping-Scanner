use crate::error::ScannerError;
use crate::types::AppConfig;

/// Parsed config + raw content kept for comment-preserving writes.
pub(crate) struct LoadedConfig {
    pub(crate) app: AppConfig,
    raw: String,
    path: String,
}

pub(crate) fn load(path: &str) -> Result<LoadedConfig, ScannerError> {
    tracing::debug!(config_path = path, "reading scanner configuration");
    let raw = std::fs::read_to_string(path)
        .map_err(|e| ScannerError::Config(format!("cannot read config file {}: {}", path, e)))?;

    // Parse for type checking, but keep the raw string for later edits.
    let doc: toml_edit::ImDocument<String> = raw
        .parse()
        .map_err(|e| ScannerError::Config(format!("failed to parse config {}: {}", path, e)))?;

    let app: AppConfig = toml_edit::de::from_document(doc).map_err(|e| {
        ScannerError::Config(format!("failed to deserialize config {}: {}", path, e))
    })?;

    validate(&app)?;
    tracing::debug!(
        config_path = path,
        config_bytes = raw.len(),
        "configuration parsed"
    );
    Ok(LoadedConfig {
        app,
        raw,
        path: path.to_owned(),
    })
}

impl LoadedConfig {
    /// Persist `scanner_id` and the runtime token back to `[scanner]`.
    ///
    /// Re-parses the original file content so that all comments, whitespace,
    /// and ordering are preserved exactly as they were on disk.
    pub(crate) fn save_scanner_identity(&self) -> Result<(), ScannerError> {
        tracing::debug!(config_path = %self.path, "persisting scanner identity");
        let mut doc: toml_edit::DocumentMut = self.raw.parse().map_err(|e| {
            ScannerError::Config(format!("failed to re-parse config for saving: {}", e))
        })?;
        let scanner = doc["scanner"].as_table_mut().ok_or_else(|| {
            ScannerError::Config("scanner configuration must be a TOML table".into())
        })?;
        scanner.remove("token");
        scanner["scanner_id"] = toml_edit::value(&self.app.scanner.scanner_id);
        scanner["runtime_token"] = toml_edit::value(&self.app.scanner.runtime_token);
        std::fs::write(&self.path, doc.to_string()).map_err(ScannerError::Io)?;
        tracing::debug!(config_path = %self.path, "scanner identity persisted");
        Ok(())
    }
}

fn validate(cfg: &AppConfig) -> Result<(), ScannerError> {
    let rules: &[(&str, bool, &str)] = &[
        (
            "scanner.c_server",
            cfg.scanner.c_server.is_empty(),
            "must not be empty",
        ),
        ("scanner.c_port", cfg.scanner.c_port <= 0, "must be > 0"),
        (
            "scanner.rate",
            cfg.scanner.rate <= 0 || cfg.scanner.rate > i64::from(i32::MAX),
            "must be between 1 and 2147483647",
        ),
        (
            "upload.endpoint",
            cfg.upload.endpoint.is_empty(),
            "must not be empty",
        ),
        (
            "scanner.heartbeat_interval_seconds",
            !(5..=300).contains(&cfg.scanner.heartbeat_interval_seconds),
            "must be between 5 and 300",
        ),
        (
            "scanner.connect_timeout_seconds",
            !(1..=60).contains(&cfg.scanner.connect_timeout_seconds),
            "must be between 1 and 60",
        ),
        (
            "scanner.request_timeout_seconds",
            cfg.scanner.request_timeout_seconds < cfg.scanner.connect_timeout_seconds
                || cfg.scanner.request_timeout_seconds > 300,
            "must be at least connect_timeout_seconds and at most 300",
        ),
        (
            "scanner.reconnect_initial_delay_seconds",
            !(1..=60).contains(&cfg.scanner.reconnect_initial_delay_seconds),
            "must be between 1 and 60",
        ),
        (
            "scanner.reconnect_max_delay_seconds",
            cfg.scanner.reconnect_max_delay_seconds < cfg.scanner.reconnect_initial_delay_seconds
                || cfg.scanner.reconnect_max_delay_seconds > 600,
            "must be at least reconnect_initial_delay_seconds and at most 600",
        ),
        (
            "scanner.active_task_reconnect_max_delay_seconds",
            cfg.scanner.active_task_reconnect_max_delay_seconds == 0
                || cfg.scanner.active_task_reconnect_max_delay_seconds
                    > cfg.scanner.reconnect_max_delay_seconds,
            "must be between 1 and reconnect_max_delay_seconds",
        ),
        (
            "scanner.lease_safety_margin_seconds",
            !(1..=60).contains(&cfg.scanner.lease_safety_margin_seconds),
            "must be between 1 and 60",
        ),
        (
            "network.probe_interval_seconds",
            !(30..=86400).contains(&cfg.network.probe_interval_seconds),
            "must be between 30 and 86400",
        ),
        (
            "network.probe_timeout_seconds",
            !(1..=60).contains(&cfg.network.probe_timeout_seconds),
            "must be between 1 and 60",
        ),
        (
            "service_detection.zgrab_path",
            cfg.service_detection.enabled && cfg.service_detection.zgrab_path.trim().is_empty(),
            "must not be empty when service detection is enabled",
        ),
        (
            "service_detection.senders",
            !(1..=10_000).contains(&cfg.service_detection.senders),
            "must be between 1 and 10000",
        ),
        (
            "service_detection.server_rate_limit",
            !(1..=10_000).contains(&cfg.service_detection.server_rate_limit),
            "must be between 1 and 10000",
        ),
        (
            "service_detection.connect_timeout_seconds",
            !(1..=60).contains(&cfg.service_detection.connect_timeout_seconds),
            "must be between 1 and 60",
        ),
        (
            "service_detection.target_timeout_seconds",
            cfg.service_detection.target_timeout_seconds
                < cfg.service_detection.connect_timeout_seconds
                || cfg.service_detection.target_timeout_seconds > 300,
            "must be at least connect_timeout_seconds and at most 300",
        ),
        (
            "service_detection.max_result_bytes",
            !(1_024..=1_048_576).contains(&cfg.service_detection.max_result_bytes),
            "must be between 1024 and 1048576",
        ),
    ];

    for &(field, failed, msg) in rules {
        if failed {
            return Err(ScannerError::Config(format!("{}: {}", field, msg)));
        }
    }

    Ok(())
}
