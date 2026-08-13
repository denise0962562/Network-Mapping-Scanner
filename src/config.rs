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
            "scanner.source_port",
            !(1..=65535).contains(&cfg.scanner.source_port),
            "must be between 1 and 65535",
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
            "network.probe_interval_seconds",
            !(30..=86400).contains(&cfg.network.probe_interval_seconds),
            "must be between 30 and 86400",
        ),
        (
            "network.probe_timeout_seconds",
            !(1..=60).contains(&cfg.network.probe_timeout_seconds),
            "must be between 1 and 60",
        ),
    ];

    for &(field, failed, msg) in rules {
        if failed {
            return Err(ScannerError::Config(format!("{}: {}", field, msg)));
        }
    }

    Ok(())
}
