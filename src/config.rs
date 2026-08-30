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
    pub(crate) fn has_legacy_runtime_token(&self) -> bool {
        !self.app.scanner.runtime_token.is_empty()
    }

    pub(crate) fn has_legacy_secret(&self) -> bool {
        if self.has_legacy_runtime_token() {
            return true;
        }
        self.raw
            .parse::<toml_edit::DocumentMut>()
            .ok()
            .and_then(|doc| {
                doc.get("scanner")
                    .and_then(toml_edit::Item::as_table)
                    .map(|scanner| scanner.contains_key("token"))
            })
            .unwrap_or(false)
    }

    /// Remove runtime identity from the legacy TOML after it has been stored in SQLite.
    pub(crate) fn clear_legacy_identity(&self) -> Result<(), ScannerError> {
        tracing::debug!(config_path = %self.path, "removing legacy scanner identity");
        let mut doc: toml_edit::DocumentMut = self.raw.parse().map_err(|e| {
            ScannerError::Config(format!("failed to re-parse config for saving: {}", e))
        })?;
        let scanner = doc["scanner"].as_table_mut().ok_or_else(|| {
            ScannerError::Config("scanner configuration must be a TOML table".into())
        })?;
        scanner.remove("token");
        scanner["scanner_id"] = toml_edit::value("");
        scanner["runtime_token"] = toml_edit::value("");
        atomic_write(&self.path, doc.to_string().as_bytes())?;
        tracing::debug!(config_path = %self.path, "legacy scanner identity removed");
        Ok(())
    }
}

fn atomic_write(path: &str, contents: &[u8]) -> Result<(), ScannerError> {
    use std::io::Write;

    let path = std::path::Path::new(path);
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| ScannerError::Config("config path has no valid file name".into()))?;
    let temporary = path.with_file_name(format!(".{file_name}.{}.tmp", uuid::Uuid::now_v7()));
    let original_permissions = std::fs::metadata(path)
        .map_err(ScannerError::Io)?
        .permissions();
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    let write_result = (|| {
        let mut file = options.open(&temporary).map_err(ScannerError::Io)?;
        std::fs::set_permissions(&temporary, original_permissions).map_err(ScannerError::Io)?;
        file.write_all(contents).map_err(ScannerError::Io)?;
        file.sync_all().map_err(ScannerError::Io)
    })();
    if let Err(error) = write_result {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    std::fs::rename(&temporary, path).map_err(ScannerError::Io)?;
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(ScannerError::Io)
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
            "service_detection.max_probes_per_endpoint",
            !(1..=32).contains(&cfg.service_detection.max_probes_per_endpoint),
            "must be between 1 and 32",
        ),
        (
            "service_detection.confidence_threshold",
            !(1..=100).contains(&cfg.service_detection.confidence_threshold),
            "must be between 1 and 100",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clearing_legacy_identity_preserves_other_config_content() {
        let path =
            std::env::temp_dir().join(format!("scanner-config-{}.toml", uuid::Uuid::now_v7()));
        let raw = include_str!("../config.toml")
            .replace(
                "scanner_id = \"\"",
                "scanner_id = \"019c0000-0000-7000-8000-000000000001\"",
            )
            .replace("runtime_token = \"\"", "runtime_token = \"runtime-secret\"")
            .replace("[scanner]", "[scanner]\ntoken = \"one-time-secret\"");
        std::fs::write(&path, raw).unwrap();

        let loaded = load(path.to_str().unwrap()).unwrap();
        assert!(loaded.has_legacy_secret());
        loaded.clear_legacy_identity().unwrap();

        let updated = std::fs::read_to_string(&path).unwrap();
        assert!(updated.contains("# Target API server hostname"));
        assert!(updated.contains("scanner_id = \"\""));
        assert!(updated.contains("runtime_token = \"\""));
        assert!(!updated.contains("one-time-secret"));
        std::fs::remove_file(path).unwrap();
    }
}
