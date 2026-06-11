use crate::error::ScannerError;
use crate::types::AppConfig;

/// Parsed config + raw content kept for comment-preserving writes.
pub(crate) struct LoadedConfig {
    pub(crate) app: AppConfig,
    raw: String,
    path: String,
}

pub(crate) fn load(path: &str) -> Result<LoadedConfig, ScannerError> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        ScannerError::Config(format!("cannot read config file {}: {}", path, e))
    })?;

    // Parse for type checking, but keep the raw string for later edits.
    let doc: toml_edit::ImDocument<String> = raw.parse().map_err(|e| {
        ScannerError::Config(format!("failed to parse config {}: {}", path, e))
    })?;

    let app: AppConfig = toml_edit::de::from_document(doc).map_err(|e| {
        ScannerError::Config(format!("failed to deserialize config {}: {}", path, e))
    })?;

    validate(&app)?;
    Ok(LoadedConfig {
        app,
        raw,
        path: path.to_owned(),
    })
}

impl LoadedConfig {
    /// Persist `scanner_id` and `token` back to the `[scanner]` section.
    ///
    /// Re-parses the original file content so that all comments, whitespace,
    /// and ordering are preserved exactly as they were on disk.
    pub(crate) fn save_scanner_identity(&self) -> Result<(), ScannerError> {
        let mut doc: toml_edit::DocumentMut = self.raw.parse().map_err(|e| {
            ScannerError::Config(format!("failed to re-parse config for saving: {}", e))
        })?;
        doc["scanner"]["scanner_id"] = toml_edit::value(&self.app.scanner.scanner_id);
        doc["scanner"]["token"] = toml_edit::value(&self.app.scanner.token);
        std::fs::write(&self.path, doc.to_string()).map_err(ScannerError::Io)
    }
}

fn validate(cfg: &AppConfig) -> Result<(), ScannerError> {
    let rules: &[(&str, bool, &str)] = &[
        ("scanner.c_server", cfg.scanner.c_server.is_empty(), "must not be empty"),
        ("scanner.c_port", cfg.scanner.c_port <= 0, "must be > 0"),
        ("scanner.rate", cfg.scanner.rate <= 0, "must be > 0"),
        ("upload.endpoint", cfg.upload.endpoint.is_empty(), "must not be empty"),
    ];

    for &(field, failed, msg) in rules {
        if failed {
            return Err(ScannerError::Config(format!("{}: {}", field, msg)));
        }
    }

    Ok(())
}
