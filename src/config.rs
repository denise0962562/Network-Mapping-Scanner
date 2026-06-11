use crate::error::ScannerError;
use crate::types::AppConfig;

pub(crate) fn load_config(path: &str) -> Result<AppConfig, ScannerError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        ScannerError::Config(format!("cannot read config file {}: {}", path, e))
    })?;

    let config: AppConfig = toml::from_str(&content).map_err(|e| {
        ScannerError::Config(format!("failed to parse config {}: {}", path, e))
    })?;

    validate(&config)?;
    Ok(config)
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
