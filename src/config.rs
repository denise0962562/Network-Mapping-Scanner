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
        ("scanner.c_server", cfg.scanner.c_server.is_empty(), "scanner.c_server must not be empty"),
        ("scanner.c_port", cfg.scanner.c_port <= 0, "scanner.c_port must be > 0"),
        ("scanner.rate", cfg.scanner.rate <= 0, "scanner.rate must be > 0"),
        ("email_notify.api", cfg.email_notify.api.is_empty(), "email_notify.api must not be empty"),
        ("email_notify.send_email", cfg.email_notify.send_email.is_empty(), "email_notify.send_email must not be empty"),
        ("email_notify.email", cfg.email_notify.email.is_empty(), "email_notify.email must not be empty"),
        ("database.host", cfg.database.host.is_empty(), "database.host must not be empty"),
        ("database.port", cfg.database.port <= 0, "database.port must be > 0"),
        ("database.db_name", cfg.database.db_name.is_empty(), "database.db_name must not be empty"),
        ("database.username", cfg.database.username.is_empty(), "database.username must not be empty"),
        ("database.password", cfg.database.password.is_empty(), "database.password must not be empty"),
    ];

    for &(field, failed, msg) in rules {
        if failed {
            return Err(ScannerError::Config(format!("{}: {}", field, msg)));
        }
    }

    Ok(())
}
