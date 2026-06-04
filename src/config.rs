use crate::error::ScannerError;
use crate::types::AppConfig;

/// Load and validate the TOML configuration file.
///
/// Reads `filename`, deserializes into `AppConfig`, and validates
/// that all required fields are present and of the correct type.
pub fn load_config(filename: &str) -> Result<AppConfig, ScannerError> {
    let content = std::fs::read_to_string(filename)
        .map_err(|e| ScannerError::Config(format!("无法读取配置文件 {}: {}", filename, e)))?;

    let config: AppConfig = toml::from_str(&content)
        .map_err(|e| ScannerError::Config(format!("解析配置文件失败 {}: {}", filename, e)))?;

    validate_config(&config)?;

    Ok(config)
}

/// Validate configuration fields match expected types and constraints.
fn validate_config(config: &AppConfig) -> Result<(), ScannerError> {
    // Scanner section validation
    if config.scanner.c_server.is_empty() {
        return Err(ScannerError::Config("scanner.c_server 不能为空".into()));
    }
    if config.scanner.c_port <= 0 {
        return Err(ScannerError::Config("scanner.c_port 必须大于 0".into()));
    }
    if config.scanner.rate <= 0 {
        return Err(ScannerError::Config("scanner.rate 必须大于 0".into()));
    }

    // Email notify section validation
    if config.email_notify.api.is_empty() {
        return Err(ScannerError::Config("email_notify.api 不能为空".into()));
    }
    if config.email_notify.send_email.is_empty() {
        return Err(ScannerError::Config(
            "email_notify.send_email 不能为空".into(),
        ));
    }
    if config.email_notify.email.is_empty() {
        return Err(ScannerError::Config("email_notify.email 不能为空".into()));
    }

    // Database section validation
    if config.database.host.is_empty() {
        return Err(ScannerError::Config("database.host 不能为空".into()));
    }
    if config.database.port <= 0 {
        return Err(ScannerError::Config("database.port 必须大于 0".into()));
    }
    if config.database.db_name.is_empty() {
        return Err(ScannerError::Config("database.db_name 不能为空".into()));
    }
    if config.database.username.is_empty() {
        return Err(ScannerError::Config(
            "database.username 不能为空".into(),
        ));
    }
    if config.database.password.is_empty() {
        return Err(ScannerError::Config(
            "database.password 不能为空".into(),
        ));
    }

    Ok(())
}
