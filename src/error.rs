use std::fmt;

/// Unified error type for the scanner application.
///
/// Each variant carries a human-readable message. For types that implement
/// `std::error::Error` (I/O, JSON), the source error is preserved via the
/// `source()` method so error chains remain inspectable.
#[derive(Debug)]
pub enum ScannerError {
    /// File or filesystem I/O error.
    Io(std::io::Error),
    /// TOML deserialization error.
    Toml(String),
    /// JSON serialization / deserialization error.
    Json(serde_json::Error),
    /// HTTP request error (reqwest).
    Http(String),
    /// PostgreSQL / tokio-postgres error.
    Database(String),
    /// Configuration validation error.
    Config(String),
    /// Scanner / masscan execution error.
    Scan(String),
    /// Target validation / health-check error.
    HealthCheck(String),
}

impl fmt::Display for ScannerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScannerError::Io(e) => write!(f, "I/O 错误: {}", e),
            ScannerError::Toml(s) => write!(f, "TOML 解析错误: {}", s),
            ScannerError::Json(e) => write!(f, "JSON 错误: {}", e),
            ScannerError::Http(s) => write!(f, "HTTP 错误: {}", s),
            ScannerError::Database(s) => write!(f, "数据库错误: {}", s),
            ScannerError::Config(s) => write!(f, "配置错误: {}", s),
            ScannerError::Scan(s) => write!(f, "扫描错误: {}", s),
            ScannerError::HealthCheck(s) => write!(f, "健康检查错误: {}", s),
        }
    }
}

impl std::error::Error for ScannerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ScannerError::Io(e) => Some(e),
            ScannerError::Json(e) => Some(e),
            _ => None,
        }
    }
}

// ---- From impls ---- automates `?` propagation via `.into()` ----

impl From<std::io::Error> for ScannerError {
    fn from(e: std::io::Error) -> Self {
        ScannerError::Io(e)
    }
}

impl From<serde_json::Error> for ScannerError {
    fn from(e: serde_json::Error) -> Self {
        ScannerError::Json(e)
    }
}

impl From<reqwest::Error> for ScannerError {
    fn from(e: reqwest::Error) -> Self {
        ScannerError::Http(e.to_string())
    }
}

impl From<tokio_postgres::Error> for ScannerError {
    fn from(e: tokio_postgres::Error) -> Self {
        ScannerError::Database(e.to_string())
    }
}

impl From<toml::de::Error> for ScannerError {
    fn from(e: toml::de::Error) -> Self {
        ScannerError::Toml(e.to_string())
    }
}
