use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum ScannerError {
    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Toml(String),

    #[error("{0}")]
    Http(String),

    #[error("{0}")]
    Upload(String),

    #[error("{0}")]
    Config(String),

    #[error("{0}")]
    Scan(String),

    #[error("{0}")]
    HealthCheck(String),
}

impl From<toml::de::Error> for ScannerError {
    fn from(e: toml::de::Error) -> Self {
        Self::Toml(e.to_string())
    }
}

impl From<reqwest::Error> for ScannerError {
    fn from(e: reqwest::Error) -> Self {
        Self::Http(e.to_string())
    }
}
