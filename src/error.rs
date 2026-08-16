use reqwest::StatusCode;
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum ServerError {
    #[error("{operation} timed out: {detail}")]
    Timeout {
        operation: &'static str,
        detail: String,
    },

    #[error("{operation} could not connect: {detail}")]
    Connect {
        operation: &'static str,
        detail: String,
    },

    #[error("{operation} transport failed: {detail}")]
    Transport {
        operation: &'static str,
        detail: String,
    },

    #[error("{operation} returned retryable status {status}: {detail}")]
    RetryableStatus {
        operation: &'static str,
        status: StatusCode,
        detail: String,
        retry_after: Option<Duration>,
    },

    #[error("{operation} rejected the runtime token: {detail}")]
    AuthRejected {
        operation: &'static str,
        detail: String,
    },

    #[error("{operation} was blocked by server policy: {detail}")]
    PolicyBlocked {
        operation: &'static str,
        detail: String,
    },

    #[error("{operation} returned {status}: {detail}")]
    Rejected {
        operation: &'static str,
        status: StatusCode,
        detail: String,
    },

    #[error("{operation} returned an invalid response: {detail}")]
    InvalidResponse {
        operation: &'static str,
        detail: String,
    },

    #[error("{operation} could not build a valid request: {detail}")]
    InvalidRequest {
        operation: &'static str,
        detail: String,
    },

    #[error("failed to build server HTTP client: {0}")]
    ClientBuild(String),
}

impl ServerError {
    pub(crate) fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Timeout { .. }
                | Self::Connect { .. }
                | Self::Transport { .. }
                | Self::RetryableStatus { .. }
        )
    }

    pub(crate) fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RetryableStatus { retry_after, .. } => *retry_after,
            _ => None,
        }
    }

    pub(crate) fn status(&self) -> Option<StatusCode> {
        match self {
            Self::RetryableStatus { status, .. } | Self::Rejected { status, .. } => Some(*status),
            Self::AuthRejected { .. } => Some(StatusCode::UNAUTHORIZED),
            Self::PolicyBlocked { .. } => Some(StatusCode::FORBIDDEN),
            _ => None,
        }
    }
}

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

    #[error(transparent)]
    Server(#[from] ServerError),
}

impl From<toml_edit::de::Error> for ScannerError {
    fn from(e: toml_edit::de::Error) -> Self {
        Self::Toml(e.to_string())
    }
}

impl From<reqwest::Error> for ScannerError {
    fn from(e: reqwest::Error) -> Self {
        Self::Http(e.to_string())
    }
}
