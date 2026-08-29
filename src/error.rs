use reqwest::StatusCode;
use serde::Deserialize;
use std::time::Duration;
use thiserror::Error;

fn maintenance_enabled_by_default() -> bool {
    true
}

fn default_maintenance_retry_seconds() -> u64 {
    600
}

fn default_result_upload_grace_hours() -> u64 {
    24
}

fn default_maintenance_task_action() -> String {
    "finish_and_cache".into()
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct MaintenanceInfo {
    #[serde(default = "maintenance_enabled_by_default")]
    pub(crate) enabled: bool,
    #[serde(default, alias = "maintenance_id")]
    pub(crate) id: Option<uuid::Uuid>,
    pub(crate) phase: String,
    #[serde(default)]
    pub(crate) message: String,
    #[serde(default)]
    pub(crate) started_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub(crate) expected_end_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default = "default_maintenance_retry_seconds")]
    pub(crate) retry_after_seconds: u64,
    #[serde(default = "default_maintenance_task_action")]
    pub(crate) task_action: String,
    #[serde(default = "default_result_upload_grace_hours")]
    pub(crate) result_upload_grace_hours: u64,
    #[serde(default)]
    pub(crate) revision: i64,
}

impl MaintenanceInfo {
    pub(crate) fn retry_delay(&self) -> Duration {
        Duration::from_secs(self.retry_after_seconds.clamp(60, 86_400))
    }

    pub(crate) fn result_upload_grace_ttl(&self) -> Duration {
        Duration::from_secs(
            self.result_upload_grace_hours
                .clamp(1, 24 * 7)
                .saturating_mul(60 * 60),
        )
    }
}

#[derive(Error, Debug)]
pub(crate) enum ServerError {
    #[error("{operation} paused for scanner maintenance: {detail}")]
    Maintenance {
        operation: &'static str,
        detail: String,
        info: Box<MaintenanceInfo>,
    },

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
            Self::Maintenance { info, .. } => Some(info.retry_delay()),
            Self::RetryableStatus { retry_after, .. } => *retry_after,
            _ => None,
        }
    }

    pub(crate) fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Maintenance { .. } => Some(StatusCode::SERVICE_UNAVAILABLE),
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
