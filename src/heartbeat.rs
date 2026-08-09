use crate::error::ScannerError;
use crate::sysinfo::SystemInfo;
use reqwest::Client;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

const USER_AGENT: &str = "Scanner/1.0";

#[derive(Clone, Default)]
pub(crate) struct ActiveTask(Arc<RwLock<Option<Uuid>>>);

impl ActiveTask {
    pub(crate) async fn get(&self) -> Option<Uuid> {
        *self.0.read().await
    }

    pub(crate) async fn set(&self, task_id: Uuid) {
        *self.0.write().await = Some(task_id);
    }

    pub(crate) async fn clear(&self) {
        *self.0.write().await = None;
    }
}

#[derive(Serialize)]
struct HeartbeatPayload {
    scanner_id: Uuid,
    state: &'static str,
    active_task_id: Option<Uuid>,
    scanner_version: &'static str,
    system: SystemInfo,
}

#[derive(Serialize)]
struct TaskFailurePayload<'a> {
    scanner_id: Uuid,
    task_id: Uuid,
    error: &'a str,
    retryable: bool,
}

#[derive(Clone)]
pub(crate) struct HeartbeatClient {
    client: Client,
    heartbeat_url: String,
    failure_url: String,
    runtime_token: String,
    scanner_id: Uuid,
}

impl HeartbeatClient {
    pub(crate) fn new(
        heartbeat_url: String,
        failure_url: String,
        verify_tls: bool,
        runtime_token: String,
        scanner_id: Uuid,
    ) -> Result<Self, ScannerError> {
        let client = Client::builder()
            .user_agent(USER_AGENT)
            .danger_accept_invalid_certs(!verify_tls)
            .build()?;
        Ok(Self {
            client,
            heartbeat_url,
            failure_url,
            runtime_token,
            scanner_id,
        })
    }

    pub(crate) async fn send(
        &self,
        active_task_id: Option<Uuid>,
        stopping: bool,
    ) -> Result<(), ScannerError> {
        let state = if stopping {
            "stopping"
        } else if active_task_id.is_some() {
            "scanning"
        } else {
            "idle"
        };
        let payload = HeartbeatPayload {
            scanner_id: self.scanner_id,
            state,
            active_task_id,
            scanner_version: env!("CARGO_PKG_VERSION"),
            system: SystemInfo::gather()?,
        };
        let response = self
            .client
            .post(&self.heartbeat_url)
            .bearer_auth(&self.runtime_token)
            .json(&payload)
            .send()
            .await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(ScannerError::Http(format!(
                "heartbeat endpoint returned {}",
                response.status()
            )))
        }
    }

    pub(crate) async fn report_failure(
        &self,
        task_id: Uuid,
        error: &str,
    ) -> Result<(), ScannerError> {
        let payload = TaskFailurePayload {
            scanner_id: self.scanner_id,
            task_id,
            error,
            retryable: true,
        };
        let response = self
            .client
            .post(&self.failure_url)
            .bearer_auth(&self.runtime_token)
            .json(&payload)
            .send()
            .await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(ScannerError::Http(format!(
                "task failure endpoint returned {}",
                response.status()
            )))
        }
    }
}
