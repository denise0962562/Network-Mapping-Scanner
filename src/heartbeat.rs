use crate::error::ScannerError;
use crate::network::{NetworkCapabilities, SharedNetworkCapabilities};
use crate::scan::ScanCapabilities;
use crate::sysinfo::SystemInfo;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::RwLock;
use uuid::Uuid;

const USER_AGENT: &str = "Scanner/1.0";

#[derive(Clone, Default)]
pub(crate) struct ActiveTask {
    current: Arc<RwLock<Option<Uuid>>>,
    cancel_requested: Arc<AtomicBool>,
}

impl ActiveTask {
    pub(crate) async fn get(&self) -> Option<Uuid> {
        *self.current.read().await
    }

    pub(crate) async fn set(&self, task_id: Uuid) {
        self.cancel_requested.store(false, Ordering::Relaxed);
        *self.current.write().await = Some(task_id);
        tracing::debug!(%task_id, "active task set");
    }

    pub(crate) async fn clear(&self) {
        let previous_task_id = *self.current.read().await;
        *self.current.write().await = None;
        self.cancel_requested.store(false, Ordering::Relaxed);
        tracing::debug!(?previous_task_id, "active task cleared");
    }

    pub(crate) async fn request_cancel(&self, task_id: Uuid) {
        let active_task_id = self.get().await;
        if active_task_id == Some(task_id) {
            self.cancel_requested.store(true, Ordering::Relaxed);
            tracing::debug!(%task_id, "cancellation requested for active task");
        } else {
            tracing::debug!(%task_id, ?active_task_id, "ignored cancellation for inactive task");
        }
    }

    pub(crate) fn cancellation_flag(&self) -> Arc<AtomicBool> {
        self.cancel_requested.clone()
    }
}

#[derive(Serialize)]
struct HeartbeatPayload {
    scanner_id: Uuid,
    state: &'static str,
    active_task_id: Option<Uuid>,
    scanner_version: &'static str,
    system: SystemInfo,
    network_capabilities: NetworkCapabilities,
    scan_capabilities: ScanCapabilities,
}

#[derive(Serialize)]
struct TaskFailurePayload<'a> {
    scanner_id: Uuid,
    task_id: Uuid,
    error: &'a str,
    retryable: bool,
}

#[derive(Serialize)]
struct TaskCancelledPayload {
    scanner_id: Uuid,
    task_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HeartbeatResponse {
    command: Option<HeartbeatCommand>,
}

#[derive(Debug, Deserialize)]
struct HeartbeatCommand {
    #[serde(rename = "type")]
    command_type: String,
    task_id: Uuid,
}

#[derive(Clone)]
pub(crate) struct HeartbeatClient {
    client: Client,
    heartbeat_url: String,
    failure_url: String,
    cancelled_url: String,
    runtime_token: String,
    scanner_id: Uuid,
    network_capabilities: SharedNetworkCapabilities,
    scan_capabilities: ScanCapabilities,
}

pub(crate) struct HeartbeatEndpoints {
    pub(crate) heartbeat: String,
    pub(crate) failure: String,
    pub(crate) cancelled: String,
}

impl HeartbeatClient {
    pub(crate) async fn can_scan(&self, address_family: &str) -> bool {
        self.network_capabilities
            .get()
            .await
            .is_ready(address_family)
    }

    pub(crate) fn new(
        endpoints: HeartbeatEndpoints,
        verify_tls: bool,
        runtime_token: String,
        scanner_id: Uuid,
        network_capabilities: SharedNetworkCapabilities,
        scan_capabilities: ScanCapabilities,
    ) -> Result<Self, ScannerError> {
        let client = Client::builder()
            .user_agent(USER_AGENT)
            .danger_accept_invalid_certs(!verify_tls)
            .build()?;
        Ok(Self {
            client,
            heartbeat_url: endpoints.heartbeat,
            failure_url: endpoints.failure,
            cancelled_url: endpoints.cancelled,
            runtime_token,
            scanner_id,
            network_capabilities,
            scan_capabilities,
        })
    }

    pub(crate) async fn send(
        &self,
        active_task_id: Option<Uuid>,
        stopping: bool,
    ) -> Result<HeartbeatResponse, ScannerError> {
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
            network_capabilities: self.network_capabilities.get().await,
            scan_capabilities: self.scan_capabilities.clone(),
        };
        tracing::debug!(
            scanner_id = %self.scanner_id,
            state,
            ?active_task_id,
            stopping,
            "sending heartbeat"
        );
        let response = self
            .client
            .post(&self.heartbeat_url)
            .bearer_auth(&self.runtime_token)
            .json(&payload)
            .send()
            .await?;
        tracing::debug!(status = %response.status(), state, "heartbeat endpoint responded");
        if response.status().is_success() {
            let response = response.json().await?;
            tracing::debug!(response = ?response, "heartbeat response decoded");
            Ok(response)
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
        self.report_task_failure(task_id, error, true).await
    }

    pub(crate) async fn report_terminal_failure(
        &self,
        task_id: Uuid,
        error: &str,
    ) -> Result<(), ScannerError> {
        self.report_task_failure(task_id, error, false).await
    }

    async fn report_task_failure(
        &self,
        task_id: Uuid,
        error: &str,
        retryable: bool,
    ) -> Result<(), ScannerError> {
        let payload = TaskFailurePayload {
            scanner_id: self.scanner_id,
            task_id,
            error,
            retryable,
        };
        tracing::debug!(%task_id, retryable, "reporting scan task failure");
        let response = self
            .client
            .post(&self.failure_url)
            .bearer_auth(&self.runtime_token)
            .json(&payload)
            .send()
            .await?;
        tracing::debug!(%task_id, status = %response.status(), "task failure endpoint responded");
        if response.status().is_success() {
            Ok(())
        } else {
            Err(ScannerError::Http(format!(
                "task failure endpoint returned {}",
                response.status()
            )))
        }
    }

    pub(crate) async fn report_cancelled(&self, task_id: Uuid) -> Result<(), ScannerError> {
        tracing::debug!(%task_id, "acknowledging scan task cancellation");
        let response = self
            .client
            .post(&self.cancelled_url)
            .bearer_auth(&self.runtime_token)
            .json(&TaskCancelledPayload {
                scanner_id: self.scanner_id,
                task_id,
            })
            .send()
            .await?;
        tracing::debug!(%task_id, status = %response.status(), "task cancellation endpoint responded");
        if response.status().is_success() {
            Ok(())
        } else {
            Err(ScannerError::Http(format!(
                "task cancellation endpoint returned {}",
                response.status()
            )))
        }
    }

    pub(crate) async fn apply_command(&self, response: HeartbeatResponse, active: &ActiveTask) {
        if let Some(command) = response.command
            && command.command_type == "cancel_task"
        {
            tracing::debug!(task_id = %command.task_id, "applying heartbeat cancellation command");
            active.request_cancel(command.task_id).await;
        } else {
            tracing::debug!("heartbeat contained no actionable command");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancellation_command_only_targets_active_task() {
        let active = ActiveTask::default();
        let active_id = Uuid::now_v7();
        active.set(active_id).await;
        active.request_cancel(Uuid::now_v7()).await;
        assert!(!active.cancellation_flag().load(Ordering::Relaxed));
        active.request_cancel(active_id).await;
        assert!(active.cancellation_flag().load(Ordering::Relaxed));
        active.clear().await;
        assert!(!active.cancellation_flag().load(Ordering::Relaxed));
    }
}
