use crate::error::ScannerError;
use crate::http_client::{ServerHttpClient, response_decode_error, response_error};
use crate::network::{NetworkCapabilities, SharedNetworkCapabilities};
use crate::scan::ScanCapabilities;
use crate::sysinfo::SystemInfo;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use uuid::Uuid;

const MAX_LEASE_TTL_MS: u64 = 86_400_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TaskCancellationReason {
    ServerRequested,
    LeaseLost,
    Shutdown,
}

impl TaskCancellationReason {
    fn code(self) -> u8 {
        match self {
            Self::ServerRequested => 1,
            Self::LeaseLost => 2,
            Self::Shutdown => 3,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::ServerRequested),
            2 => Some(Self::LeaseLost),
            3 => Some(Self::Shutdown),
            _ => None,
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct ActiveTask {
    current: Arc<RwLock<Option<Uuid>>>,
    cancel_requested: Arc<AtomicBool>,
    cancellation_reason: Arc<AtomicU8>,
    lease_deadline: Arc<RwLock<Option<Instant>>>,
    lease_ttl_ms: Arc<AtomicU64>,
}

impl ActiveTask {
    pub(crate) async fn get(&self) -> Option<Uuid> {
        *self.current.read().await
    }

    pub(crate) async fn set(&self, task_id: Uuid, lease_ttl_ms: u64) {
        self.cancel_requested.store(false, Ordering::Relaxed);
        self.cancellation_reason.store(0, Ordering::Relaxed);
        *self.current.write().await = Some(task_id);
        self.renew_lease(lease_ttl_ms).await;
        tracing::debug!(%task_id, "active task set");
    }

    pub(crate) async fn clear(&self) {
        let previous_task_id = *self.current.read().await;
        *self.current.write().await = None;
        *self.lease_deadline.write().await = None;
        self.lease_ttl_ms.store(0, Ordering::Relaxed);
        self.cancel_requested.store(false, Ordering::Relaxed);
        self.cancellation_reason.store(0, Ordering::Relaxed);
        tracing::debug!(?previous_task_id, "active task cleared");
    }

    pub(crate) async fn request_cancel(&self, task_id: Uuid) {
        let active_task_id = self.get().await;
        if active_task_id == Some(task_id) {
            self.request_cancellation(TaskCancellationReason::ServerRequested);
            tracing::debug!(%task_id, "cancellation requested for active task");
        } else {
            tracing::debug!(%task_id, ?active_task_id, "ignored cancellation for inactive task");
        }
    }

    pub(crate) fn cancellation_flag(&self) -> Arc<AtomicBool> {
        self.cancel_requested.clone()
    }

    pub(crate) fn cancellation_reason(&self) -> Option<TaskCancellationReason> {
        TaskCancellationReason::from_code(self.cancellation_reason.load(Ordering::Relaxed))
    }

    pub(crate) async fn renew_lease(&self, lease_ttl_ms: u64) {
        let bounded_ttl_ms = lease_ttl_ms.clamp(1, MAX_LEASE_TTL_MS);
        if bounded_ttl_ms != lease_ttl_ms {
            tracing::warn!(lease_ttl_ms, bounded_ttl_ms, "server lease TTL was clamped");
        }
        let ttl = Duration::from_millis(bounded_ttl_ms);
        self.lease_ttl_ms.store(bounded_ttl_ms, Ordering::Relaxed);
        *self.lease_deadline.write().await = Some(Instant::now() + ttl);
        tracing::debug!(
            lease_ttl_ms = bounded_ttl_ms,
            "active task lease deadline updated"
        );
    }

    async fn renew_last_lease(&self) {
        let lease_ttl_ms = self.lease_ttl_ms.load(Ordering::Relaxed);
        if lease_ttl_ms > 0 {
            self.renew_lease(lease_ttl_ms).await;
        }
    }

    pub(crate) async fn lease_safety_expired(&self, safety_margin: Duration) -> bool {
        self.lease_deadline
            .read()
            .await
            .is_some_and(|deadline| Instant::now() + safety_margin >= deadline)
    }

    pub(crate) async fn lease_safety_remaining(&self, safety_margin: Duration) -> Option<Duration> {
        self.lease_deadline
            .read()
            .await
            .map(|deadline| deadline.saturating_duration_since(Instant::now() + safety_margin))
    }

    pub(crate) async fn request_lease_lost(&self, task_id: Uuid) {
        if self.get().await == Some(task_id) {
            self.request_cancellation(TaskCancellationReason::LeaseLost);
            tracing::error!(%task_id, "active task lease was lost");
        }
    }

    pub(crate) async fn request_shutdown(&self) {
        if self.get().await.is_some() {
            self.request_cancellation(TaskCancellationReason::Shutdown);
        }
    }

    fn request_cancellation(&self, reason: TaskCancellationReason) {
        self.cancellation_reason
            .store(reason.code(), Ordering::Relaxed);
        self.cancel_requested.store(true, Ordering::Relaxed);
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
    lease: Option<HeartbeatLease>,
}

#[derive(Debug, Deserialize)]
struct HeartbeatCommand {
    #[serde(rename = "type")]
    command_type: String,
    task_id: Uuid,
}

#[derive(Debug, Deserialize)]
struct HeartbeatLease {
    task_id: Uuid,
    status: String,
    #[allow(dead_code)]
    expires_at_ms: Option<i64>,
    ttl_ms: u64,
}

#[derive(Clone)]
pub(crate) struct HeartbeatClient {
    client: ServerHttpClient,
    heartbeat_url: String,
    failure_url: String,
    cancelled_url: String,
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
        client: ServerHttpClient,
        endpoints: HeartbeatEndpoints,
        scanner_id: Uuid,
        network_capabilities: SharedNetworkCapabilities,
        scan_capabilities: ScanCapabilities,
    ) -> Self {
        Self {
            client,
            heartbeat_url: endpoints.heartbeat,
            failure_url: endpoints.failure,
            cancelled_url: endpoints.cancelled,
            scanner_id,
            network_capabilities,
            scan_capabilities,
        }
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
            .post_json(&self.heartbeat_url, &payload, "send heartbeat")
            .await?;
        tracing::debug!(status = %response.status(), state, "heartbeat endpoint responded");
        if response.status().is_success() {
            let response = response
                .json()
                .await
                .map_err(|error| response_decode_error(error, "send heartbeat"))?;
            tracing::debug!(response = ?response, "heartbeat response decoded");
            Ok(response)
        } else {
            Err(response_error(response, "send heartbeat").await.into())
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
            .post_json(&self.failure_url, &payload, "report task failure")
            .await?;
        tracing::debug!(%task_id, status = %response.status(), "task failure endpoint responded");
        if response.status().is_success() {
            Ok(())
        } else {
            Err(response_error(response, "report task failure").await.into())
        }
    }

    pub(crate) async fn report_cancelled(&self, task_id: Uuid) -> Result<(), ScannerError> {
        tracing::debug!(%task_id, "acknowledging scan task cancellation");
        let response = self
            .client
            .post_json(
                &self.cancelled_url,
                &TaskCancelledPayload {
                    scanner_id: self.scanner_id,
                    task_id,
                },
                "report task cancellation",
            )
            .await?;
        tracing::debug!(%task_id, status = %response.status(), "task cancellation endpoint responded");
        if response.status().is_success() {
            Ok(())
        } else {
            Err(response_error(response, "report task cancellation")
                .await
                .into())
        }
    }

    pub(crate) async fn apply_command(&self, response: HeartbeatResponse, active: &ActiveTask) {
        if let Some(lease) = response.lease {
            match lease.status.as_str() {
                "renewed" if active.get().await == Some(lease.task_id) => {
                    active.renew_lease(lease.ttl_ms).await;
                }
                "lost" => active.request_lease_lost(lease.task_id).await,
                status => tracing::warn!(%status, task_id = %lease.task_id, "unknown lease status"),
            }
        } else if active.get().await.is_some() {
            // Compatibility with servers that renew leases but predate the
            // explicit lease response object.
            active.renew_last_lease().await;
        }
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
        active.set(active_id, 90_000).await;
        active.request_cancel(Uuid::now_v7()).await;
        assert!(!active.cancellation_flag().load(Ordering::Relaxed));
        active.request_cancel(active_id).await;
        assert!(active.cancellation_flag().load(Ordering::Relaxed));
        active.clear().await;
        assert!(!active.cancellation_flag().load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn lease_loss_has_a_distinct_cancellation_reason() {
        let active = ActiveTask::default();
        let task_id = Uuid::now_v7();
        active.set(task_id, 90_000).await;
        active.request_lease_lost(task_id).await;
        assert_eq!(
            active.cancellation_reason(),
            Some(TaskCancellationReason::LeaseLost)
        );
    }
}
