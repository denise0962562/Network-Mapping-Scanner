use crate::error::ScannerError;
use crate::types::AssignedTask;
use reqwest::{Client, Response, StatusCode};

const USER_AGENT: &str = "Scanner/1.0";

pub(crate) enum FetchTaskOutcome {
    Task(AssignedTask),
    NoTask,
    Unauthorized { detail: String },
    Forbidden { detail: String },
}

#[derive(Debug, PartialEq, Eq)]
enum TaskResponseStatus {
    Task,
    NoTask,
    Unauthorized,
    Forbidden,
    Other(StatusCode),
}

fn classify_task_status(status: StatusCode) -> TaskResponseStatus {
    match status {
        StatusCode::OK => TaskResponseStatus::Task,
        StatusCode::NOT_FOUND => TaskResponseStatus::NoTask,
        StatusCode::UNAUTHORIZED => TaskResponseStatus::Unauthorized,
        StatusCode::FORBIDDEN => TaskResponseStatus::Forbidden,
        status => TaskResponseStatus::Other(status),
    }
}

async fn response_detail(response: Response) -> String {
    let body = response.text().await.unwrap_or_default();
    let detail: String = body
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(256)
        .collect();
    if detail.is_empty() {
        "empty response body".into()
    } else {
        detail
    }
}

fn client(verify_tls: bool) -> Result<Client, ScannerError> {
    tracing::debug!(
        verify_tls,
        user_agent = USER_AGENT,
        "building task HTTP client"
    );
    Client::builder()
        .user_agent(USER_AGENT)
        .danger_accept_invalid_certs(!verify_tls)
        .build()
        .map_err(ScannerError::from)
}

pub(crate) async fn fetch_task(
    url: &str,
    verify_tls: bool,
    runtime_token: &str,
) -> Result<FetchTaskOutcome, ScannerError> {
    tracing::debug!(url, verify_tls, "requesting scan task");
    let response = client(verify_tls)?
        .get(url)
        .bearer_auth(runtime_token)
        .send()
        .await?;

    tracing::debug!(status = %response.status(), "task endpoint responded");

    match classify_task_status(response.status()) {
        TaskResponseStatus::Task => {
            let task = response
                .json::<AssignedTask>()
                .await
                .map_err(|error| ScannerError::Http(format!("invalid task response: {error}")))?;
            tracing::debug!(
                task_id = %task.task_id,
                target_count = task.task_target.len(),
                ports = %task.task_port,
                "task response decoded"
            );
            Ok(FetchTaskOutcome::Task(task))
        }
        TaskResponseStatus::NoTask => Ok(FetchTaskOutcome::NoTask),
        TaskResponseStatus::Unauthorized => Ok(FetchTaskOutcome::Unauthorized {
            detail: response_detail(response).await,
        }),
        TaskResponseStatus::Forbidden => Ok(FetchTaskOutcome::Forbidden {
            detail: response_detail(response).await,
        }),
        TaskResponseStatus::Other(status) => {
            let detail = response_detail(response).await;
            Err(ScannerError::Http(format!(
                "task endpoint returned {status}: {detail}"
            )))
        }
    }
}

pub(crate) async fn validate_credentials(
    url: &str,
    verify_tls: bool,
    runtime_token: &str,
) -> Result<(), ScannerError> {
    tracing::debug!(url, verify_tls, "validating runtime credentials");
    let response = client(verify_tls)?
        .get(url)
        .bearer_auth(runtime_token)
        .send()
        .await?;

    let status = response.status();
    tracing::debug!(status = %status, "credential endpoint responded");
    match status {
        StatusCode::OK => Ok(()),
        StatusCode::UNAUTHORIZED => {
            let detail = response_detail(response).await;
            Err(ScannerError::HealthCheck(format!(
                "runtime credentials were rejected: {detail}"
            )))
        }
        StatusCode::FORBIDDEN => {
            let detail = response_detail(response).await;
            Err(ScannerError::HealthCheck(format!(
                "credential check was blocked by server security middleware: {detail}"
            )))
        }
        status => {
            let detail = response_detail(response).await;
            Err(ScannerError::HealthCheck(format!(
                "credential check returned {status}: {detail}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TaskResponseStatus, classify_task_status};
    use reqwest::StatusCode;

    #[test]
    fn task_http_statuses_are_classified_for_actionable_errors() {
        assert_eq!(
            classify_task_status(StatusCode::OK),
            TaskResponseStatus::Task
        );
        assert_eq!(
            classify_task_status(StatusCode::NOT_FOUND),
            TaskResponseStatus::NoTask
        );
        assert_eq!(
            classify_task_status(StatusCode::UNAUTHORIZED),
            TaskResponseStatus::Unauthorized
        );
        assert_eq!(
            classify_task_status(StatusCode::FORBIDDEN),
            TaskResponseStatus::Forbidden
        );
        assert_eq!(
            classify_task_status(StatusCode::INTERNAL_SERVER_ERROR),
            TaskResponseStatus::Other(StatusCode::INTERNAL_SERVER_ERROR)
        );
    }
}
