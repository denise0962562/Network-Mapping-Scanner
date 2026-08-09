use crate::error::ScannerError;
use crate::types::AssignedTask;
use reqwest::{Client, StatusCode};

const USER_AGENT: &str = "Scanner/1.0";

pub(crate) enum FetchTaskOutcome {
    Task(AssignedTask),
    NoTask,
    Unauthorized,
}

fn client(verify_tls: bool) -> Result<Client, ScannerError> {
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
    let response = client(verify_tls)?
        .get(url)
        .bearer_auth(runtime_token)
        .send()
        .await?;

    match response.status() {
        StatusCode::OK => response
            .json::<AssignedTask>()
            .await
            .map(FetchTaskOutcome::Task)
            .map_err(|error| ScannerError::Http(format!("invalid task response: {error}"))),
        StatusCode::NOT_FOUND => Ok(FetchTaskOutcome::NoTask),
        StatusCode::UNAUTHORIZED => Ok(FetchTaskOutcome::Unauthorized),
        status => {
            let body = response.text().await.unwrap_or_default();
            Err(ScannerError::Http(format!(
                "task endpoint returned {status}: {body}"
            )))
        }
    }
}

pub(crate) async fn validate_credentials(
    url: &str,
    verify_tls: bool,
    runtime_token: &str,
) -> Result<(), ScannerError> {
    let response = client(verify_tls)?
        .get(url)
        .bearer_auth(runtime_token)
        .send()
        .await?;

    match response.status() {
        StatusCode::OK => Ok(()),
        StatusCode::UNAUTHORIZED => Err(ScannerError::HealthCheck(
            "runtime credentials were rejected".into(),
        )),
        status => {
            let body = response.text().await.unwrap_or_default();
            Err(ScannerError::HealthCheck(format!(
                "credential check returned {status}: {body}"
            )))
        }
    }
}
