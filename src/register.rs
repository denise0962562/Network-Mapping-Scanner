use crate::error::ScannerError;
use reqwest::Client;

const USER_AGENT: &str = "Scanner/1.0";

#[derive(Debug, serde::Serialize)]
struct RegisterRequest {
    scanner_id: String,
}

#[derive(Debug, serde::Deserialize)]
struct RegisterResponse {
    runtime_token: String,
}

pub(crate) enum RegisterOutcome {
    Registered { runtime_token: String },
    Unauthorized,
}

pub(crate) async fn register(
    c_server: &str,
    c_port: i64,
    verify_tls: bool,
    scanner_id: &str,
    token: &str,
) -> Result<RegisterOutcome, ScannerError> {
    let url = format!("https://{}:{}/api/scanner/register", c_server, c_port);
    let body = RegisterRequest {
        scanner_id: scanner_id.to_string(),
    };

    tracing::debug!(url, scanner_id, verify_tls, "starting scanner registration");

    let client = Client::builder()
        .user_agent(USER_AGENT)
        .danger_accept_invalid_certs(!verify_tls)
        .build()?;

    let response = client
        .post(&url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await?;

    tracing::debug!(status = %response.status(), "registration endpoint responded");

    match response.status().as_u16() {
        200 => {
            let response: RegisterResponse = response.json().await.map_err(|error| {
                ScannerError::Http(format!("invalid registration response: {error}"))
            })?;
            if response.runtime_token.is_empty() {
                return Err(ScannerError::Http(
                    "registration response contained an empty runtime token".into(),
                ));
            }
            tracing::info!("scanner registered successfully (id={})", scanner_id);
            Ok(RegisterOutcome::Registered {
                runtime_token: response.runtime_token,
            })
        }
        401 => {
            tracing::warn!("registration rejected: invalid credentials (401)");
            Ok(RegisterOutcome::Unauthorized)
        }
        status => {
            let body = response.text().await.unwrap_or_default();
            Err(ScannerError::Http(format!(
                "registration failed with status {status}: {body}"
            )))
        }
    }
}
