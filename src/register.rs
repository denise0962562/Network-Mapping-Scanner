use crate::error::ScannerError;
use reqwest::Client;

const USER_AGENT: &str = "Scanner/1.0";

#[derive(Debug, serde::Serialize)]
struct RegisterRequest {
    scanner_id: String,
    token: String,
}

/// POST to the registration endpoint. Returns the HTTP status code.
///
/// - 200 → registration accepted
/// - 401 → invalid credentials
/// - 500 → server error
pub(crate) async fn register(
    c_server: &str,
    c_port: i64,
    verify_tls: bool,
    scanner_id: &str,
    token: &str,
) -> Result<u16, ScannerError> {
    let url = format!("https://{}:{}/api/scanner/register", c_server, c_port);
    let body = RegisterRequest {
        scanner_id: scanner_id.to_string(),
        token: token.to_string(),
    };

    let client = Client::builder()
        .user_agent(USER_AGENT)
        .danger_accept_invalid_certs(!verify_tls)
        .build()?;

    let response = client.post(&url).json(&body).send().await?;
    let status = response.status().as_u16();

    match status {
        200 => tracing::info!("scanner registered successfully (id={})", scanner_id),
        401 => tracing::warn!("registration rejected: invalid credentials (401)"),
        500 => tracing::error!("registration failed: server error (500)"),
        other => tracing::warn!("registration returned unexpected status: {}", other),
    }

    Ok(status)
}
