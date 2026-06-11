use crate::error::ScannerError;
use reqwest::Client;

const USER_AGENT: &str = "Scanner/1.0";

pub(crate) async fn fetch_target(url: &str, verify_tls: bool) -> Result<String, ScannerError> {
    let client = Client::builder()
        .user_agent(USER_AGENT)
        .danger_accept_invalid_certs(!verify_tls)
        .build()?;

    let body = client.get(url).send().await?.text().await?;
    Ok(body)
}
