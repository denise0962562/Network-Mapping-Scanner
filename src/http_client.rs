use crate::error::ScannerError;
use reqwest::Client;

/// Perform an HTTP GET request to `url` and return the response body as a String.
///
/// Uses `User-Agent: Scanner/1.0` header, matching the C version's libcurl behavior.
pub async fn http_requests(url: &str) -> Result<String, ScannerError> {
    let client = Client::builder()
        .user_agent("Scanner/1.0")
        .build()?;

    let response = client.get(url).send().await?;

    let body = response.text().await?;

    Ok(body)
}

/// Send a stop notification email via Mailgun API.
///
/// This is a placeholder matching the C version's `send_stop_email` function.
/// Replace with real configuration before production use.
#[allow(dead_code)]
pub async fn send_stop_email(
    api_key: &str,
    domain: &str,
    from: &str,
    to: &[&str],
    subject: &str,
    text: &str,
) -> Result<(), ScannerError> {
    let client = Client::new();

    let url = format!("https://api.mailgun.net/v3/{}/messages", domain);

    let mut form = reqwest::multipart::Form::new()
        .text("from", from.to_string())
        .text("subject", subject.to_string())
        .text("text", text.to_string());

    for recipient in to {
        form = form.text("to", recipient.to_string());
    }

    let response = client
        .post(&url)
        .basic_auth("api", Some(api_key))
        .multipart(form)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ScannerError::Http(format!(
            "邮件发送失败 ({}): {}",
            status, body
        )));
    }

    tracing::info!("邮件发送成功");
    Ok(())
}
