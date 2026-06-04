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

/// Placeholder for Mailgun stop-notification. Replace credentials before use.
#[allow(dead_code)]
pub(crate) async fn send_stop_email(
    api_key: &str,
    domain: &str,
    from: &str,
    to: &[&str],
    subject: &str,
    text: &str,
) -> Result<(), ScannerError> {
    let mut form = reqwest::multipart::Form::new()
        .text("from", from.to_string())
        .text("subject", subject.to_string())
        .text("text", text.to_string());

    for recipient in to {
        form = form.text("to", recipient.to_string());
    }

    let url = format!("https://api.mailgun.net/v3/{}/messages", domain);
    let response = Client::new()
        .post(&url)
        .basic_auth("api", Some(api_key))
        .multipart(form)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ScannerError::Http(format!(
            "email send failed ({}): {}",
            status, body
        )));
    }

    tracing::info!("email sent successfully");
    Ok(())
}
