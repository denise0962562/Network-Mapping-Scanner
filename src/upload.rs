use crate::error::ScannerError;
use crate::types::UploadEntry;
use reqwest::Client;

const USER_AGENT: &str = "Scanner/1.0";

/// Uploader encapsulates the result-reporting pipeline.
///
/// Currently implemented as HTTPS JSON POST. To add encryption later,
/// wrap the payload before calling `send()` — no other module needs to change.
pub(crate) struct Uploader {
    endpoint: String,
    verify_tls: bool,
}

impl Uploader {
    pub(crate) fn new(endpoint: String, verify_tls: bool) -> Self {
        Self {
            endpoint,
            verify_tls,
        }
    }

    /// POST a batch of scan entries as JSON to the configured endpoint.
    pub(crate) async fn upload(&self, entries: &[UploadEntry]) -> Result<(), ScannerError> {
        if entries.is_empty() {
            return Ok(());
        }

        let client = Client::builder()
            .user_agent(USER_AGENT)
            .danger_accept_invalid_certs(!self.verify_tls)
            .build()?;

        let payload = serde_json::to_string(entries)?;

        let response = client
            .post(&self.endpoint)
            .header("Content-Type", "application/json")
            .body(payload)
            .send()
            .await
            .map_err(|e| ScannerError::Upload(format!("upload request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ScannerError::Upload(format!(
                "server returned {}: {}",
                status, body
            )));
        }

        tracing::info!(
            "uploaded {} entries to {}",
            entries.len(),
            self.endpoint
        );
        Ok(())
    }
}
