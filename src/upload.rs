use crate::error::ScannerError;
use crate::types::ScannerResultUpload;
use reqwest::Client;

const USER_AGENT: &str = "Scanner/1.0";

/// Uploader encapsulates the result-reporting pipeline.
///
/// Currently implemented as HTTPS JSON POST. To add encryption later,
/// wrap the payload before calling `send()` — no other module needs to change.
pub(crate) struct Uploader {
    endpoint: String,
    verify_tls: bool,
    runtime_token: String,
}

impl Uploader {
    pub(crate) fn new(endpoint: String, verify_tls: bool, runtime_token: String) -> Self {
        Self {
            endpoint,
            verify_tls,
            runtime_token,
        }
    }

    /// POST a batch of scan entries as JSON to the configured endpoint.
    pub(crate) async fn upload(&self, payload: &ScannerResultUpload) -> Result<(), ScannerError> {
        tracing::debug!(
            endpoint = %self.endpoint,
            verify_tls = self.verify_tls,
            scanner_id = %payload.scanner_id,
            task_id = %payload.task_id,
            result_count = payload.results.len(),
            "starting result upload"
        );
        let client = Client::builder()
            .user_agent(USER_AGENT)
            .danger_accept_invalid_certs(!self.verify_tls)
            .build()?;

        let response = client
            .post(&self.endpoint)
            .bearer_auth(&self.runtime_token)
            .json(payload)
            .send()
            .await
            .map_err(|e| ScannerError::Upload(format!("upload request failed: {}", e)))?;

        tracing::debug!(
            task_id = %payload.task_id,
            status = %response.status(),
            "upload endpoint responded"
        );

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ScannerError::Upload(format!(
                "server returned {}: {}",
                status, body
            )));
        }

        tracing::info!(
            "uploaded {} entries for task {} to {}",
            payload.results.len(),
            payload.task_id,
            self.endpoint
        );
        Ok(())
    }
}
