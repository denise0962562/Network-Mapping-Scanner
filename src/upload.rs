use crate::error::ServerError;
use crate::http_client::{ServerHttpClient, response_error};
use crate::types::ScannerResultBatchUpload;

/// Uploader encapsulates the idempotent result-reporting pipeline.
pub(crate) struct Uploader {
    endpoint: String,
    client: ServerHttpClient,
}

impl Uploader {
    pub(crate) fn new(endpoint: String, client: ServerHttpClient) -> Self {
        Self { endpoint, client }
    }

    pub(crate) async fn upload(
        &self,
        payload: &ScannerResultBatchUpload,
    ) -> Result<(), ServerError> {
        tracing::debug!(
            endpoint = %self.endpoint,
            scanner_id = %payload.scanner_id,
            task_id = %payload.task_id,
            upload_id = %payload.upload_id,
            batch_index = payload.batch_index,
            is_final = payload.is_final,
            observation_count = payload.observations.len(),
            "starting result upload"
        );
        let response = self
            .client
            .post_json(&self.endpoint, payload, "upload results")
            .await?;
        let status = response.status();
        tracing::debug!(task_id = %payload.task_id, %status, "upload endpoint responded");
        if !status.is_success() {
            return Err(response_error(response, "upload results").await);
        }
        tracing::info!(
            event = "ResultBatchUploaded",
            task_id = %payload.task_id,
            upload_id = %payload.upload_id,
            batch_index = payload.batch_index,
            is_final = payload.is_final,
            observation_count = payload.observations.len(),
            endpoint = %self.endpoint,
            "scan result batch uploaded"
        );
        Ok(())
    }
}
