use crate::error::ScannerError;
use crate::http_client::{self, ServerHttpClient};

pub(crate) async fn health_check(
    client: &ServerHttpClient,
    credential_check_url: &str,
) -> Result<(), ScannerError> {
    tracing::debug!(credential_check_url, "starting scanner health check");
    http_client::validate_credentials(client, credential_check_url).await?;
    tracing::info!("health check OK: runtime credentials accepted");
    Ok(())
}
