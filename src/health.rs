use crate::error::ScannerError;
use crate::http_client;

pub(crate) async fn health_check(
    credential_check_url: &str,
    verify_tls: bool,
    runtime_token: &str,
) -> Result<(), ScannerError> {
    http_client::validate_credentials(credential_check_url, verify_tls, runtime_token).await?;
    tracing::info!("health check OK: runtime credentials accepted");
    Ok(())
}
