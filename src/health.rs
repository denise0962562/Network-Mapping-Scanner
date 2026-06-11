use crate::error::ScannerError;
use crate::http_client;
use crate::types::TargetParams;
use serde_json::Value;

pub(crate) async fn health_check(target_url: &str, verify_tls: bool) -> Result<(), ScannerError> {
    let body = http_client::fetch_target(target_url, verify_tls)
        .await
        .map_err(|e| ScannerError::HealthCheck(format!("fetch failed: {}", e)))?;

    if body.is_empty() {
        return Err(ScannerError::HealthCheck("empty response body".into()));
    }

    let params = validate_target(&body, true)?;

    tracing::info!(
        "health check OK: {}:{} rate={} source-port={}",
        params.ip,
        params.port,
        params.rate,
        params.source_port
    );

    Ok(())
}

pub(crate) fn validate_target(json: &str, verbose: bool) -> Result<TargetParams, ScannerError> {
    if verbose {
        println!("validating target...");
    }

    let root: Value = serde_json::from_str(json)
        .map_err(|e| ScannerError::HealthCheck(format!("JSON parse error: {}", e)))?;

    let ip = extract_field(&root, "ip", "missing IP field")?;
    let port = extract_field(&root, "port", "missing PORT field")?;
    let rate = extract_int_range(&root, "rate", 1, 1_000_000, "RATE")?;
    let source_port = extract_int_range(&root, "source_port", 1, 65535, "SOURCE-PORT")?;

    Ok(TargetParams {
        ip,
        port,
        rate,
        source_port,
    })
}

fn extract_field(root: &Value, key: &str, err_msg: &str) -> Result<String, ScannerError> {
    root.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| ScannerError::HealthCheck(err_msg.into()))
}

fn extract_int_range(
    root: &Value,
    key: &str,
    min: i64,
    max: i64,
    label: &str,
) -> Result<i32, ScannerError> {
    let val = root
        .get(key)
        .and_then(|v| v.as_i64())
        .ok_or_else(|| ScannerError::HealthCheck(format!("{} field error", label)))?;

    if val < min || val > max {
        return Err(ScannerError::HealthCheck(format!(
            "{} out of range: {} (expected {}..={})",
            label, val, min, max
        )));
    }

    Ok(val as i32)
}
