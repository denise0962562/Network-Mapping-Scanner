use crate::error::ScannerError;
use crate::http_client;
use crate::types::TargetParams;
use serde_json::Value;

/// Health check: test target acquisition by fetching from `test_url`
/// and validating the JSON response fields.
pub async fn get_target_test(test_url: &str) -> Result<(), ScannerError> {
    let result = http_client::http_requests(test_url)
        .await
        .map_err(|e| ScannerError::HealthCheck(format!("获取目标失败: {}", e)))?;

    if result.is_empty() {
        return Err(ScannerError::HealthCheck("返回结果为空".into()));
    }

    let params = check_target(&result, true)?;

    tracing::info!(
        "健康检查通过: {}:{} RATE:{} SOURCE-PORT:{}",
        params.ip,
        params.port,
        params.rate,
        params.source_port
    );

    Ok(())
}

/// Validate and extract target scan parameters from a JSON string.
///
/// Checks that all required fields are present with valid types and ranges:
/// - `ip`: non-empty string
/// - `port`: comma-separated port list string
/// - `rate`: integer in range (0, 1000000]
/// - `source-port`: integer in range (0, 65535]
pub fn check_target(json_str: &str, verbose: bool) -> Result<TargetParams, ScannerError> {
    if verbose {
        println!("开始检查目标");
    }

    let root: Value = serde_json::from_str(json_str)
        .map_err(|e| ScannerError::HealthCheck(format!("解析目标 JSON 失败: {}", e)))?;

    // Validate ip field
    let ip = root
        .get("ip")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ScannerError::HealthCheck("IP 字段出现错误".into()))?
        .to_string();

    // Validate port field
    let port = root
        .get("port")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ScannerError::HealthCheck("PORT 字段出现错误".into()))?
        .to_string();

    // Validate rate field
    let rate = root
        .get("rate")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| ScannerError::HealthCheck("RATE 字段出现错误".into()))?;

    if rate <= 0 || rate > 1_000_000 {
        return Err(ScannerError::HealthCheck(format!(
            "RATE 字段数值异常: RATE={} (0 < RATE <= 1000000)",
            rate
        )));
    }
    let rate = rate as i32;

    // Validate source-port field
    let source_port = root
        .get("source-port")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| ScannerError::HealthCheck("SOURCE-PORT 字段出现异常".into()))?;

    if source_port <= 0 || source_port > 65535 {
        return Err(ScannerError::HealthCheck(format!(
            "SOURCE-PORT 字段数值异常: SOURCE-PORT={} (0 < SOURCE-PORT <= 65535)",
            source_port
        )));
    }
    let source_port = source_port as i32;

    Ok(TargetParams {
        ip,
        port,
        rate,
        source_port,
    })
}
