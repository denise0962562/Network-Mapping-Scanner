use crate::error::ScannerError;
use crate::scan::detection::{
    ProbeAttempt, ProbeEvidence, ProbeKind, aggregate, fallback_attempts, initial_attempts,
};
use crate::scan::{PortObservation, ServiceObservation};
use crate::types::ServiceDetectionConfig;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStderr, Command};
use tokio::task::JoinHandle;
use tokio::time::{Duration, sleep};
use uuid::Uuid;

const MAX_ZGRAB_STDERR_CHARS: usize = 4096;
const MAX_BANNER_CHARS: usize = 1024;

pub(crate) enum EngineOutcome {
    Completed(Vec<ServiceObservation>),
    Cancelled,
}

enum ProcessOutcome {
    Completed(Vec<ProbeEvidence>),
    Cancelled,
}

pub(crate) fn validate_binary(path: &str) -> Result<(), ScannerError> {
    if path.trim().is_empty() {
        return Err(ScannerError::Config(
            "service_detection.zgrab_path must not be empty".into(),
        ));
    }

    let configured_path = Path::new(path);
    let resolved = if configured_path.is_absolute() || configured_path.components().count() > 1 {
        configured_path.to_path_buf()
    } else {
        find_in_path(configured_path).ok_or_else(|| {
            ScannerError::Config(format!(
                "service_detection.zgrab_path '{path}' was not found as an executable file in PATH"
            ))
        })?
    };

    let metadata = std::fs::metadata(&resolved).map_err(|error| {
        ScannerError::Config(format!(
            "service detection binary '{}' cannot be accessed: {error}",
            resolved.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(ScannerError::Config(format!(
            "service detection binary '{}' is not a file",
            resolved.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(ScannerError::Config(format!(
                "service detection binary '{}' is not executable",
                resolved.display()
            )));
        }
    }

    tracing::info!(zgrab_path = %resolved.display(), "zgrab2 binary validated");
    Ok(())
}

fn find_in_path(program: &Path) -> Option<PathBuf> {
    let search_path = std::env::var_os("PATH")?;
    std::env::split_paths(&search_path)
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file() && is_executable(candidate))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

pub(crate) async fn run(
    config: &ServiceDetectionConfig,
    open_ports: &[PortObservation],
    address_family: &str,
    cancel_requested: &AtomicBool,
) -> Result<EngineOutcome, ScannerError> {
    let initial = initial_attempts(open_ports, config);
    if initial.is_empty() {
        tracing::info!(
            event = "ServiceDetectionSkipped",
            reason = "no_tcp_endpoints",
            "service detection skipped"
        );
        return Ok(EngineOutcome::Completed(Vec::new()));
    }

    let mut evidence =
        match run_attempts(config, &initial, address_family, cancel_requested).await? {
            ProcessOutcome::Completed(evidence) => evidence,
            ProcessOutcome::Cancelled => return Ok(EngineOutcome::Cancelled),
        };
    let fallback = fallback_attempts(open_ports, &initial, &evidence, config);
    if !fallback.is_empty() {
        tracing::debug!(
            endpoint_count = fallback
                .iter()
                .map(|attempt| (&attempt.ip, attempt.port))
                .collect::<std::collections::HashSet<_>>()
                .len(),
            probe_count = fallback.len(),
            "running adaptive service detection fallback round"
        );
        match run_attempts(config, &fallback, address_family, cancel_requested).await? {
            ProcessOutcome::Completed(mut fallback_evidence) => {
                evidence.append(&mut fallback_evidence)
            }
            ProcessOutcome::Cancelled => return Ok(EngineOutcome::Cancelled),
        }
    }

    Ok(EngineOutcome::Completed(aggregate(&evidence, config)))
}

async fn run_attempts(
    config: &ServiceDetectionConfig,
    attempts: &[ProbeAttempt],
    address_family: &str,
    cancel_requested: &AtomicBool,
) -> Result<ProcessOutcome, ScannerError> {
    let input = build_zgrab_input(attempts);

    let config_file = TempZgrabConfig::create(config).await?;
    let started_at = Instant::now();
    tracing::debug!(
        zgrab_path = %config.zgrab_path,
        probe_count = input.lines().count(),
        senders = config.senders,
        server_rate_limit = config.server_rate_limit,
        address_family,
        "spawning zgrab2 service detection"
    );

    let read_limit_kib = config.max_result_bytes.div_ceil(1024).max(1);
    let mut command = Command::new(&config.zgrab_path);
    command
        .args(["--senders", &config.senders.to_string()])
        .args(["--server-rate-limit", &config.server_rate_limit.to_string()])
        .args(["--read-limit-per-host", &read_limit_kib.to_string()])
        .arg("--flush");
    if address_family == "ipv6" {
        command.arg("--resolve-ipv6");
    }
    let mut child = command
        .arg("multiple")
        .args(["--config-file", config_file.path_string()?])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| ScannerError::Scan(format!("failed to spawn zgrab2: {error}")))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| ScannerError::Scan("zgrab2 stdin unavailable".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ScannerError::Scan("zgrab2 stdout unavailable".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ScannerError::Scan("zgrab2 stderr unavailable".into()))?;

    let input_handle = tokio::spawn(async move {
        stdin.write_all(input.as_bytes()).await?;
        stdin.shutdown().await
    });
    let stderr_handle = tokio::spawn(collect_zgrab_stderr(stderr));
    let mut lines = BufReader::new(stdout).lines();
    let mut results = Vec::new();
    let mut invalid_lines = 0usize;

    loop {
        if cancel_requested.load(Ordering::Relaxed) {
            tracing::debug!(process_id = ?child.id(), "stopping zgrab2 after cancellation request");
            let _ = child.kill().await;
            let _ = child.wait().await;
            input_handle.abort();
            let _ = finish_zgrab_stderr(stderr_handle).await;
            return Ok(ProcessOutcome::Cancelled);
        }

        let line = tokio::select! {
            line = lines.next_line() => line
                .map_err(|error| ScannerError::Scan(format!("failed to read zgrab2 output: {error}")))?,
            _ = sleep(Duration::from_millis(200)) => continue,
        };
        let Some(line) = line else { break };
        match parse_zgrab_line(&line, config.max_result_bytes) {
            Ok(mut parsed) => results.append(&mut parsed),
            Err(error) => {
                invalid_lines += 1;
                tracing::warn!(%error, "ignored invalid zgrab2 JSON output line");
            }
        }
    }

    if cancel_requested.load(Ordering::Relaxed) {
        tracing::debug!(process_id = ?child.id(), "zgrab2 exited during cancellation");
        input_handle.abort();
        let _ = child.kill().await;
        let _ = child.wait().await;
        let _ = finish_zgrab_stderr(stderr_handle).await;
        return Ok(ProcessOutcome::Cancelled);
    }

    input_handle
        .await
        .map_err(|error| ScannerError::Scan(format!("zgrab2 input writer failed: {error}")))?
        .map_err(|error| ScannerError::Scan(format!("failed to write zgrab2 input: {error}")))?;
    let status = child
        .wait()
        .await
        .map_err(|error| ScannerError::Scan(format!("failed to wait for zgrab2: {error}")))?;
    let stderr_output = finish_zgrab_stderr(stderr_handle).await;

    if cancel_requested.load(Ordering::Relaxed) {
        tracing::debug!(
            elapsed_ms = started_at.elapsed().as_millis(),
            "zgrab2 completed while cancellation was pending"
        );
        return Ok(ProcessOutcome::Cancelled);
    }

    tracing::info!(
        event = "ServiceDetectionCompleted",
        exit_code = ?status.code(),
        success = status.success(),
        elapsed_ms = started_at.elapsed().as_millis(),
        result_count = results.len(),
        invalid_lines,
        "service detection completed"
    );
    if !status.success() {
        let detail = if stderr_output.trim().is_empty() {
            "zgrab2 produced no stderr output"
        } else {
            stderr_output.trim()
        };
        return Err(ScannerError::Scan(format!(
            "zgrab2 exited with {status}: {detail}"
        )));
    }

    Ok(ProcessOutcome::Completed(results))
}

fn build_zgrab_input(attempts: &[ProbeAttempt]) -> String {
    let mut input = String::new();
    for attempt in attempts {
        input.push_str(&format!(
            "{},,{},{}\n",
            attempt.ip,
            attempt.probe.name(),
            attempt.port
        ));
    }
    input
}

fn parse_zgrab_line(
    line: &str,
    max_result_bytes: usize,
) -> Result<Vec<ProbeEvidence>, ScannerError> {
    let root: Value = serde_json::from_str(line)?;
    let ip = root
        .get("ip")
        .and_then(Value::as_str)
        .ok_or_else(|| ScannerError::Scan("zgrab2 output is missing ip".into()))?;
    let data = root
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(|| ScannerError::Scan("zgrab2 output is missing data".into()))?;

    let mut results = Vec::new();
    for (module, module_data) in data {
        let Some(port) = module_data
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
        else {
            tracing::warn!(%ip, %module, "zgrab2 module result is missing a valid port");
            continue;
        };
        let status = module_data
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let banner = (status == "success")
            .then(|| extract_banner(module_data))
            .flatten();
        results.push(ProbeEvidence {
            ip: ip.to_owned(),
            port,
            module: module.to_owned(),
            status: status.to_owned(),
            banner,
            detail: bounded_detail(module_data, max_result_bytes),
        });
    }
    Ok(results)
}

fn extract_banner(module_data: &Value) -> Option<String> {
    for pointer in [
        "/result/banner",
        "/result/server_id/raw",
        "/result/server",
        "/result/response/status_line",
    ] {
        if let Some(value) = module_data.pointer(pointer)
            && let Some(text) = banner_text(value)
        {
            return Some(strip_nul(text).chars().take(MAX_BANNER_CHARS).collect());
        }
    }
    None
}

fn banner_text(value: &Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.get("raw").and_then(Value::as_str))
}

// 服务端 PostgreSQL 的 text/jsonb 不接受 NUL 字节（22P05），抓取到的
// 原始 banner/响应体常含 NUL，上传前必须剔除，否则服务端写库报错。
fn strip_nul(value: &str) -> String {
    if value.contains('\0') {
        value.replace('\0', "")
    } else {
        value.to_owned()
    }
}

fn sanitize_json_value(value: Value) -> Value {
    match value {
        Value::String(text) => Value::String(strip_nul(&text)),
        Value::Array(items) => Value::Array(items.into_iter().map(sanitize_json_value).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (strip_nul(&key), sanitize_json_value(value)))
                .collect(),
        ),
        other => other,
    }
}

fn bounded_detail(module_data: &Value, max_result_bytes: usize) -> Value {
    let module_data = sanitize_json_value(module_data.clone());
    let serialized_bytes = serde_json::to_vec(&module_data)
        .map(|value| value.len())
        .unwrap_or(0);
    if serialized_bytes <= max_result_bytes {
        return module_data;
    }

    json!({
        "status": module_data.get("status"),
        "error": module_data.get("error"),
        "truncated": true,
        "original_bytes": serialized_bytes,
    })
}

struct TempZgrabConfig {
    path: PathBuf,
}

impl TempZgrabConfig {
    async fn create(config: &ServiceDetectionConfig) -> Result<Self, ScannerError> {
        let path = std::env::temp_dir().join(format!(
            "network-mapping-zgrab2-{}-{}.ini",
            std::process::id(),
            Uuid::now_v7()
        ));
        tokio::fs::write(&path, zgrab_config(config)).await?;
        Ok(Self { path })
    }

    fn path_string(&self) -> Result<&str, ScannerError> {
        self.path.to_str().ok_or_else(|| {
            ScannerError::Config("temporary zgrab2 config path is not valid UTF-8".into())
        })
    }
}

impl Drop for TempZgrabConfig {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(path = %self.path.display(), %error, "failed to remove temporary zgrab2 config");
        }
    }
}

fn zgrab_config(config: &ServiceDetectionConfig) -> String {
    let timeout = format!(
        "connect-timeout=\"{}s\"\ntarget-timeout=\"{}s\"\n",
        config.connect_timeout_seconds, config.target_timeout_seconds
    );
    let mut output = String::from("[Application Options]\n\n");
    for probe in ProbeKind::ALL {
        output.push_str(&format!(
            "[{}]\nname=\"{}\"\ntrigger=\"{}\"\nport={}\n{timeout}{}\n",
            probe.section(),
            probe.name(),
            probe.name(),
            probe.default_port(),
            probe.extra_config(),
        ));
    }
    output
}

async fn collect_zgrab_stderr(stderr: ChildStderr) -> String {
    let mut lines = BufReader::new(stderr).lines();
    let mut captured = String::new();
    while let Ok(Some(line)) = lines.next_line().await {
        tracing::debug!(line = %line, "zgrab2 stderr");
        if captured.len() < MAX_ZGRAB_STDERR_CHARS {
            if !captured.is_empty() {
                captured.push('\n');
            }
            let remaining = MAX_ZGRAB_STDERR_CHARS.saturating_sub(captured.len());
            captured.extend(line.chars().take(remaining));
        }
    }
    captured
}

async fn finish_zgrab_stderr(handle: JoinHandle<String>) -> String {
    match handle.await {
        Ok(output) => output,
        Err(error) => {
            tracing::warn!(%error, "zgrab2 stderr reader task failed");
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn open_port(ip: &str, port: u16, protocol: &str) -> PortObservation {
        PortObservation {
            ip: ip.into(),
            port,
            protocol: protocol.into(),
            state: "open",
            source: "masscan",
        }
    }

    #[test]
    fn input_tags_each_probe_and_overrides_its_port() {
        let input = build_zgrab_input(&[
            ProbeAttempt {
                ip: "192.0.2.1".into(),
                port: 2222,
                probe: ProbeKind::Ssh,
            },
            ProbeAttempt {
                ip: "2001:db8::1".into(),
                port: 10443,
                probe: ProbeKind::Https,
            },
        ]);
        assert_eq!(input, "192.0.2.1,,ssh,2222\n2001:db8::1,,https,10443\n");
    }

    #[test]
    fn successful_http_result_is_normalized() {
        let line = r#"{"ip":"192.0.2.1","data":{"http":{"status":"success","protocol":"http","port":8080,"result":{"response":{"status_line":"HTTP/1.1 200 OK"}}}}}"#;
        let results = parse_zgrab_line(line, 65_536).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].module, "http");
        assert_eq!(results[0].status, "success");
        assert_eq!(results[0].banner.as_deref(), Some("HTTP/1.1 200 OK"));
        assert_eq!(results[0].detail["status"], "success");
    }

    #[test]
    fn failed_probe_preserves_status_and_detail() {
        let line = r#"{"ip":"192.0.2.2","data":{"ssh":{"status":"connection-timeout","protocol":"ssh","port":22,"error":"timeout"}}}"#;
        let results = parse_zgrab_line(line, 65_536).unwrap();
        assert_eq!(results[0].port, 22);
        assert_eq!(results[0].status, "connection-timeout");
        assert_eq!(results[0].detail["status"], "connection-timeout");
    }

    #[test]
    fn oversized_detail_is_replaced_with_summary() {
        let line = format!(
            r#"{{"ip":"192.0.2.3","data":{{"banner":{{"status":"success","protocol":"banner","port":9000,"result":{{"banner":"{}"}}}}}}}}"#,
            "x".repeat(2048)
        );
        let results = parse_zgrab_line(&line, 1024).unwrap();
        assert_eq!(results[0].detail["truncated"], true);
    }

    #[test]
    fn generated_config_routes_http_and_https_separately() {
        let config = zgrab_config(&ServiceDetectionConfig::default());
        assert!(config.contains("name=\"http\""));
        assert!(config.contains("name=\"https\""));
        assert!(config.contains("use-https=true"));
        assert!(config.contains("connect-timeout=\"5s\""));
    }

    #[test]
    fn generated_config_enables_implicit_tls_application_modules() {
        let config = zgrab_config(&ServiceDetectionConfig::default());
        assert!(config.contains("[smtp]\nname=\"smtps\""));
        assert!(config.contains("smtps=true"));
        assert!(config.contains("[ftp]\nname=\"ftps\""));
        assert!(config.contains("implicit-tls=true"));
        assert!(config.contains("[pop3]\nname=\"pop3s\""));
        assert!(config.contains("pop3s=true"));
        assert!(config.contains("[imap]\nname=\"imaps\""));
        assert!(config.contains("imaps=true"));
        assert!(config.contains("[mqtt]\nname=\"mqtts\""));
        assert!(config.contains("tls=true"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn zgrab_process_receives_tagged_targets_and_returns_enrichment() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "scanner-rs-fake-zgrab2-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        std::fs::write(
            &path,
            br#"#!/bin/sh
while IFS=',' read -r ip domain tag port; do
  printf '{"ip":"%s","data":{"%s":{"status":"success","protocol":"%s","port":%s,"result":{"banner":"identified"}}}}\n' "$ip" "$tag" "$tag" "$port"
done
"#,
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();

        let config = ServiceDetectionConfig {
            enabled: true,
            zgrab_path: path.to_string_lossy().into_owned(),
            ..ServiceDetectionConfig::default()
        };
        let outcome = run(
            &config,
            &[
                open_port("192.0.2.10", 22, "tcp"),
                open_port("192.0.2.11", 8080, "tcp"),
            ],
            "ipv4",
            &AtomicBool::new(false),
        )
        .await
        .unwrap();
        std::fs::remove_file(&path).unwrap();

        let EngineOutcome::Completed(results) = outcome else {
            panic!("service detection must complete");
        };
        assert_eq!(results.len(), 2);
        assert!(
            results
                .iter()
                .any(|item| item.service.as_deref() == Some("ssh"))
        );
        assert!(
            results
                .iter()
                .any(|item| item.service.as_deref() == Some("http"))
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn adaptive_fallback_identifies_mysql_on_a_nonstandard_port() {
        use crate::types::ServiceDetectionStrategy;
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "scanner-rs-fake-adaptive-zgrab2-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        std::fs::write(
            &path,
            br#"#!/bin/sh
while IFS=',' read -r ip domain tag port; do
  if [ "$tag" = "mysql" ]; then
    status=success
  else
    status=protocol-error
  fi
  printf '{"ip":"%s","data":{"%s":{"status":"%s","protocol":"%s","port":%s,"result":{"banner":"mysql identified"}}}}\n' "$ip" "$tag" "$status" "$tag" "$port"
done
"#,
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();

        let config = ServiceDetectionConfig {
            enabled: true,
            strategy: ServiceDetectionStrategy::Adaptive,
            max_probes_per_endpoint: 8,
            zgrab_path: path.to_string_lossy().into_owned(),
            ..ServiceDetectionConfig::default()
        };
        let outcome = run(
            &config,
            &[open_port("192.0.2.20", 13306, "tcp")],
            "ipv4",
            &AtomicBool::new(false),
        )
        .await
        .unwrap();
        std::fs::remove_file(&path).unwrap();

        let EngineOutcome::Completed(results) = outcome else {
            panic!("service detection must complete");
        };
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].port, 13306);
        assert_eq!(results[0].service.as_deref(), Some("mysql"));
        assert_eq!(results[0].data.as_ref().unwrap()["attempt_count"], 8);
    }

    #[test]
    fn strip_nul_removes_nul_characters() {
        assert_eq!(strip_nul("a\u{0}b\u{0}c"), "abc");
        assert_eq!(strip_nul("clean"), "clean");
    }

    #[test]
    fn bounded_detail_strips_nul_from_nested_data() {
        let module_data = json!({
            "status": "success",
            "result": {
                "response": {"body": "bin\u{0}ary"},
                "banner": "telnet\u{0}banner",
            }
        });
        let detail = bounded_detail(&module_data, 1024);
        assert_eq!(detail["result"]["response"]["body"], "binary");
        assert_eq!(detail["result"]["banner"], "telnetbanner");
    }
}
