use crate::error::ScannerError;
use crate::types::{ScanResult, ServiceDetectionConfig};
use serde_json::{Value, json};
use std::collections::HashSet;
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

pub(crate) enum ServiceDetectionOutcome {
    Completed(Vec<ScanResult>),
    Cancelled,
}

pub(crate) fn validate_zgrab_binary(path: &str) -> Result<(), ScannerError> {
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

pub(crate) async fn run_service_detection(
    config: &ServiceDetectionConfig,
    open_ports: &[ScanResult],
    address_family: &str,
    cancel_requested: &AtomicBool,
) -> Result<ServiceDetectionOutcome, ScannerError> {
    let input = build_zgrab_input(open_ports);
    if input.is_empty() {
        tracing::debug!("zgrab2 skipped; masscan found no TCP endpoints");
        return Ok(ServiceDetectionOutcome::Completed(Vec::new()));
    }

    let config_file = TempZgrabConfig::create(config).await?;
    let started_at = Instant::now();
    tracing::debug!(
        zgrab_path = %config.zgrab_path,
        endpoint_count = input.lines().count(),
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
            return Ok(ServiceDetectionOutcome::Cancelled);
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

    input_handle
        .await
        .map_err(|error| ScannerError::Scan(format!("zgrab2 input writer failed: {error}")))?
        .map_err(|error| ScannerError::Scan(format!("failed to write zgrab2 input: {error}")))?;
    let status = child
        .wait()
        .await
        .map_err(|error| ScannerError::Scan(format!("failed to wait for zgrab2: {error}")))?;
    let stderr_output = finish_zgrab_stderr(stderr_handle).await;

    tracing::debug!(
        exit_code = ?status.code(),
        success = status.success(),
        elapsed_ms = started_at.elapsed().as_millis(),
        result_count = results.len(),
        invalid_lines,
        "zgrab2 service detection finished"
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

    Ok(ServiceDetectionOutcome::Completed(results))
}

fn build_zgrab_input(open_ports: &[ScanResult]) -> String {
    let mut seen = HashSet::new();
    let mut input = String::new();
    for result in open_ports {
        if result.protocol != "tcp" || !seen.insert((&result.ip, result.port)) {
            continue;
        }
        let module = probe_module_for_port(result.port);
        input.push_str(&format!("{},,{},{}\n", result.ip, module, result.port));
    }
    input
}

fn probe_module_for_port(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 | 587 => "smtp",
        80 | 8000 | 8008 | 8080 | 8081 | 8888 => "http",
        110 => "pop3",
        143 => "imap",
        443 | 4443 | 8443 | 9443 => "https",
        445 => "smb",
        465 | 636 | 853 | 989 | 990 | 993 | 995 => "tls",
        1883 => "mqtt",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgres",
        6379 => "redis",
        11211 => "memcached",
        27017 => "mongodb",
        _ => "banner",
    }
}

fn parse_zgrab_line(line: &str, max_result_bytes: usize) -> Result<Vec<ScanResult>, ScannerError> {
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
        let success = status == "success";
        let service = success
            .then(|| normalized_service(module))
            .flatten()
            .map(str::to_owned);
        let banner = success.then(|| extract_banner(module_data)).flatten();
        results.push(ScanResult {
            ip: ip.to_owned(),
            port,
            protocol: "tcp".into(),
            service,
            banner,
            other: Some(bounded_detail(module, module_data, max_result_bytes)),
        });
    }
    Ok(results)
}

fn normalized_service(module: &str) -> Option<&str> {
    match module {
        "banner" => None,
        value => Some(value),
    }
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
            return Some(text.chars().take(MAX_BANNER_CHARS).collect());
        }
    }
    None
}

fn banner_text(value: &Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.get("raw").and_then(Value::as_str))
}

fn bounded_detail(module: &str, module_data: &Value, max_result_bytes: usize) -> Value {
    let serialized_bytes = serde_json::to_vec(module_data)
        .map(|value| value.len())
        .unwrap_or(0);
    if serialized_bytes <= max_result_bytes {
        return json!({
            "source": "zgrab2",
            "module": module,
            "data": module_data,
        });
    }

    json!({
        "source": "zgrab2",
        "module": module,
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
    for (section, name, port, extra) in [
        ("ftp", "ftp", 21, ""),
        ("ssh", "ssh", 22, ""),
        ("telnet", "telnet", 23, ""),
        ("smtp", "smtp", 25, ""),
        ("http", "http", 80, "endpoint=\"/\"\nmax-redirects=0\n"),
        ("pop3", "pop3", 110, ""),
        ("imap", "imap", 143, ""),
        (
            "http",
            "https",
            443,
            "use-https=true\nendpoint=\"/\"\nmax-redirects=0\n",
        ),
        ("smb", "smb", 445, ""),
        ("tls", "tls", 443, ""),
        ("mqtt", "mqtt", 1883, ""),
        ("mysql", "mysql", 3306, ""),
        ("rdp", "rdp", 3389, ""),
        ("postgres", "postgres", 5432, ""),
        ("redis", "redis", 6379, ""),
        ("memcached", "memcached", 11211, ""),
        ("mongodb", "mongodb", 27017, ""),
        ("banner", "banner", 80, ""),
    ] {
        output.push_str(&format!(
            "[{section}]\nname=\"{name}\"\ntrigger=\"{name}\"\nport={port}\n{timeout}{extra}\n"
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

    fn open_port(ip: &str, port: u16, protocol: &str) -> ScanResult {
        ScanResult {
            ip: ip.into(),
            port,
            protocol: protocol.into(),
            service: None,
            banner: None,
            other: None,
        }
    }

    #[test]
    fn input_deduplicates_tcp_targets_and_tags_modules() {
        let input = build_zgrab_input(&[
            open_port("192.0.2.1", 22, "tcp"),
            open_port("192.0.2.1", 22, "tcp"),
            open_port("192.0.2.1", 53, "udp"),
            open_port("2001:db8::1", 443, "tcp"),
        ]);
        assert_eq!(input, "192.0.2.1,,ssh,22\n2001:db8::1,,https,443\n");
    }

    #[test]
    fn successful_http_result_is_normalized() {
        let line = r#"{"ip":"192.0.2.1","data":{"http":{"status":"success","protocol":"http","port":8080,"result":{"response":{"status_line":"HTTP/1.1 200 OK"}}}}}"#;
        let results = parse_zgrab_line(line, 65_536).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].service.as_deref(), Some("http"));
        assert_eq!(results[0].banner.as_deref(), Some("HTTP/1.1 200 OK"));
        assert_eq!(results[0].other.as_ref().unwrap()["source"], "zgrab2");
    }

    #[test]
    fn failed_probe_preserves_open_port_without_claiming_service() {
        let line = r#"{"ip":"192.0.2.2","data":{"ssh":{"status":"connection-timeout","protocol":"ssh","port":22,"error":"timeout"}}}"#;
        let results = parse_zgrab_line(line, 65_536).unwrap();
        assert_eq!(results[0].port, 22);
        assert!(results[0].service.is_none());
        assert_eq!(
            results[0].other.as_ref().unwrap()["data"]["status"],
            "connection-timeout"
        );
    }

    #[test]
    fn oversized_detail_is_replaced_with_summary() {
        let line = format!(
            r#"{{"ip":"192.0.2.3","data":{{"banner":{{"status":"success","protocol":"banner","port":9000,"result":{{"banner":"{}"}}}}}}}}"#,
            "x".repeat(2048)
        );
        let results = parse_zgrab_line(&line, 1024).unwrap();
        assert_eq!(results[0].other.as_ref().unwrap()["truncated"], true);
        assert!(results[0].service.is_none());
    }

    #[test]
    fn generated_config_routes_http_and_https_separately() {
        let config = zgrab_config(&ServiceDetectionConfig::default());
        assert!(config.contains("name=\"http\""));
        assert!(config.contains("name=\"https\""));
        assert!(config.contains("use-https=true"));
        assert!(config.contains("connect-timeout=\"5s\""));
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
        let outcome = run_service_detection(
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

        let ServiceDetectionOutcome::Completed(results) = outcome else {
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
}
