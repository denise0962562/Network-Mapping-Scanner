use crate::error::ScannerError;
use crate::scan::{PortObservation, ServiceObservation, VulnerabilityObservation};
use crate::types::NucleiConfig;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{ChildStderr, Command};
use tokio::task::JoinHandle;
use tokio::time::{Duration, sleep};
use uuid::Uuid;

const MAX_STDERR_CHARS: usize = 4_096;

pub(crate) enum EngineOutcome {
    Completed(Vec<VulnerabilityObservation>),
    Cancelled,
}

pub(crate) fn validate_binary(path: &str) -> Result<(), ScannerError> {
    if path.trim().is_empty() {
        return Err(ScannerError::Config("nuclei.path must not be empty".into()));
    }
    let configured = Path::new(path);
    let resolved = if configured.is_absolute() || configured.components().count() > 1 {
        configured.to_path_buf()
    } else {
        find_in_path(configured).ok_or_else(|| {
            ScannerError::Config(format!(
                "nuclei.path '{path}' was not found as an executable file in PATH"
            ))
        })?
    };
    let metadata = std::fs::metadata(&resolved).map_err(|error| {
        ScannerError::Config(format!(
            "nuclei binary '{}' cannot be accessed: {error}",
            resolved.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(ScannerError::Config(format!(
            "nuclei binary '{}' is not a file",
            resolved.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(ScannerError::Config(format!(
                "nuclei binary '{}' is not executable",
                resolved.display()
            )));
        }
    }
    tracing::info!(nuclei_path = %resolved.display(), "nuclei binary validated");
    Ok(())
}

pub(crate) fn validate_templates(path: &str) -> Result<(), ScannerError> {
    let templates = Path::new(path);
    let metadata = std::fs::metadata(templates).map_err(|error| {
        ScannerError::Config(format!(
            "nuclei.templates_path '{}' cannot be accessed: {error}",
            templates.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(ScannerError::Config(format!(
            "nuclei.templates_path '{}' is not a directory",
            templates.display()
        )));
    }
    tracing::info!(templates_path = %templates.display(), "nuclei template directory validated");
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
    config: &NucleiConfig,
    ports: &[PortObservation],
    services: &[ServiceObservation],
    cancel_requested: &AtomicBool,
) -> Result<EngineOutcome, ScannerError> {
    let targets = build_targets(ports, services);
    if targets.is_empty() {
        tracing::info!(
            event = "VulnerabilityScanSkipped",
            reason = "no_open_endpoints"
        );
        return Ok(EngineOutcome::Completed(Vec::new()));
    }

    let target_path = std::env::temp_dir().join(format!(
        "network-mapping-nuclei-targets-{}-{}.txt",
        std::process::id(),
        Uuid::now_v7()
    ));
    tokio::fs::write(&target_path, targets.join("\n"))
        .await
        .map_err(|error| ScannerError::Scan(format!("failed to write nuclei targets: {error}")))?;

    let started_at = Instant::now();
    let mut command = Command::new(&config.path);
    command
        .arg("-list")
        .arg(&target_path)
        .arg("-templates")
        .arg(&config.templates_path)
        .arg("-severity")
        .arg(config.severities.join(","))
        .arg("-jsonl")
        .arg("-silent")
        .arg("-no-interactsh")
        .arg("-disable-unsigned-templates")
        .arg("-disable-update-check")
        .arg("-rate-limit")
        .arg(config.rate_limit.to_string())
        .arg("-bulk-size")
        .arg(config.bulk_size.to_string())
        .arg("-concurrency")
        .arg(config.concurrency.to_string())
        .arg("-timeout")
        .arg(config.timeout_seconds.to_string())
        .arg("-retries")
        .arg(config.retries.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    tracing::info!(
        event = "VulnerabilityScanStarted",
        target_count = targets.len(),
        rate_limit = config.rate_limit,
        concurrency = config.concurrency,
        "starting nuclei vulnerability scan"
    );
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = tokio::fs::remove_file(&target_path).await;
            return Err(ScannerError::Scan(format!(
                "failed to spawn nuclei: {error}"
            )));
        }
    };
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ScannerError::Scan("nuclei stdout unavailable".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ScannerError::Scan("nuclei stderr unavailable".into()))?;
    let stderr_handle = tokio::spawn(collect_stderr(stderr));
    let mut lines = BufReader::new(stdout).lines();
    let mut findings = Vec::new();
    let mut invalid_lines = 0usize;

    loop {
        let timed_out = started_at.elapsed() >= Duration::from_secs(config.max_runtime_seconds);
        if cancel_requested.load(Ordering::Relaxed) || timed_out {
            let _ = child.kill().await;
            let _ = child.wait().await;
            let _ = finish_stderr(stderr_handle).await;
            let _ = tokio::fs::remove_file(&target_path).await;
            if timed_out {
                return Err(ScannerError::Scan(format!(
                    "nuclei exceeded the {} second runtime limit",
                    config.max_runtime_seconds
                )));
            }
            return Ok(EngineOutcome::Cancelled);
        }
        let line = tokio::select! {
            line = lines.next_line() => line
                .map_err(|error| ScannerError::Scan(format!("failed to read nuclei output: {error}")))?,
            _ = sleep(Duration::from_millis(200)) => continue,
        };
        let Some(line) = line else { break };
        if line.len() > config.max_result_bytes {
            let _ = child.kill().await;
            let _ = child.wait().await;
            let _ = finish_stderr(stderr_handle).await;
            let _ = tokio::fs::remove_file(&target_path).await;
            return Err(ScannerError::Scan(
                "nuclei result exceeded max_result_bytes".into(),
            ));
        }
        match parse_result(&line) {
            Ok(finding) => findings.push(finding),
            Err(error) => {
                invalid_lines += 1;
                tracing::warn!(%error, "ignored invalid nuclei JSONL output line");
            }
        }
        if findings.len() > config.max_findings {
            let _ = child.kill().await;
            let _ = child.wait().await;
            let _ = finish_stderr(stderr_handle).await;
            let _ = tokio::fs::remove_file(&target_path).await;
            return Err(ScannerError::Scan(format!(
                "nuclei exceeded the {} finding limit",
                config.max_findings
            )));
        }
    }

    let status = child
        .wait()
        .await
        .map_err(|error| ScannerError::Scan(format!("failed to wait for nuclei: {error}")))?;
    let stderr_output = finish_stderr(stderr_handle).await;
    let _ = tokio::fs::remove_file(&target_path).await;
    if !status.success() {
        let detail = if stderr_output.trim().is_empty() {
            "nuclei produced no stderr output"
        } else {
            stderr_output.trim()
        };
        return Err(ScannerError::Scan(format!(
            "nuclei exited with {status}: {detail}"
        )));
    }
    if invalid_lines > 0 {
        return Err(ScannerError::Scan(format!(
            "nuclei produced {invalid_lines} invalid JSONL result line(s)"
        )));
    }
    tracing::info!(
        event = "VulnerabilityScanCompleted",
        elapsed_ms = started_at.elapsed().as_millis(),
        finding_count = findings.len(),
        "nuclei vulnerability scan completed"
    );
    Ok(EngineOutcome::Completed(findings))
}

fn build_targets(ports: &[PortObservation], services: &[ServiceObservation]) -> Vec<String> {
    let service_by_endpoint = services
        .iter()
        .filter_map(|item| {
            item.service
                .as_deref()
                .map(|service| ((item.ip.as_str(), item.port), service))
        })
        .collect::<HashMap<_, _>>();
    let mut targets = BTreeSet::new();
    for endpoint in ports.iter().filter(|item| item.state == "open") {
        let host = if endpoint.ip.contains(':') {
            format!("[{}]", endpoint.ip)
        } else {
            endpoint.ip.clone()
        };
        let service = service_by_endpoint
            .get(&(endpoint.ip.as_str(), endpoint.port))
            .map(|value| value.to_ascii_lowercase());
        let scheme = match service.as_deref() {
            Some("http") | Some("http-alt") => Some("http"),
            Some("https") | Some("https-alt") | Some("tls") | Some("ssl") => Some("https"),
            _ if matches!(endpoint.port, 80 | 8000 | 8080 | 8081 | 8888) => Some("http"),
            _ if matches!(endpoint.port, 443 | 8443 | 9443) => Some("https"),
            _ => None,
        };
        targets.insert(match scheme {
            Some(scheme) => format!("{scheme}://{host}:{}", endpoint.port),
            None => format!("{host}:{}", endpoint.port),
        });
    }
    targets.into_iter().collect()
}

fn parse_result(line: &str) -> Result<VulnerabilityObservation, ScannerError> {
    let root: Value = serde_json::from_str(line)?;
    let info = root.get("info").unwrap_or(&Value::Null);
    let template_id = required_text(&root, "template-id")?;
    let name = required_text(info, "name")?;
    let severity = required_text(info, "severity")?.to_ascii_lowercase();
    let matched_at = required_text(&root, "matched-at")?;
    let scheme = root
        .get("scheme")
        .and_then(Value::as_str)
        .or_else(|| matched_at.split_once("://").map(|(scheme, _)| scheme))
        .unwrap_or_else(|| root.get("type").and_then(Value::as_str).unwrap_or("tcp"));
    let ip = root
        .get("ip")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .or_else(|| extract_host(&matched_at))
        .ok_or_else(|| ScannerError::Scan("nuclei result is missing ip".into()))?;
    let port = root
        .get("port")
        .and_then(|value| {
            value
                .as_str()
                .and_then(|value| value.parse::<u16>().ok())
                .or_else(|| value.as_u64().and_then(|value| u16::try_from(value).ok()))
        })
        .or_else(|| extract_port(&matched_at))
        .or(match scheme {
            "http" => Some(80),
            "https" => Some(443),
            _ => None,
        })
        .ok_or_else(|| ScannerError::Scan("nuclei result is missing port".into()))?;
    let observed_at = root
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.timestamp_millis())
        .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());

    Ok(VulnerabilityObservation {
        ip: clean_text(&ip, 253),
        port,
        protocol: clean_text(scheme, 16),
        template_id: clean_text(&template_id, 256),
        name: clean_text(&name, 512),
        severity: clean_text(&severity, 16),
        matcher_name: optional_text(&root, "matcher-name").map(|value| clean_text(&value, 256)),
        matched_at: clean_text(&matched_at, 4_096),
        description: optional_text(info, "description").map(|value| clean_text(&value, 8_192)),
        remediation: optional_text(info, "remediation").map(|value| clean_text(&value, 8_192)),
        tags: string_list(info.get("tags"), 128, 128),
        references: string_list(info.get("reference"), 64, 2_048)
            .into_iter()
            .filter(|reference| {
                reference.starts_with("https://") || reference.starts_with("http://")
            })
            .collect(),
        classification: info.get("classification").cloned(),
        extracted_results: string_list(root.get("extracted-results"), 64, 2_048),
        source: "nuclei".into(),
        observed_at,
    })
}

fn required_text(value: &Value, field: &str) -> Result<String, ScannerError> {
    optional_text(value, field)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ScannerError::Scan(format!("nuclei result is missing {field}")))
}

fn optional_text(value: &Value, field: &str) -> Option<String> {
    value.get(field).and_then(Value::as_str).map(str::to_owned)
}

fn string_list(value: Option<&Value>, max_items: usize, max_chars: usize) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .take(max_items)
            .map(|item| clean_text(item, max_chars))
            .collect(),
        Some(Value::String(items)) => items
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .take(max_items)
            .map(|item| clean_text(item, max_chars))
            .collect(),
        _ => Vec::new(),
    }
}

fn clean_text(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .filter(|character| *character != '\0')
        .take(max_chars)
        .collect()
}

fn extract_host(value: &str) -> Option<String> {
    let authority = value
        .split_once("://")
        .map_or(value, |(_, remainder)| remainder)
        .split('/')
        .next()?;
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().map(str::to_owned);
    }
    Some(
        authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host)
            .to_owned(),
    )
}

fn extract_port(value: &str) -> Option<u16> {
    let authority = value
        .split_once("://")
        .map_or(value, |(_, remainder)| remainder)
        .split('/')
        .next()?;
    if let Some((_, remainder)) = authority.rsplit_once(']') {
        return remainder.strip_prefix(':')?.parse().ok();
    }
    authority.rsplit_once(':')?.1.parse().ok()
}

async fn collect_stderr(stderr: ChildStderr) -> String {
    let mut lines = BufReader::new(stderr).lines();
    let mut captured = String::new();
    while let Ok(Some(line)) = lines.next_line().await {
        tracing::debug!(line = %line, "nuclei stderr");
        if captured.chars().count() < MAX_STDERR_CHARS {
            if !captured.is_empty() {
                captured.push('\n');
            }
            let remaining = MAX_STDERR_CHARS.saturating_sub(captured.chars().count());
            captured.extend(line.chars().take(remaining));
        }
    }
    captured
}

async fn finish_stderr(handle: JoinHandle<String>) -> String {
    handle.await.unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_use_detected_web_scheme_and_ipv6_brackets() {
        let ports = vec![
            PortObservation {
                ip: "192.0.2.1".into(),
                port: 8080,
                protocol: "tcp".into(),
                state: "open".into(),
                source: "masscan".into(),
                observed_at: 1,
            },
            PortObservation {
                ip: "2001:db8::1".into(),
                port: 443,
                protocol: "tcp".into(),
                state: "open".into(),
                source: "masscan".into(),
                observed_at: 1,
            },
        ];
        assert_eq!(
            build_targets(&ports, &[]),
            vec!["http://192.0.2.1:8080", "https://[2001:db8::1]:443"]
        );
    }

    #[test]
    fn parses_jsonl_without_retaining_raw_request_or_response() {
        let result = parse_result(r#"{"template-id":"cve-test","info":{"name":"Example","severity":"high","tags":["cve"],"reference":["https://example.test/advisory"]},"type":"http","host":"https://192.0.2.1:8443","port":"8443","scheme":"https","matched-at":"https://192.0.2.1:8443/login","ip":"192.0.2.1","timestamp":"2026-09-03T00:00:00Z","request":"secret","response":"secret"}"#).unwrap();
        assert_eq!(result.ip, "192.0.2.1");
        assert_eq!(result.port, 8443);
        assert_eq!(result.template_id, "cve-test");
        assert_eq!(result.severity, "high");
        assert_eq!(result.tags, vec!["cve"]);
    }
}
