use crate::error::ScannerError;
use crate::scan::PortObservation;
use crate::types::TargetParams;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{ChildStderr, Command};
use tokio::task::JoinHandle;
use tokio::time::{Duration, sleep};

const MAX_SCANNER_STDERR_CHARS: usize = 4096;

pub(crate) enum EngineOutcome {
    Completed(Vec<PortObservation>),
    Cancelled,
}

#[derive(Default)]
struct StderrCapture {
    text: String,
    bytes: usize,
    truncated: bool,
}

/// Validate that the configured scanner resolves to an executable file.
///
/// Explicit paths are checked directly. A bare command name is resolved
/// through `PATH`, matching the way `std::process::Command` locates programs.
pub(crate) fn validate_scanner_binary(scanner_path: &str) -> Result<(), ScannerError> {
    if scanner_path.trim().is_empty() {
        return Err(ScannerError::Config(
            "scanner.scanner_path must not be empty".into(),
        ));
    }

    let configured_path = Path::new(scanner_path);
    let resolved = if is_explicit_path(configured_path) {
        configured_path.to_path_buf()
    } else {
        find_in_path(configured_path).ok_or_else(|| {
            ScannerError::Config(format!(
                "scanner.scanner_path '{scanner_path}' was not found as an executable file in PATH"
            ))
        })?
    };

    let metadata = std::fs::metadata(&resolved).map_err(|error| {
        ScannerError::Config(format!(
            "scanner.scanner_path '{}' cannot be accessed: {error}",
            resolved.display()
        ))
    })?;

    if !metadata.is_file() {
        return Err(ScannerError::Config(format!(
            "scanner.scanner_path '{}' is not a file",
            resolved.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(ScannerError::Config(format!(
                "scanner.scanner_path '{}' is not executable",
                resolved.display()
            )));
        }
    }

    tracing::info!(scanner_path = %resolved.display(), "scanner binary validated");
    Ok(())
}

fn is_explicit_path(path: &Path) -> bool {
    path.is_absolute() || path.components().count() > 1
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
    path: &str,
    target: &TargetParams,
    cancel_requested: &AtomicBool,
) -> Result<EngineOutcome, ScannerError> {
    tracing::debug!(
        scanner_path = path,
        targets = %target.ip,
        ports = %target.port,
        rate = target.rate,
        banner_scan = false,
        "spawning masscan process"
    );
    let started_at = Instant::now();
    let mut child = Command::new(path)
        .arg(&target.ip)
        .args(["-p", &target.port])
        .args(["--rate", &target.rate.to_string()])
        .args(["--output-format", "list"])
        .args(["--output-filename", "-"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| ScannerError::Scan(format!("failed to spawn scanner: {}", e)))?;

    tracing::debug!(process_id = ?child.id(), "masscan process spawned");

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ScannerError::Scan("scanner stdout unavailable".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ScannerError::Scan("scanner stderr unavailable".into()))?;
    let stderr_handle = tokio::spawn(log_scanner_stderr(stderr));

    let mut lines = BufReader::new(stdout).lines();
    let mut results = Vec::new();
    let mut discovered_count = 0usize;
    let mut unknown_count = 0usize;

    loop {
        if cancel_requested.load(Ordering::Relaxed) {
            tracing::debug!(process_id = ?child.id(), "stopping masscan after cancellation request");
            child
                .kill()
                .await
                .map_err(|e| ScannerError::Scan(format!("failed to stop scanner: {e}")))?;
            let _ = child.wait().await;
            let _ = finish_scanner_stderr(stderr_handle).await;
            tracing::debug!(
                elapsed_ms = started_at.elapsed().as_millis(),
                "masscan cancelled"
            );
            return Ok(EngineOutcome::Cancelled);
        }
        let line = tokio::select! {
            line = lines.next_line() => line.map_err(|e| ScannerError::Scan(format!("read error: {e}")))?,
            _ = sleep(Duration::from_millis(200)) => continue,
        };
        let Some(line) = line else { break };
        let trimmed = line.trim();

        match MasscanLine::parse(trimmed) {
            MasscanLine::Discovered(r) => {
                discovered_count += 1;
                results.push(r);
            }
            MasscanLine::Error => {
                let process_id = child.id();
                let status = child.wait().await.ok();
                let stderr_output = finish_scanner_stderr(stderr_handle).await;
                let detail = scanner_failure_detail(trimmed, &stderr_output.text);
                tracing::error!(
                    event = "MasscanErrorMarker",
                    operation = "parse_masscan_output",
                    error_kind = "external_process",
                    error_code = "masscan_error_marker",
                    error_message = %detail,
                    retryable = false,
                    outcome = "task_failed",
                    engine = "masscan",
                    stage = "read_stdout",
                    process_id = ?process_id,
                    exit_code = ?status.and_then(|value| value.code()),
                    elapsed_ms = started_at.elapsed().as_millis(),
                    discovered_count,
                    unknown_count,
                    result_count = results.len(),
                    stderr_bytes = stderr_output.bytes,
                    stderr_truncated = stderr_output.truncated,
                    "masscan reported an error marker"
                );
                return Err(ScannerError::Scan(format!("scanner error: {detail}")));
            }
            MasscanLine::Complete => {
                tracing::debug!(marker = "COMPLETE", "masscan completion marker received");
                break;
            }
            MasscanLine::DoneOk => {
                tracing::debug!(marker = "DONE_OK", "masscan completion marker received");
                break;
            }
            MasscanLine::Unknown => {
                unknown_count += 1;
                tracing::debug!(line = trimmed, "unrecognized masscan stdout line");
            }
        }
    }

    let status = child
        .wait()
        .await
        .map_err(|e| ScannerError::Scan(format!("waitpid failed: {}", e)))?;
    let stderr_output = finish_scanner_stderr(stderr_handle).await;

    tracing::info!(
        event = "PortDiscoveryCompleted",
        exit_code = ?status.code(),
        success = status.success(),
        elapsed_ms = started_at.elapsed().as_millis(),
        discovered_count,
        unknown_count,
        result_count = results.len(),
        "port discovery completed"
    );

    if !status.success() {
        let detail =
            scanner_failure_detail("scanner produced no stderr output", &stderr_output.text);
        tracing::error!(
            event = "MasscanProcessFailed",
            operation = "wait_masscan_process",
            error_kind = "process_exit",
            error_code = "masscan_nonzero_exit",
            error_message = %detail,
            retryable = false,
            outcome = "task_failed",
            engine = "masscan",
            stage = "process_exit",
            exit_code = ?status.code(),
            elapsed_ms = started_at.elapsed().as_millis(),
            discovered_count,
            unknown_count,
            result_count = results.len(),
            stderr_bytes = stderr_output.bytes,
            stderr_truncated = stderr_output.truncated,
            "masscan exited unsuccessfully"
        );
        return Err(ScannerError::Scan(format!(
            "masscan exited with {status}: {detail}"
        )));
    }

    Ok(EngineOutcome::Completed(results))
}

async fn log_scanner_stderr(stderr: ChildStderr) -> StderrCapture {
    let mut lines = BufReader::new(stderr).lines();
    let mut captured = String::new();
    let mut captured_chars = 0usize;
    let mut bytes = 0usize;
    let mut truncated = false;

    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                tracing::debug!(line = %line, "masscan stderr");
                bytes = bytes.saturating_add(line.len()).saturating_add(1);
                if captured_chars < MAX_SCANNER_STDERR_CHARS {
                    if !captured.is_empty() {
                        captured.push('\n');
                        captured_chars += 1;
                    }
                    let remaining = MAX_SCANNER_STDERR_CHARS.saturating_sub(captured_chars);
                    let line_chars = line.chars().count();
                    captured.extend(line.chars().take(remaining));
                    captured_chars += line_chars.min(remaining);
                    truncated |= line_chars > remaining;
                } else {
                    truncated = true;
                }
            }
            Ok(None) => break,
            Err(error) => {
                tracing::warn!(error = %error, "failed to read masscan stderr");
                break;
            }
        }
    }

    if truncated {
        captured.push_str("\n[stderr truncated]");
    }
    StderrCapture {
        text: captured,
        bytes,
        truncated,
    }
}

async fn finish_scanner_stderr(handle: JoinHandle<StderrCapture>) -> StderrCapture {
    match handle.await {
        Ok(output) => output,
        Err(error) => {
            tracing::warn!(error = %error, "masscan stderr reader task failed");
            StderrCapture::default()
        }
    }
}

fn scanner_failure_detail(stdout_error: &str, stderr_output: &str) -> String {
    if stderr_output.trim().is_empty() {
        stdout_error.to_owned()
    } else {
        stderr_output.trim().to_owned()
    }
}

// ---- Masscan line parser ------------------------------------------------

enum MasscanLine {
    Discovered(PortObservation),
    Complete,
    DoneOk,
    Error,
    Unknown,
}

impl MasscanLine {
    fn parse(line: &str) -> Self {
        if line.starts_with("open ") || line.starts_with("Discovered") {
            return parse_discovered(line).map_or(Self::Unknown, Self::Discovered);
        }
        match line {
            s if s.starts_with("COMPLETE") => Self::Complete,
            s if s.starts_with("DONE_OK") => Self::DoneOk,
            s if s.starts_with("ERROR") => Self::Error,
            _ => Self::Unknown,
        }
    }
}

fn parse_discovered(line: &str) -> Option<PortObservation> {
    let (port, protocol, ip) = if line.starts_with("open ") {
        let mut parts = line.split_whitespace().skip(1);
        let protocol = parts.next()?.to_owned();
        let port = parts.next()?.parse().ok()?;
        let ip = parts.next()?.to_owned();
        (port, protocol, ip)
    } else {
        let mut parts = line.split_whitespace().skip(1);
        let port = parts.next()?.parse().ok()?;
        let protocol = parts.next()?.to_owned();
        let ip = parts.next()?.to_owned();
        (port, protocol, ip)
    };

    Some(PortObservation {
        ip,
        port,
        protocol,
        state: "open".into(),
        source: "masscan".into(),
        observed_at: chrono::Utc::now().timestamp_millis(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn nonzero_scanner_exit_returns_error_with_stderr() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "scanner-rs-failing-scanner-{}-{nonce}",
            std::process::id()
        ));
        std::fs::write(
            &path,
            b"#!/bin/sh\nprintf 'args:%s\\n' \"$*\" >&2\nprintf 'permission denied by test scanner\\n' >&2\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();

        let target = TargetParams {
            ip: "192.0.2.1/32".into(),
            port: "80".into(),
            rate: 100,
            address_family: "ipv4".into(),
        };
        let cancel_requested = AtomicBool::new(false);
        let result = run(path.to_str().unwrap(), &target, &cancel_requested).await;
        std::fs::remove_file(&path).unwrap();

        let error = match result {
            Err(error) => error.to_string(),
            Ok(_) => panic!("non-zero scanner exit must not be reported as completed"),
        };
        assert!(error.contains("exit status: 1"));
        assert!(error.contains("permission denied by test scanner"));
        assert!(!error.contains("--source-port"));
    }

    #[test]
    fn validate_scanner_binary_accepts_current_executable() {
        let executable = std::env::current_exe().expect("current executable path");

        assert!(validate_scanner_binary(executable.to_str().unwrap()).is_ok());
    }

    #[test]
    fn validate_scanner_binary_rejects_missing_file() {
        let path = std::env::temp_dir().join(format!(
            "scanner-rs-missing-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));

        let error = validate_scanner_binary(path.to_str().unwrap()).unwrap_err();

        assert!(error.to_string().contains("cannot be accessed"));
        assert!(error.to_string().contains(path.to_str().unwrap()));
    }

    #[test]
    fn validate_scanner_binary_rejects_directory() {
        let directory = std::env::temp_dir();

        let error = validate_scanner_binary(directory.to_str().unwrap()).unwrap_err();

        assert!(error.to_string().contains("is not a file"));
    }

    #[cfg(unix)]
    #[test]
    fn validate_scanner_binary_rejects_file_without_execute_permission() {
        use std::os::unix::fs::PermissionsExt;

        let path =
            std::env::temp_dir().join(format!("scanner-rs-not-executable-{}", std::process::id()));
        std::fs::write(&path, b"not executable").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let error = validate_scanner_binary(path.to_str().unwrap()).unwrap_err();
        std::fs::remove_file(&path).unwrap();

        assert!(error.to_string().contains("is not executable"));
    }

    #[test]
    fn test_parse_discovered() {
        let r = parse_discovered("Discovered  80 tcp 192.168.1.1").unwrap();
        assert_eq!(r.port, 80);
        assert_eq!(r.protocol, "tcp");
        assert_eq!(r.ip, "192.168.1.1");
        assert_eq!(r.state, "open");
    }

    #[test]
    fn test_parse_masscan_list_output() {
        let r = parse_discovered("open tcp 22 192.168.1.1 1720000000").unwrap();
        assert_eq!(r.port, 22);
        assert_eq!(r.protocol, "tcp");
        assert_eq!(r.ip, "192.168.1.1");
        assert_eq!(r.source, "masscan");
    }
}
