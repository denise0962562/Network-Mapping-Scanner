use crate::error::ScannerError;
use crate::types::{ScanResult, TargetParams};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{ChildStderr, Command};
use tokio::task::JoinHandle;
use tokio::time::{Duration, sleep};

const MAX_SCANNER_STDERR_CHARS: usize = 4096;

pub(crate) enum ScanOutcome {
    Completed(Vec<ScanResult>),
    Cancelled,
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

// ---- Scanner abstraction ------------------------------------------------
//
// To add a new scanner (e.g. nuclei for vulnerability scanning):
//   1. Add a new module under scanner/ (e.g. scanner/nuclei.rs)
//   2. Implement a `run_xxx()` function following the same signature
//   3. Dispatch here based on config or CLI flag

/// Run a scan against `target` using the configured scanner binary.
///
/// Currently dispatches to masscan. The scanner type is determined by
/// the binary path — pass a masscan binary for port scanning, or a
/// nuclei binary for vulnerability scanning.
pub(crate) async fn run_scan(
    scanner_path: &str,
    target: &TargetParams,
    cancel_requested: &AtomicBool,
) -> Result<ScanOutcome, ScannerError> {
    // Future: match on scanner type / path to dispatch
    run_masscan(scanner_path, target, cancel_requested).await
}

// ---- Masscan implementation ---------------------------------------------

async fn run_masscan(
    path: &str,
    target: &TargetParams,
    cancel_requested: &AtomicBool,
) -> Result<ScanOutcome, ScannerError> {
    tracing::debug!(
        scanner_path = path,
        targets = %target.ip,
        ports = %target.port,
        rate = target.rate,
        source_port = target.source_port,
        banner_scan = true,
        "spawning masscan process"
    );
    let started_at = Instant::now();
    let mut child = Command::new(path)
        .arg(&target.ip)
        .args(["-p", &target.port])
        .args(["--rate", &target.rate.to_string()])
        .arg("--banner")
        .args(["--source-port", &target.source_port.to_string()])
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
    let mut banner_count = 0usize;
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
            return Ok(ScanOutcome::Cancelled);
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
            MasscanLine::Banner(r) => {
                banner_count += 1;
                results.push(r);
            }
            MasscanLine::Error => {
                tracing::error!("scanner reported error: {}", trimmed);
                let _ = child.wait().await;
                let stderr_output = finish_scanner_stderr(stderr_handle).await;
                let detail = scanner_failure_detail(trimmed, &stderr_output);
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

    tracing::debug!(
        exit_code = ?status.code(),
        success = status.success(),
        elapsed_ms = started_at.elapsed().as_millis(),
        discovered_count,
        banner_count,
        unknown_count,
        result_count = results.len(),
        "masscan process finished"
    );

    if !status.success() {
        let detail = scanner_failure_detail("scanner produced no stderr output", &stderr_output);
        tracing::error!(
            exit_code = ?status.code(),
            stderr = %stderr_output,
            "masscan exited unsuccessfully"
        );
        return Err(ScannerError::Scan(format!(
            "masscan exited with {status}: {detail}"
        )));
    }

    Ok(ScanOutcome::Completed(results))
}

async fn log_scanner_stderr(stderr: ChildStderr) -> String {
    let mut lines = BufReader::new(stderr).lines();
    let mut captured = String::new();
    let mut captured_chars = 0usize;
    let mut truncated = false;

    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                tracing::debug!(line = %line, "masscan stderr");
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
    captured
}

async fn finish_scanner_stderr(handle: JoinHandle<String>) -> String {
    match handle.await {
        Ok(output) => output,
        Err(error) => {
            tracing::warn!(error = %error, "masscan stderr reader task failed");
            String::new()
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
    Discovered(ScanResult),
    Banner(ScanResult),
    Complete,
    DoneOk,
    Error,
    Unknown,
}

impl MasscanLine {
    fn parse(line: &str) -> Self {
        if line.starts_with("Discovered") {
            return parse_discovered(line).map_or(Self::Unknown, Self::Discovered);
        }
        if line.starts_with("Banner") {
            return parse_banner(line).map_or(Self::Unknown, Self::Banner);
        }
        match line {
            s if s.starts_with("COMPLETE") => Self::Complete,
            s if s.starts_with("DONE_OK") => Self::DoneOk,
            s if s.starts_with("ERROR") => Self::Error,
            _ => Self::Unknown,
        }
    }
}

fn parse_discovered(line: &str) -> Option<ScanResult> {
    let mut parts = line.split_whitespace().skip(1);
    let port: u16 = parts.next()?.parse().ok()?;
    let protocol = parts.next()?.to_owned();
    let ip = parts.next()?.to_owned();

    Some(ScanResult {
        ip,
        port,
        protocol,
        service: None,
        banner: None,
    })
}

fn parse_banner(line: &str) -> Option<ScanResult> {
    let mut parts = line.splitn(6, char::is_whitespace).skip(1);
    let port: u16 = parts.next()?.parse().ok()?;
    let protocol = parts.next()?.to_owned();
    let ip = parts.next()?.to_owned();
    let service = parts.next()?.to_owned();
    let banner = parts.next().map(|s| s.trim().to_owned());

    Some(ScanResult {
        ip,
        port,
        protocol,
        service: Some(service),
        banner,
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
            b"#!/bin/sh\nprintf 'permission denied by test scanner\\n' >&2\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();

        let target = TargetParams {
            ip: "192.0.2.1/32".into(),
            port: "80".into(),
            rate: 100,
            source_port: 61_000,
        };
        let cancel_requested = AtomicBool::new(false);
        let result = run_masscan(path.to_str().unwrap(), &target, &cancel_requested).await;
        std::fs::remove_file(&path).unwrap();

        let error = match result {
            Err(error) => error.to_string(),
            Ok(_) => panic!("non-zero scanner exit must not be reported as completed"),
        };
        assert!(error.contains("exit status: 1"));
        assert!(error.contains("permission denied by test scanner"));
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
        assert!(r.service.is_none());
    }

    #[test]
    fn test_parse_banner() {
        let r = parse_banner("Banner 22 tcp 192.168.1.1 SSH OpenSSH_8.9p1").unwrap();
        assert_eq!(r.port, 22);
        assert_eq!(r.service.as_deref(), Some("SSH"));
        assert!(r.banner.unwrap().contains("OpenSSH"));
    }

    #[test]
    fn test_parse_banner_no_trailing_text() {
        let r = parse_banner("Banner 443 tcp 10.0.0.1 https").unwrap();
        assert_eq!(r.service.as_deref(), Some("https"));
        assert!(r.banner.is_none());
    }
}
