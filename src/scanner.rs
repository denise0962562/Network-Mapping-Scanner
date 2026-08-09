use crate::error::ScannerError;
use crate::types::{ScanResult, TargetParams};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::{Duration, sleep};

pub(crate) enum ScanOutcome {
    Completed(Vec<ScanResult>),
    Cancelled,
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

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ScannerError::Scan("scanner stdout unavailable".into()))?;

    let mut lines = BufReader::new(stdout).lines();
    let mut results = Vec::new();

    loop {
        if cancel_requested.load(Ordering::Relaxed) {
            child
                .kill()
                .await
                .map_err(|e| ScannerError::Scan(format!("failed to stop scanner: {e}")))?;
            let _ = child.wait().await;
            return Ok(ScanOutcome::Cancelled);
        }
        let line = tokio::select! {
            line = lines.next_line() => line.map_err(|e| ScannerError::Scan(format!("read error: {e}")))?,
            _ = sleep(Duration::from_millis(200)) => continue,
        };
        let Some(line) = line else { break };
        let trimmed = line.trim();

        match MasscanLine::parse(trimmed) {
            MasscanLine::Discovered(r) => results.push(r),
            MasscanLine::Banner(r) => results.push(r),
            MasscanLine::Error => {
                tracing::error!("scanner reported error: {}", trimmed);
                let _ = child.wait().await;
                return Err(ScannerError::Scan(format!("scanner error: {}", trimmed)));
            }
            MasscanLine::Complete | MasscanLine::DoneOk => break,
            MasscanLine::Unknown => {}
        }
    }

    let status = child
        .wait()
        .await
        .map_err(|e| ScannerError::Scan(format!("waitpid failed: {}", e)))?;

    if !status.success() {
        tracing::warn!("scanner exited with non-zero status: {:?}", status.code());
    }

    Ok(ScanOutcome::Completed(results))
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
