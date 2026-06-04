use crate::error::ScannerError;
use crate::types::ScanResult;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

/// Spawn masscan, parse its stdout line-by-line, and return all discovered results.
pub(crate) async fn run_scan(
    target_ip: &str,
    target_port: &str,
    rate: i32,
    source_port: i32,
) -> Result<Vec<ScanResult>, ScannerError> {
    let mut child = Command::new("./a")
        .arg(target_ip)
        .args(["-p", target_port])
        .args(["--rate", &rate.to_string()])
        .arg("--banner")
        .args(["--source-port", &source_port.to_string()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| ScannerError::Scan(format!("failed to spawn masscan: {}", e)))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ScannerError::Scan("masscan stdout unavailable".into()))?;

    let mut lines = BufReader::new(stdout).lines();
    let mut results = Vec::new();

    while let Some(line) = lines
        .next_line()
        .await
        .map_err(|e| ScannerError::Scan(format!("read error: {}", e)))?
    {
        let trimmed = line.trim();

        // Dispatch on the first token
        match MasscanLine::parse(trimmed) {
            MasscanLine::Discovered(r) => results.push(r),
            MasscanLine::Banner(r) => results.push(r),
            MasscanLine::Error => {
                tracing::error!("masscan reported error: {}", trimmed);
                let _ = child.wait().await;
                return Err(ScannerError::Scan(format!("masscan error: {}", trimmed)));
            }
            MasscanLine::Complete | MasscanLine::DoneOk => break,
            MasscanLine::Unknown => {} // skip unrecognized lines
        }
    }

    let status = child
        .wait()
        .await
        .map_err(|e| ScannerError::Scan(format!("waitpid failed: {}", e)))?;

    if !status.success() {
        tracing::warn!("masscan exited with non-zero status: {:?}", status.code());
    }

    Ok(results)
}

// ---- masscan line parser ------------------------------------------------

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
    // Format: "Discovered  <port> <protocol> <ip>"
    let mut parts = line.split_whitespace().skip(1); // skip "Discovered"
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
    // Format: "Banner <port> <protocol> <ip> <service> <banner_text...>"
    let mut parts = line.splitn(6, char::is_whitespace).skip(1); // skip "Banner"
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
