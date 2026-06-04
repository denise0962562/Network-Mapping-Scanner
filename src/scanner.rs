use crate::error::ScannerError;
use crate::types::ScanResult;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

/// Run a masscan scan against a target and collect parsed results.
///
/// Spawns the external masscan binary (./a) with the provided target parameters,
/// then parses its stdout line by line. Returns all parsed scan results.
///
/// # Arguments
/// * `target_ip` - The target IP address
/// * `target_port` - The target port(s) specification (e.g., "80", "1-1000")
/// * `rate` - Packet send rate for masscan
/// * `source_port` - Source port for banner scanning
pub async fn run_scan(
    target_ip: &str,
    target_port: &str,
    rate: i32,
    source_port: i32,
) -> Result<Vec<ScanResult>, ScannerError> {
    let rate_str = rate.to_string();
    let source_port_str = source_port.to_string();

    let mut child = Command::new("./a")
        .arg(target_ip)
        .args(["-p", target_port])
        .args(["--rate", &rate_str])
        .arg("--banner")
        .args(["--source-port", &source_port_str])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| ScannerError::Scan(format!("启动 masscan 子进程失败: {}", e)))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ScannerError::Scan("无法获取 masscan 标准输出".into()))?;

    let reader = BufReader::new(stdout);
    let mut lines = reader.lines();
    let mut results = Vec::new();

    loop {
        let line = lines
            .next_line()
            .await
            .map_err(|e| ScannerError::Scan(format!("读取 masscan 输出行失败: {}", e)))?;

        let line = match line {
            Some(l) => l,
            None => break, // EOF
        };

        let trimmed = line.trim();

        if trimmed.starts_with("Discovered") {
            if let Some(result) = parse_discovered(trimmed) {
                results.push(result);
            }
        } else if trimmed.starts_with("Banner") {
            if let Some(result) = parse_banner(trimmed) {
                results.push(result);
            }
        } else if trimmed.starts_with("ERROR") {
            tracing::error!("masscan 子进程报告错误: {}", trimmed);
            let _ = child.wait().await;
            return Err(ScannerError::Scan(format!(
                "masscan 执行出错: {}",
                trimmed
            )));
        } else if trimmed.starts_with("COMPLETE") {
            tracing::info!("masscan 扫描完成 (COMPLETE)");
            break;
        } else if trimmed.starts_with("DONE_OK") {
            tracing::info!("masscan 子进程正常结束 (DONE_OK)");
            break;
        }
    }

    // Wait for the child process to exit
    let status = child
        .wait()
        .await
        .map_err(|e| ScannerError::Scan(format!("等待 masscan 子进程退出失败: {}", e)))?;

    if !status.success() {
        tracing::warn!("masscan 子进程以非零状态退出: {:?}", status.code());
    }

    Ok(results)
}

/// Parse a "Discovered" line from masscan output.
///
/// Format: `Discovered  <port> <protocol> <ip>`
fn parse_discovered(line: &str) -> Option<ScanResult> {
    let parts: Vec<&str> = line.split_whitespace().collect();

    if parts.len() < 4 {
        return None;
    }

    let port: u16 = parts[1].parse().ok()?;
    let protocol = parts[2].to_string();
    let ip = parts[3].to_string();

    Some(ScanResult {
        ip,
        port,
        protocol,
        service: None,
        banner: None,
    })
}

/// Parse a "Banner" line from masscan output.
///
/// Format: `Banner <port> <protocol> <ip> <service> <banner...>`
fn parse_banner(line: &str) -> Option<ScanResult> {
    let parts: Vec<&str> = line.splitn(6, char::is_whitespace).collect();

    if parts.len() < 5 {
        return None;
    }

    let port: u16 = parts[1].parse().ok()?;
    let protocol = parts[2].to_string();
    let ip = parts[3].to_string();
    let service = parts[4].to_string();
    let banner = if parts.len() > 5 {
        Some(parts[5].trim().to_string())
    } else {
        None
    };

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
        let line = "Discovered  80 tcp 192.168.1.1";
        let result = parse_discovered(line).unwrap();
        assert_eq!(result.port, 80);
        assert_eq!(result.protocol, "tcp");
        assert_eq!(result.ip, "192.168.1.1");
        assert_eq!(result.service, None);
        assert_eq!(result.banner, None);
    }

    #[test]
    fn test_parse_banner() {
        let line = "Banner 22 tcp 192.168.1.1 SSH OpenSSH_8.9p1 Ubuntu-3ubuntu0.7";
        let result = parse_banner(line).unwrap();
        assert_eq!(result.port, 22);
        assert_eq!(result.protocol, "tcp");
        assert_eq!(result.ip, "192.168.1.1");
        assert_eq!(result.service, Some("SSH".to_string()));
        assert!(result.banner.unwrap().contains("OpenSSH"));
    }
}
