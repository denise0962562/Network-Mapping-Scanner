use crate::error::ScannerError;

#[derive(Debug, serde::Serialize)]
pub(crate) struct SystemInfo {
    pub(crate) os_name: String,
    pub(crate) os_version: String,
    pub(crate) cpu_model: String,
    pub(crate) cpu_cores: u32,
    pub(crate) ram_total_mb: u64,
    pub(crate) uptime_seconds: u64,
}

impl SystemInfo {
    pub(crate) fn gather() -> Result<Self, ScannerError> {
        Ok(Self {
            os_name: read_os_name(),
            os_version: read_os_version(),
            cpu_model: read_cpu_model().unwrap_or_else(|_| "unknown".into()),
            cpu_cores: read_cpu_cores().unwrap_or(0),
            ram_total_mb: read_ram_total().unwrap_or(0),
            uptime_seconds: read_uptime().unwrap_or(0),
        })
    }

    pub(crate) fn print(&self) {
        let uptime = self.uptime_seconds;
        let d = uptime / 86400;
        let h = (uptime % 86400) / 3600;
        let m = (uptime % 3600) / 60;

        println!("╔══════════════════════════════════════════╗");
        println!("║           SYSTEM INFORMATION             ║");
        println!("╠══════════════════════════════════════════╣");
        println!("║ OS       : {:<30}║", truncate(&self.os_name, 30));
        println!("║ Version  : {:<30}║", truncate(&self.os_version, 30));
        println!("║ CPU      : {:<30}║", truncate(&self.cpu_model, 30));
        println!("║ Cores    : {:<30}║", self.cpu_cores);
        println!(
            "║ RAM      : {:.1} GB{:>24}║",
            self.ram_total_mb as f64 / 1024.0,
            ""
        );
        println!("║ Uptime   : {}d {}h {}m{:>20}║", d, h, m, "");
        println!("╚══════════════════════════════════════════╝");
    }
}

// ---- /proc readers ------------------------------------------------------

fn read_file(path: &str) -> Result<String, ScannerError> {
    std::fs::read_to_string(path).map_err(|e| ScannerError::Io(e))
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

fn read_os_name() -> String {
    // Prefer /etc/os-release over /proc/version
    if let Ok(content) = read_file("/etc/os-release") {
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("PRETTY_NAME=") {
                return val.trim_matches('"').to_string();
            }
            if let Some(val) = line.strip_prefix("NAME=") {
                return val.trim_matches('"').to_string();
            }
        }
    }
    // Fallback
    if let Ok(content) = read_file("/proc/version") {
        return content
            .split_whitespace()
            .take(1)
            .collect::<Vec<_>>()
            .join(" ");
    }
    "Linux".into()
}

fn read_os_version() -> String {
    if let Ok(content) = read_file("/etc/os-release") {
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("VERSION_ID=") {
                return val.trim_matches('"').to_string();
            }
            if let Some(val) = line.strip_prefix("VERSION=") {
                return val.trim_matches('"').to_string();
            }
        }
    }
    // Fallback: kernel version
    if let Ok(content) = read_file("/proc/version") {
        return content
            .split_whitespace()
            .take(3)
            .collect::<Vec<_>>()
            .join(" ");
    }
    "unknown".into()
}

fn read_cpu_model() -> Result<String, ScannerError> {
    let content = read_file("/proc/cpuinfo")?;
    for line in content.lines() {
        if let Some(val) = line.strip_prefix("model name") {
            return Ok(val
                .split(':')
                .nth(1)
                .unwrap_or("unknown")
                .trim()
                .to_string());
        }
    }
    Ok("unknown".into())
}

fn read_cpu_cores() -> Result<u32, ScannerError> {
    let content = read_file("/proc/cpuinfo")?;
    // Count physical cores (cpu cores) prefer over logical processors
    let mut cores = 0u32;
    let mut seen = std::collections::HashSet::new();

    for line in content.lines() {
        if line.starts_with("processor") {
            cores += 1;
        }
        // Also try "cpu cores" field which gives per-socket core count
        if let Some(val) = line.strip_prefix("cpu cores") {
            if let Ok(n) = val.split(':').nth(1).unwrap_or("").trim().parse::<u32>() {
                seen.insert(n);
            }
        }
    }

    // If we found "cpu cores" entries, multiply by socket count (physical id count)
    if !seen.is_empty() {
        let socket_count = content
            .lines()
            .filter(|l| l.starts_with("physical id"))
            .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
            .collect::<std::collections::HashSet<_>>()
            .len() as u32;

        let per_socket = *seen.iter().max().unwrap_or(&0);
        if per_socket > 0 && socket_count > 0 {
            return Ok(per_socket * socket_count);
        }
    }

    Ok(cores)
}

fn read_ram_total() -> Result<u64, ScannerError> {
    let content = read_file("/proc/meminfo")?;
    for line in content.lines() {
        if line.starts_with("MemTotal:") {
            // Format: "MemTotal:       16384000 kB"
            let kb: u64 = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            return Ok(kb / 1024); // kB → MB
        }
    }
    Ok(0)
}

fn read_uptime() -> Result<u64, ScannerError> {
    let content = read_file("/proc/uptime")?;
    let seconds: f64 = content
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);
    Ok(seconds as u64)
}
