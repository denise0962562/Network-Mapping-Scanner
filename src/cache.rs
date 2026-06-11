use crate::error::ScannerError;
use crate::types::{CacheManager, IpEntry, PortInfo, ServiceInfo, UploadEntry};
use std::collections::hash_map::Entry;

impl CacheManager {
    pub(crate) fn insert(
        &mut self,
        ip: &str,
        scanner_name: &str,
        port: u16,
        service: Option<&str>,
        protocol: &str,
        banner: Option<&str>,
    ) -> Result<(), ScannerError> {
        match self.ip_table.entry(ip.to_owned()) {
            Entry::Occupied(mut e) => {
                add_or_fill(e.get_mut(), port, service, protocol, banner)?;
            }
            Entry::Vacant(e) => {
                let mut entry = IpEntry {
                    scanner_name: scanner_name.to_owned(),
                    ports: Vec::new(),
                };
                add_or_fill(&mut entry, port, service, protocol, banner)?;
                e.insert(entry);
            }
        }
        self.total_records += 1;
        Ok(())
    }

    /// Flatten the hierarchical cache into a flat `Vec<UploadEntry>`.
    ///
    /// Each (ip, port, service) tuple becomes one independent upload entry
    /// so the server can consume them without understanding the nested structure.
    pub(crate) fn flatten(&self) -> Vec<UploadEntry> {
        let scan_time = chrono::Utc::now().timestamp_millis();
        let mut entries = Vec::new();

        for (ip, ip_entry) in &self.ip_table {
            for port_info in &ip_entry.ports {
                for svc in &port_info.services {
                    entries.push(UploadEntry {
                        ip: ip.clone(),
                        port: port_info.port,
                        protocol: port_info.protocol.clone(),
                        scanner_name: ip_entry.scanner_name.clone(),
                        service: svc.name.clone(),
                        banner: svc.banner.clone(),
                        scan_time,
                    });
                }
            }
        }

        entries
    }
}

// ---- Internal helpers ---------------------------------------------------

fn add_or_fill(
    entry: &mut IpEntry,
    port: u16,
    service: Option<&str>,
    protocol: &str,
    banner: Option<&str>,
) -> Result<(), ScannerError> {
    if let Some(pi) = entry
        .ports
        .iter_mut()
        .find(|pi| pi.port == port && pi.protocol == protocol)
    {
        if service.is_none() && banner.is_none() {
            return Ok(());
        }
        return upsert_service(pi, service, banner);
    }

    let mut pi = PortInfo {
        port,
        protocol: protocol.to_owned(),
        services: Vec::new(),
    };
    upsert_service(&mut pi, service, banner)?;
    entry.ports.push(pi);
    Ok(())
}

fn upsert_service(
    pi: &mut PortInfo,
    service: Option<&str>,
    banner: Option<&str>,
) -> Result<(), ScannerError> {
    if let Some(name) = service {
        if let Some(empty) = pi.services.iter_mut().find(|s| s.is_placeholder()) {
            empty.name = Some(name.to_owned());
            if banner.is_some() && empty.banner.is_none() {
                empty.banner = banner.map(str::to_owned);
            }
            return Ok(());
        }
    }

    pi.services.push(ServiceInfo {
        name: service.map(str::to_owned),
        banner: banner.map(str::to_owned),
    });
    Ok(())
}
