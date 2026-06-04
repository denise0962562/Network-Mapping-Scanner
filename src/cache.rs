use crate::error::ScannerError;
use crate::types::{CacheManager, IpEntry, PortInfo, ServiceInfo};
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
}

/// Find an existing (port, protocol) slot or create a new one, then add the service.
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
        // Duplicate Discovered line → skip
        if service.is_none() && banner.is_none() {
            return Ok(());
        }
        return upsert_service(pi, service, banner);
    }

    // New port entry
    let mut pi = PortInfo {
        port,
        protocol: protocol.to_owned(),
        services: Vec::new(),
    };
    upsert_service(&mut pi, service, banner)?;
    entry.ports.push(pi);
    Ok(())
}

/// Fill the first empty placeholder (service == None), or append a new service record.
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
