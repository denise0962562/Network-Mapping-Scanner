use crate::error::ScannerError;
use crate::types::{CacheManager, IpEntry, PortInfo, ServiceInfo};
use std::collections::hash_map::Entry;

impl CacheManager {
    /// Create a new empty cache manager.
    pub fn new() -> Self {
        Self {
            ip_table: std::collections::HashMap::new(),
            total_records: 0,
        }
    }

    /// Add a scan result to the in-memory cache.
    ///
    /// Deduplicates: if the same (ip, port, protocol) already exists:
    /// - If service is None (Discovered line), skip if an entry already exists.
    /// - If service is Some (Banner line), fill into the first empty ServiceInfo slot
    ///   or append a new one.
    pub fn add_scan_result(
        &mut self,
        ip: &str,
        scanner_name: &str,
        port: u16,
        service: Option<&str>,
        protocol: &str,
        banner: Option<&str>,
    ) -> Result<(), ScannerError> {
        match self.ip_table.entry(ip.to_string()) {
            Entry::Occupied(mut occupied) => {
                add_data_to_entry(occupied.get_mut(), port, service, protocol, banner)?;
            }
            Entry::Vacant(vacant) => {
                let mut entry = IpEntry {
                    ip: ip.to_string(),
                    scanner_name: scanner_name.to_string(),
                    ports: Vec::new(),
                };
                add_data_to_entry(&mut entry, port, service, protocol, banner)?;
                vacant.insert(entry);
            }
        }

        self.total_records += 1;
        Ok(())
    }

    /// Clear all cached data (but keep the manager struct).
    pub fn clear_cache_data(&mut self) {
        self.ip_table.clear();
        self.total_records = 0;
    }
}

/// Add port/service data to an existing IpEntry.
///
/// Logic mirrors the C function `add_data_to_entry`:
/// - If the same (port, protocol) already exists:
///   - If service is None (repeated Discovered): skip
///   - Otherwise: add or fill a ServiceInfo
/// - If not existing: create a new PortInfo slot and add the first ServiceInfo.
fn add_data_to_entry(
    entry: &mut IpEntry,
    port: u16,
    service: Option<&str>,
    protocol: &str,
    banner: Option<&str>,
) -> Result<(), ScannerError> {
    // Look for existing port+protocol match
    for port_info in entry.ports.iter_mut() {
        if port_info.port == port && port_info.protocol == protocol {
            // Repeated Discovered (all None) → skip
            if service.is_none() && banner.is_none() {
                return Ok(());
            }
            return add_service_to_info(port_info, service, banner);
        }
    }

    // New port+protocol — create a new PortInfo
    let mut port_info = PortInfo {
        port,
        protocol: protocol.to_string(),
        services: Vec::new(),
    };

    add_service_to_info(&mut port_info, service, banner)?;
    entry.ports.push(port_info);

    Ok(())
}

/// Add a ServiceInfo to a PortInfo.
///
/// Rules (matching C `add_service_to_info`):
/// - If service is Some and there's an existing ServiceInfo with service==None,
///   fill that placeholder slot.
/// - Otherwise, append a new ServiceInfo.
fn add_service_to_info(
    port_info: &mut PortInfo,
    service: Option<&str>,
    banner: Option<&str>,
) -> Result<(), ScannerError> {
    // If service is provided, try to find and fill an empty placeholder
    if let Some(svc) = service {
        for existing in port_info.services.iter_mut() {
            if existing.service.is_none() {
                existing.service = Some(svc.to_string());
                if banner.is_some() && existing.banner.is_none() {
                    existing.banner = banner.map(|b| b.to_string());
                }
                return Ok(());
            }
        }
    }

    // No placeholder found or service is None — append new entry
    port_info.services.push(ServiceInfo {
        service: service.map(|s| s.to_string()),
        banner: banner.map(|b| b.to_string()),
    });

    Ok(())
}
