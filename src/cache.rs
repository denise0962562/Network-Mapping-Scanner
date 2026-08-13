use crate::error::ScannerError;
use crate::types::{
    CacheManager, IpEntry, PortInfo, ScannerResultItem, ScannerResultUpload, ServiceInfo,
};
use std::collections::hash_map::Entry;
use uuid::Uuid;

impl CacheManager {
    pub(crate) fn insert(
        &mut self,
        ip: &str,
        port: u16,
        service: Option<&str>,
        protocol: &str,
        banner: Option<&str>,
        other: Option<&serde_json::Value>,
    ) -> Result<(), ScannerError> {
        match self.ip_table.entry(ip.to_owned()) {
            Entry::Occupied(mut e) => {
                add_or_fill(e.get_mut(), port, service, protocol, banner, other)?;
            }
            Entry::Vacant(e) => {
                let mut entry = IpEntry { ports: Vec::new() };
                add_or_fill(&mut entry, port, service, protocol, banner, other)?;
                e.insert(entry);
            }
        }
        self.total_records += 1;
        Ok(())
    }

    pub(crate) fn begin_task(&mut self, task_id: Uuid) -> Result<(), ScannerError> {
        if self.task_id.is_some() || self.total_records > 0 {
            return Err(ScannerError::Scan(
                "cannot start a new task while results are pending".into(),
            ));
        }
        self.task_id = Some(task_id);
        Ok(())
    }

    pub(crate) fn has_pending_task(&self) -> bool {
        self.task_id.is_some()
    }

    pub(crate) fn upload_payload(
        &self,
        scanner_id: Uuid,
    ) -> Result<ScannerResultUpload, ScannerError> {
        let task_id = self.task_id.ok_or_else(|| {
            ScannerError::Upload("missing task context for cached results".into())
        })?;
        let mut entries = Vec::new();

        for (ip, ip_entry) in &self.ip_table {
            for port_info in &ip_entry.ports {
                for svc in &port_info.services {
                    entries.push(ScannerResultItem {
                        ip: ip.clone(),
                        port: port_info.port,
                        protocol: Some(port_info.protocol.clone()),
                        service: svc.name.clone(),
                        banner: svc.banner.clone(),
                        other: svc.other.clone(),
                    });
                }
            }
        }

        Ok(ScannerResultUpload {
            scanner_id,
            task_id,
            results: entries,
        })
    }
}

// ---- Internal helpers ---------------------------------------------------

fn add_or_fill(
    entry: &mut IpEntry,
    port: u16,
    service: Option<&str>,
    protocol: &str,
    banner: Option<&str>,
    other: Option<&serde_json::Value>,
) -> Result<(), ScannerError> {
    if let Some(pi) = entry
        .ports
        .iter_mut()
        .find(|pi| pi.port == port && pi.protocol == protocol)
    {
        if service.is_none() && banner.is_none() && other.is_none() {
            return Ok(());
        }
        return upsert_service(pi, service, banner, other);
    }

    let mut pi = PortInfo {
        port,
        protocol: protocol.to_owned(),
        services: Vec::new(),
    };
    upsert_service(&mut pi, service, banner, other)?;
    entry.ports.push(pi);
    Ok(())
}

fn upsert_service(
    pi: &mut PortInfo,
    service: Option<&str>,
    banner: Option<&str>,
    other: Option<&serde_json::Value>,
) -> Result<(), ScannerError> {
    if let Some(name) = service
        && let Some(existing) = pi
            .services
            .iter_mut()
            .find(|item| item.name.as_deref() == Some(name))
    {
        if existing.banner.is_none() {
            existing.banner = banner.map(str::to_owned);
        }
        if existing.other.is_none() {
            existing.other = other.cloned();
        }
        return Ok(());
    }

    if let Some(name) = service
        && let Some(empty) = pi.services.iter_mut().find(|s| s.is_placeholder())
    {
        empty.name = Some(name.to_owned());
        if banner.is_some() && empty.banner.is_none() {
            empty.banner = banner.map(str::to_owned);
        }
        if other.is_some() && empty.other.is_none() {
            empty.other = other.cloned();
        }
        return Ok(());
    }

    if service.is_none()
        && let Some(empty) = pi.services.iter_mut().find(|s| s.is_placeholder())
    {
        if empty.banner.is_none() {
            empty.banner = banner.map(str::to_owned);
        }
        if empty.other.is_none() {
            empty.other = other.cloned();
        }
        return Ok(());
    }

    pi.services.push(ServiceInfo {
        name: service.map(str::to_owned),
        banner: banner.map(str::to_owned),
        other: other.cloned(),
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::types::CacheManager;
    use uuid::Uuid;

    fn uuid(value: &str) -> Uuid {
        Uuid::parse_str(value).expect("valid test UUID")
    }

    #[test]
    fn payload_keeps_scanner_and_task_context() {
        let scanner_id = uuid("019c0000-0000-7000-8000-000000000001");
        let task_id = uuid("019c0000-0000-7000-8000-000000000002");
        let mut cache = CacheManager::default();
        cache.begin_task(task_id).expect("task must start");
        cache
            .insert(
                "192.0.2.1",
                443,
                Some("https"),
                "tcp",
                Some("banner"),
                Some(&serde_json::json!({"source": "zgrab2"})),
            )
            .expect("result must be cached");

        let payload = cache
            .upload_payload(scanner_id)
            .expect("payload must be built");

        assert_eq!(payload.scanner_id, scanner_id);
        assert_eq!(payload.task_id, task_id);
        assert_eq!(payload.results.len(), 1);
        assert_eq!(payload.results[0].protocol.as_deref(), Some("tcp"));

        let json = serde_json::to_value(payload).expect("payload must serialize");
        assert_eq!(json["scanner_id"], scanner_id.to_string());
        assert_eq!(json["task_id"], task_id.to_string());
        assert_eq!(json["results"][0]["ip"], "192.0.2.1");
        assert_eq!(json["results"][0]["other"]["source"], "zgrab2");
        assert!(json["results"][0].get("scanner_name").is_none());
        assert!(json["results"][0].get("scan_time").is_none());
    }

    #[test]
    fn pending_task_prevents_result_mixing() {
        let first = uuid("019c0000-0000-7000-8000-000000000001");
        let second = uuid("019c0000-0000-7000-8000-000000000002");
        let mut cache = CacheManager::default();

        cache.begin_task(first).expect("first task must start");

        assert!(cache.begin_task(second).is_err());
    }
}
