use super::engines::{dns, masscan, nuclei, zgrab2};
use super::observation::ScanObservation;
use super::plan::{ScanPlan, ScanStageKind};
use crate::error::ScannerError;
use crate::types::{DnsConfig, NucleiConfig, ServiceDetectionConfig, TargetParams};
use std::sync::atomic::AtomicBool;

pub(crate) enum ScanOutcome {
    Completed(Vec<ScanObservation>),
    Cancelled,
}

pub(crate) struct ScanRuntimeConfig<'a> {
    pub(crate) scanner_path: &'a str,
    pub(crate) service_detection: &'a ServiceDetectionConfig,
    pub(crate) dns: &'a DnsConfig,
    pub(crate) nuclei: &'a NucleiConfig,
    pub(crate) dns_resolvers: &'a [crate::types::DnsResolver],
}

/// Execute the configured scan pipeline.
///
/// Engines own process execution and output parsing. This orchestrator owns
/// stage ordering, cancellation propagation, and stage-level failure policy.
pub(crate) async fn run_scan(
    config: ScanRuntimeConfig<'_>,
    plan: &ScanPlan,
    target: &TargetParams,
    cancel_requested: &AtomicBool,
) -> Result<ScanOutcome, ScannerError> {
    plan.validate()?;
    let mut ports = Vec::new();
    let mut services = Vec::new();
    let mut dns_observations = Vec::new();
    let mut vulnerabilities = Vec::new();
    let mut resolved_ips = Vec::new();
    for stage in &plan.stages {
        match stage.kind {
            ScanStageKind::PortDiscovery => {
                let port_target = if matches!(plan.profile.as_str(), "dns_ports" | "dns_full") {
                    if resolved_ips.is_empty() {
                        tracing::info!("DNS task has no A/AAAA answers; skipping port discovery");
                        continue;
                    }
                    TargetParams {
                        ip: resolved_ips
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(","),
                        port: target.port.clone(),
                        rate: target.rate,
                        address_family: target.address_family.clone(),
                    }
                } else {
                    target.clone()
                };
                ports = match masscan::run(config.scanner_path, &port_target, cancel_requested)
                    .await?
                {
                    masscan::EngineOutcome::Completed(results) => results,
                    masscan::EngineOutcome::Cancelled => return Ok(ScanOutcome::Cancelled),
                };
            }
            ScanStageKind::ServiceDetection if ports.is_empty() => {}
            ScanStageKind::ServiceDetection if !config.service_detection.enabled => {
                if plan.profile == "legacy" || !stage.required {
                    tracing::debug!(
                        "legacy service detection stage skipped by local configuration"
                    );
                    continue;
                }
                return Err(ScannerError::Scan(
                    "task requires service_detection but this scanner has it disabled".into(),
                ));
            }
            ScanStageKind::ServiceDetection => {
                let required = if plan.profile == "legacy" {
                    config.service_detection.required
                } else {
                    stage.required
                };
                match zgrab2::run(
                    config.service_detection,
                    &ports,
                    &target.address_family,
                    cancel_requested,
                )
                .await
                {
                    Ok(zgrab2::EngineOutcome::Completed(enrichment)) => services = enrichment,
                    Ok(zgrab2::EngineOutcome::Cancelled) => return Ok(ScanOutcome::Cancelled),
                    Err(error) if required => return Err(error),
                    Err(error) => {
                        tracing::warn!(%error, "optional service detection stage failed; preserving port results");
                    }
                }
            }
            ScanStageKind::DnsLookup if !config.dns.enabled => {
                return Err(ScannerError::Scan(
                    "task requires dns_lookup but this scanner has DNS disabled".into(),
                ));
            }
            ScanStageKind::DnsLookup => {
                match dns::run(config.dns, target, config.dns_resolvers, cancel_requested).await? {
                    Some(results) => {
                        dns_observations = results.observations;
                        resolved_ips = results.resolved_ips;
                    }
                    None => return Ok(ScanOutcome::Cancelled),
                }
            }
            ScanStageKind::VulnerabilityDetection if !config.nuclei.enabled => {
                return Err(ScannerError::Scan(
                    "task requires vulnerability_detection but this scanner has nuclei disabled"
                        .into(),
                ));
            }
            ScanStageKind::VulnerabilityDetection => {
                match nuclei::run(config.nuclei, &ports, &services, cancel_requested).await? {
                    nuclei::EngineOutcome::Completed(results) => vulnerabilities = results,
                    nuclei::EngineOutcome::Cancelled => return Ok(ScanOutcome::Cancelled),
                }
            }
        }
    }
    let mut observations = Vec::with_capacity(
        ports.len() + services.len() + dns_observations.len() + vulnerabilities.len(),
    );
    if plan.profile != "dns_ports" {
        observations.extend(dns_observations.into_iter().map(ScanObservation::Dns));
    }
    observations.extend(ports.into_iter().map(ScanObservation::Port));
    observations.extend(services.into_iter().map(ScanObservation::Service));
    observations.extend(
        vulnerabilities
            .into_iter()
            .map(ScanObservation::Vulnerability),
    );
    Ok(ScanOutcome::Completed(observations))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::plan::{SCAN_PLAN_VERSION, ScanStageSpec};
    use std::sync::atomic::AtomicBool;
    use uuid::Uuid;

    #[cfg(unix)]
    #[tokio::test]
    async fn port_only_plan_never_invokes_service_engine() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "scanner-rs-port-only-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        std::fs::write(&path, "#!/bin/sh\nprintf 'open tcp 443 192.0.2.1 1\\n'\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = TargetParams {
            ip: "192.0.2.1".into(),
            port: "443".into(),
            rate: 100,
            address_family: "ipv4".into(),
        };
        let service = ServiceDetectionConfig {
            enabled: true,
            zgrab_path: "/definitely/not/invoked".into(),
            ..ServiceDetectionConfig::default()
        };
        let plan = ScanPlan {
            version: SCAN_PLAN_VERSION,
            profile: "port_only".into(),
            stages: vec![ScanStageSpec {
                kind: ScanStageKind::PortDiscovery,
                required: true,
            }],
        };

        let outcome = run_scan(
            ScanRuntimeConfig {
                scanner_path: path.to_str().unwrap(),
                service_detection: &service,
                dns: &DnsConfig::default(),
                nuclei: &NucleiConfig::default(),
                dns_resolvers: &[],
            },
            &plan,
            &target,
            &AtomicBool::new(false),
        )
        .await
        .unwrap();
        std::fs::remove_file(path).unwrap();
        let ScanOutcome::Completed(results) = outcome else {
            panic!("port-only scan must complete");
        };
        assert_eq!(results.len(), 1);
        let ScanObservation::Port(port) = &results[0] else {
            panic!("port-only plan must produce a port observation");
        };
        assert_eq!(port.port, 443);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn legacy_plan_preserves_local_required_failure_policy() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "scanner-rs-legacy-required-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        std::fs::write(&path, "#!/bin/sh\nprintf 'open tcp 443 192.0.2.1 1\\n'\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = TargetParams {
            ip: "192.0.2.1".into(),
            port: "443".into(),
            rate: 100,
            address_family: "ipv4".into(),
        };
        let service = ServiceDetectionConfig {
            enabled: true,
            required: true,
            zgrab_path: "/definitely/missing/zgrab2".into(),
            ..ServiceDetectionConfig::default()
        };
        let plan: ScanPlan = serde_json::from_value(serde_json::json!({
            "version": 1,
            "profile": "legacy",
            "stages": [
                {"type": "port_discovery", "required": true},
                {"type": "service_detection", "required": false}
            ]
        }))
        .unwrap();

        let result = run_scan(
            ScanRuntimeConfig {
                scanner_path: path.to_str().unwrap(),
                service_detection: &service,
                dns: &DnsConfig::default(),
                nuclei: &NucleiConfig::default(),
                dns_resolvers: &[],
            },
            &plan,
            &target,
            &AtomicBool::new(false),
        )
        .await;
        std::fs::remove_file(path).unwrap();
        assert!(result.is_err());
    }
}
