use super::engines::{masscan, zgrab2};
use crate::error::ScannerError;
use crate::types::{ScanResult, ServiceDetectionConfig, TargetParams};
use std::sync::atomic::AtomicBool;

pub(crate) enum ScanOutcome {
    Completed(Vec<ScanResult>),
    Cancelled,
}

/// Execute the configured scan pipeline.
///
/// Engines own process execution and output parsing. This orchestrator owns
/// stage ordering, cancellation propagation, and stage-level failure policy.
pub(crate) async fn run_scan(
    scanner_path: &str,
    service_detection: &ServiceDetectionConfig,
    target: &TargetParams,
    cancel_requested: &AtomicBool,
) -> Result<ScanOutcome, ScannerError> {
    let mut open_ports = match masscan::run(scanner_path, target, cancel_requested).await? {
        masscan::EngineOutcome::Completed(results) => results,
        masscan::EngineOutcome::Cancelled => return Ok(ScanOutcome::Cancelled),
    };
    if !service_detection.enabled || open_ports.is_empty() {
        return Ok(ScanOutcome::Completed(open_ports));
    }

    match zgrab2::run(
        service_detection,
        &open_ports,
        &target.address_family,
        cancel_requested,
    )
    .await
    {
        Ok(zgrab2::EngineOutcome::Completed(mut enrichment)) => {
            open_ports.append(&mut enrichment);
        }
        Ok(zgrab2::EngineOutcome::Cancelled) => return Ok(ScanOutcome::Cancelled),
        Err(error) if service_detection.required => return Err(error),
        Err(error) => {
            tracing::warn!(%error, "service detection failed; preserving masscan port results");
        }
    }

    Ok(ScanOutcome::Completed(open_ports))
}
