use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RecordType;

use crate::error::ScannerError;
use crate::scan::{DnsAnswer, DnsObservation, DnsQuestion};
use crate::types::{DnsConfig, TargetParams};

pub(crate) async fn run(
    config: &DnsConfig,
    target: &TargetParams,
    cancel_requested: &AtomicBool,
) -> Result<Option<Vec<DnsObservation>>, ScannerError> {
    let resolver = TokioResolver::builder_tokio()
        .map_err(|error| {
            ScannerError::Scan(format!("failed to create DNS system resolver: {error}"))
        })?
        .build();
    let mut observations = Vec::new();
    for domain in target
        .ip
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        for record_type in &config.record_types {
            if cancel_requested.load(Ordering::Relaxed) {
                return Ok(None);
            }
            observations.push(
                query(
                    &resolver,
                    domain,
                    parse_record_type(record_type)?,
                    config.query_timeout_seconds,
                )
                .await,
            );
        }
    }
    Ok(Some(observations))
}

fn parse_record_type(value: &str) -> Result<RecordType, ScannerError> {
    match value.trim().to_ascii_uppercase().as_str() {
        "A" => Ok(RecordType::A),
        "AAAA" => Ok(RecordType::AAAA),
        other => Err(ScannerError::Scan(format!(
            "unsupported configured DNS record type '{other}'"
        ))),
    }
}

async fn query(
    resolver: &TokioResolver,
    domain: &str,
    record_type: RecordType,
    timeout_seconds: u64,
) -> DnsObservation {
    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(timeout_seconds),
        resolver.lookup(domain, record_type),
    )
    .await;
    let elapsed = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);
    let observed_at = chrono::Utc::now().timestamp_millis();
    let (response_code, answers) = match result {
        Ok(Ok(lookup)) => (
            "NOERROR".into(),
            lookup
                .record_iter()
                .map(|record| DnsAnswer {
                    record_type: record.record_type().to_string(),
                    value: record.data().to_string(),
                    ttl: record.ttl(),
                    priority: None,
                    weight: None,
                    port: None,
                })
                .collect(),
        ),
        Ok(Err(error)) => (response_code(&error.to_string()), Vec::new()),
        Err(_) => ("TIMEOUT".into(), Vec::new()),
    };
    DnsObservation {
        observed_at,
        question: DnsQuestion {
            name: domain.into(),
            record_type: record_type.to_string(),
            class: "IN".into(),
        },
        response_code,
        authoritative: false,
        truncated: false,
        dnssec_authenticated: false,
        answers,
        authority: Vec::new(),
        additional: Vec::new(),
        resolver_ip: None,
        resolver_transport: Some("system".into()),
        latency_ms: Some(elapsed),
    }
}

fn response_code(error: &str) -> String {
    let error = error.to_ascii_uppercase();
    if error.contains("NXDOMAIN") || error.contains("NONEXISTENT") {
        "NXDOMAIN".into()
    } else if error.contains("NO RECORDS") {
        "NOERROR".into()
    } else {
        "SERVFAIL".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_initial_record_type_allowlist() {
        assert_eq!(parse_record_type("a").unwrap(), RecordType::A);
        assert_eq!(parse_record_type("AAAA").unwrap(), RecordType::AAAA);
        assert!(parse_record_type("MX").is_err());
    }

    #[test]
    fn error_responses_are_never_reported_as_successful_answers() {
        assert_eq!(response_code("NXDOMAIN"), "NXDOMAIN");
        assert_eq!(response_code("connection failed"), "SERVFAIL");
    }
}
