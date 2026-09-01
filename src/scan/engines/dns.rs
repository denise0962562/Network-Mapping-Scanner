use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
};

use hickory_resolver::proto::{rr::RecordType, xfer::Protocol};
use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig},
};

use crate::error::ScannerError;
use crate::scan::{DnsAnswer, DnsObservation, DnsQuestion};
use crate::types::{DnsConfig, DnsResolver, TargetParams};

pub(crate) struct DnsLookupResult {
    pub(crate) observations: Vec<DnsObservation>,
    pub(crate) resolved_ips: Vec<IpAddr>,
}

pub(crate) async fn run(
    config: &DnsConfig,
    target: &TargetParams,
    resolvers: &[DnsResolver],
    cancel_requested: &AtomicBool,
) -> Result<Option<DnsLookupResult>, ScannerError> {
    let resolver_configs = resolver_configs(resolvers)?;
    let mut observations = Vec::new();
    let mut resolved_ips = BTreeSet::new();
    for domain in target
        .ip
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        for resolver in &resolver_configs {
            for record_type in &config.record_types {
                if cancel_requested.load(Ordering::Relaxed) {
                    return Ok(None);
                }
                let observation = query(
                    &resolver.resolver,
                    domain,
                    parse_record_type(record_type)?,
                    config.query_timeout_seconds,
                    resolver.metadata.as_ref(),
                )
                .await;
                resolved_ips.extend(observation.answers.iter().filter_map(|answer| {
                    matches!(answer.record_type.as_str(), "A" | "AAAA")
                        .then(|| answer.value.parse::<IpAddr>().ok())
                        .flatten()
                }));
                observations.push(observation);
            }
        }
    }
    Ok(Some(DnsLookupResult {
        observations,
        resolved_ips: resolved_ips.into_iter().collect(),
    }))
}

struct ConfiguredResolver {
    resolver: TokioResolver,
    metadata: Option<DnsResolver>,
}

fn resolver_configs(resolvers: &[DnsResolver]) -> Result<Vec<ConfiguredResolver>, ScannerError> {
    if resolvers.is_empty() {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|error| {
                ScannerError::Scan(format!("failed to create DNS system resolver: {error}"))
            })?
            .build();
        return Ok(vec![ConfiguredResolver {
            resolver,
            metadata: None,
        }]);
    }
    resolvers
        .iter()
        .cloned()
        .map(|metadata| {
            let ip = metadata.ip.parse::<IpAddr>().map_err(|error| {
                ScannerError::Scan(format!("invalid DNS resolver {}: {error}", metadata.ip))
            })?;
            let protocol = match metadata.transport.as_str() {
                "udp" => Protocol::Udp,
                "tcp" => Protocol::Tcp,
                other => {
                    return Err(ScannerError::Scan(format!(
                        "unsupported DNS resolver transport '{other}'"
                    )));
                }
            };
            let mut config = ResolverConfig::new();
            config.add_name_server(NameServerConfig::new(
                SocketAddr::new(ip, metadata.port),
                protocol,
            ));
            Ok(ConfiguredResolver {
                resolver: TokioResolver::builder_with_config(config, Default::default()).build(),
                metadata: Some(metadata),
            })
        })
        .collect()
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
    resolver_metadata: Option<&DnsResolver>,
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
        resolver_ip: resolver_metadata.map(|item| item.ip.clone()),
        resolver_id: resolver_metadata
            .map(|item| item.id.clone())
            .or_else(|| Some("system".into())),
        resolver_label: resolver_metadata
            .map(|item| item.label.clone())
            .or_else(|| Some("系统 DNS".into())),
        resolver_port: resolver_metadata.map(|item| item.port),
        resolver_transport: Some(
            resolver_metadata.map_or_else(|| "system".into(), |item| item.transport.clone()),
        ),
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
