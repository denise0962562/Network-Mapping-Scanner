use crate::scan::{PortObservation, ServiceObservation};
use crate::types::{ServiceDetectionConfig, ServiceDetectionStrategy};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ProbeKind {
    Ftp,
    Ssh,
    Telnet,
    Smtp,
    Http,
    Pop3,
    Imap,
    Https,
    Smb,
    Tls,
    Mqtt,
    Mysql,
    Rdp,
    Postgres,
    Redis,
    Memcached,
    Mongodb,
    Banner,
}

impl ProbeKind {
    pub(crate) const ALL: [Self; 18] = [
        Self::Banner,
        Self::Tls,
        Self::Http,
        Self::Https,
        Self::Ssh,
        Self::Ftp,
        Self::Telnet,
        Self::Smtp,
        Self::Pop3,
        Self::Imap,
        Self::Redis,
        Self::Mysql,
        Self::Postgres,
        Self::Mongodb,
        Self::Mqtt,
        Self::Smb,
        Self::Rdp,
        Self::Memcached,
    ];

    const ADAPTIVE_FALLBACK: [Self; 14] = [
        Self::Redis,
        Self::Mysql,
        Self::Postgres,
        Self::Mongodb,
        Self::Mqtt,
        Self::Smb,
        Self::Rdp,
        Self::Memcached,
        Self::Ssh,
        Self::Ftp,
        Self::Telnet,
        Self::Smtp,
        Self::Pop3,
        Self::Imap,
    ];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Ftp => "ftp",
            Self::Ssh => "ssh",
            Self::Telnet => "telnet",
            Self::Smtp => "smtp",
            Self::Http => "http",
            Self::Pop3 => "pop3",
            Self::Imap => "imap",
            Self::Https => "https",
            Self::Smb => "smb",
            Self::Tls => "tls",
            Self::Mqtt => "mqtt",
            Self::Mysql => "mysql",
            Self::Rdp => "rdp",
            Self::Postgres => "postgres",
            Self::Redis => "redis",
            Self::Memcached => "memcached",
            Self::Mongodb => "mongodb",
            Self::Banner => "banner",
        }
    }

    pub(crate) fn section(self) -> &'static str {
        match self {
            Self::Https => "http",
            value => value.name(),
        }
    }

    pub(crate) fn default_port(self) -> u16 {
        match self {
            Self::Ftp => 21,
            Self::Ssh => 22,
            Self::Telnet => 23,
            Self::Smtp => 25,
            Self::Http | Self::Banner => 80,
            Self::Pop3 => 110,
            Self::Imap => 143,
            Self::Https | Self::Tls => 443,
            Self::Smb => 445,
            Self::Mqtt => 1883,
            Self::Mysql => 3306,
            Self::Rdp => 3389,
            Self::Postgres => 5432,
            Self::Redis => 6379,
            Self::Memcached => 11211,
            Self::Mongodb => 27017,
        }
    }

    pub(crate) fn extra_config(self) -> &'static str {
        match self {
            Self::Http => "endpoint=\"/\"\nmax-redirects=0\n",
            Self::Https => "use-https=true\nendpoint=\"/\"\nmax-redirects=0\n",
            _ => "",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|probe| probe.name() == name)
    }

    fn service(self) -> Option<&'static str> {
        (self != Self::Banner).then(|| self.name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ProbeAttempt {
    pub(crate) ip: String,
    pub(crate) port: u16,
    pub(crate) probe: ProbeKind,
}

#[derive(Debug, Clone)]
pub(crate) struct ProbeEvidence {
    pub(crate) ip: String,
    pub(crate) port: u16,
    pub(crate) module: String,
    pub(crate) status: String,
    pub(crate) banner: Option<String>,
    pub(crate) detail: Value,
}

#[derive(Debug, Clone)]
struct Candidate {
    service: String,
    score: u8,
    evidence_index: usize,
    reason: &'static str,
}

pub(crate) fn initial_attempts(
    open_ports: &[PortObservation],
    config: &ServiceDetectionConfig,
) -> Vec<ProbeAttempt> {
    let endpoints = unique_tcp_endpoints(open_ports);
    let mut attempts = Vec::new();
    for (ip, port) in endpoints {
        let probes = match config.strategy {
            ServiceDetectionStrategy::Standard => vec![primary_probe(port)],
            ServiceDetectionStrategy::Adaptive => {
                let mut probes = vec![primary_probe(port)];
                for probe in [
                    ProbeKind::Banner,
                    ProbeKind::Tls,
                    ProbeKind::Http,
                    ProbeKind::Https,
                ] {
                    push_unique(&mut probes, probe);
                }
                probes.truncate(config.max_probes_per_endpoint);
                probes
            }
            ServiceDetectionStrategy::Exhaustive => ProbeKind::ALL.to_vec(),
        };
        attempts.extend(probes.into_iter().map(|probe| ProbeAttempt {
            ip: ip.clone(),
            port,
            probe,
        }));
    }
    attempts
}

pub(crate) fn fallback_attempts(
    open_ports: &[PortObservation],
    completed: &[ProbeAttempt],
    evidence: &[ProbeEvidence],
    config: &ServiceDetectionConfig,
) -> Vec<ProbeAttempt> {
    if config.strategy != ServiceDetectionStrategy::Adaptive {
        return Vec::new();
    }

    let confident = confident_endpoints(evidence, config);
    let completed: HashSet<_> = completed.iter().cloned().collect();
    let counts = completed
        .iter()
        .fold(HashMap::new(), |mut counts, attempt| {
            *counts
                .entry((attempt.ip.clone(), attempt.port))
                .or_insert(0usize) += 1;
            counts
        });
    let mut attempts = Vec::new();
    for (ip, port) in unique_tcp_endpoints(open_ports) {
        if confident.contains(&(ip.clone(), port)) {
            continue;
        }
        let mut remaining = config
            .max_probes_per_endpoint
            .saturating_sub(*counts.get(&(ip.clone(), port)).unwrap_or(&0));
        // Banner already covers server-first text protocols well, so spend the
        // bounded fallback budget on binary/client-first protocols first.
        for probe in ProbeKind::ADAPTIVE_FALLBACK {
            if remaining == 0 {
                break;
            }
            let attempt = ProbeAttempt {
                ip: ip.clone(),
                port,
                probe,
            };
            if completed.contains(&attempt) {
                continue;
            }
            attempts.push(attempt);
            remaining -= 1;
        }
    }
    attempts
}

pub(crate) fn aggregate(
    evidence: &[ProbeEvidence],
    config: &ServiceDetectionConfig,
) -> Vec<ServiceObservation> {
    let mut grouped: BTreeMap<(String, u16), Vec<&ProbeEvidence>> = BTreeMap::new();
    for item in evidence {
        grouped
            .entry((item.ip.clone(), item.port))
            .or_default()
            .push(item);
    }

    grouped
        .into_iter()
        .map(|((ip, port), evidence)| {
            let candidates = candidates_for(&evidence, config.strategy);
            let selected = select_candidate(&candidates, config.confidence_threshold);
            let selected_evidence = selected.map(|candidate| evidence[candidate.evidence_index]);
            let banner = selected_evidence
                .and_then(|item| item.banner.clone())
                .or_else(|| {
                    evidence
                        .iter()
                        .find(|item| item.module == ProbeKind::Banner.name())
                        .and_then(|item| item.banner.clone())
                });
            let attempts: Vec<Value> = evidence
                .iter()
                .map(|item| {
                    json!({
                        "module": item.module,
                        "status": item.status,
                        "error": item.detail.pointer("/data/error"),
                    })
                })
                .collect();
            let candidate_details: Vec<Value> = candidates
                .iter()
                .map(|candidate| {
                    json!({
                        "service": candidate.service,
                        "confidence": candidate.score,
                        "reason": candidate.reason,
                    })
                })
                .collect();
            let data = json!({
                "source": "zgrab2",
                "strategy": config.strategy.as_str(),
                "confidence": selected.map(|candidate| candidate.score).unwrap_or(0),
                "selected_probe": selected_evidence.map(|item| item.module.as_str()),
                "attempt_count": evidence.len(),
                "attempts": attempts,
                "candidates": candidate_details,
                "selected_detail": selected_evidence.map(|item| &item.detail),
            });
            ServiceObservation {
                ip,
                port,
                protocol: "tcp".into(),
                service: selected.map(|candidate| candidate.service.clone()),
                banner,
                source: "zgrab2",
                data: Some(data),
            }
        })
        .collect()
}

fn unique_tcp_endpoints(open_ports: &[PortObservation]) -> Vec<(String, u16)> {
    let mut seen = HashSet::new();
    open_ports
        .iter()
        .filter(|item| item.protocol == "tcp")
        .filter(|item| seen.insert((item.ip.clone(), item.port)))
        .map(|item| (item.ip.clone(), item.port))
        .collect()
}

fn push_unique(probes: &mut Vec<ProbeKind>, probe: ProbeKind) {
    if !probes.contains(&probe) {
        probes.push(probe);
    }
}

fn primary_probe(port: u16) -> ProbeKind {
    match port {
        21 => ProbeKind::Ftp,
        22 => ProbeKind::Ssh,
        23 => ProbeKind::Telnet,
        25 | 587 => ProbeKind::Smtp,
        80 | 8000 | 8008 | 8080 | 8081 | 8888 => ProbeKind::Http,
        110 => ProbeKind::Pop3,
        143 => ProbeKind::Imap,
        443 | 4443 | 8443 | 9443 => ProbeKind::Https,
        445 => ProbeKind::Smb,
        465 | 636 | 853 | 989 | 990 | 993 | 995 => ProbeKind::Tls,
        1883 => ProbeKind::Mqtt,
        3306 => ProbeKind::Mysql,
        3389 => ProbeKind::Rdp,
        5432 => ProbeKind::Postgres,
        6379 => ProbeKind::Redis,
        11211 => ProbeKind::Memcached,
        27017 => ProbeKind::Mongodb,
        _ => ProbeKind::Banner,
    }
}

fn confident_endpoints(
    evidence: &[ProbeEvidence],
    config: &ServiceDetectionConfig,
) -> HashSet<(String, u16)> {
    let mut grouped: HashMap<(String, u16), Vec<&ProbeEvidence>> = HashMap::new();
    for item in evidence {
        grouped
            .entry((item.ip.clone(), item.port))
            .or_default()
            .push(item);
    }
    grouped
        .into_iter()
        .filter_map(|(endpoint, evidence)| {
            select_candidate(
                &candidates_for(&evidence, config.strategy),
                config.confidence_threshold,
            )
            .map(|_| endpoint)
        })
        .collect()
}

fn candidates_for(
    evidence: &[&ProbeEvidence],
    strategy: ServiceDetectionStrategy,
) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    for (index, item) in evidence.iter().enumerate() {
        if item.status != "success" {
            continue;
        }
        let probe = ProbeKind::from_name(&item.module);
        if let Some(service) = probe.and_then(ProbeKind::service) {
            let base_score: u8 = if probe == Some(ProbeKind::Tls) {
                85
            } else {
                95
            };
            let score = if probe == Some(primary_probe(item.port)) {
                base_score.saturating_add(3).min(100)
            } else {
                base_score
            };
            candidates.push(Candidate {
                service: service.into(),
                score,
                evidence_index: index,
                reason: "protocol_handshake",
            });
        }
        if strategy != ServiceDetectionStrategy::Standard
            && probe == Some(ProbeKind::Banner)
            && let Some((service, score)) = item.banner.as_deref().and_then(classify_banner)
        {
            candidates.push(Candidate {
                service: service.into(),
                score,
                evidence_index: index,
                reason: "banner_signature",
            });
        }
    }
    candidates.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.service.cmp(&right.service))
    });
    let mut seen_services = HashSet::new();
    candidates.retain(|candidate| seen_services.insert(candidate.service.clone()));
    candidates
}

fn select_candidate(candidates: &[Candidate], threshold: u8) -> Option<&Candidate> {
    let selected = candidates
        .first()
        .filter(|candidate| candidate.score >= threshold)?;
    if candidates.get(1).is_some_and(|runner_up| {
        runner_up.score == selected.score && runner_up.service != selected.service
    }) {
        return None;
    }
    Some(selected)
}

fn classify_banner(banner: &str) -> Option<(&'static str, u8)> {
    let trimmed = banner.trim();
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.starts_with("SSH-") {
        Some(("ssh", 99))
    } else if trimmed.starts_with("HTTP/") {
        Some(("http", 98))
    } else if trimmed.starts_with("220") && lower.contains("smtp") {
        Some(("smtp", 95))
    } else if trimmed.starts_with("220") && lower.contains("ftp") {
        Some(("ftp", 95))
    } else if trimmed.starts_with("+OK") && lower.contains("pop") {
        Some(("pop3", 95))
    } else if trimmed.starts_with("* OK") && lower.contains("imap") {
        Some(("imap", 95))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn port(port: u16) -> PortObservation {
        PortObservation {
            ip: "192.0.2.1".into(),
            port,
            protocol: "tcp".into(),
            state: "open",
            source: "masscan",
        }
    }

    fn evidence(module: &str, port: u16, status: &str, banner: Option<&str>) -> ProbeEvidence {
        ProbeEvidence {
            ip: "192.0.2.1".into(),
            port,
            module: module.into(),
            status: status.into(),
            banner: banner.map(str::to_owned),
            detail: json!({"data": {"status": status}}),
        }
    }

    #[test]
    fn standard_strategy_keeps_single_port_mapped_probe() {
        let attempts =
            initial_attempts(&[port(22), port(9000)], &ServiceDetectionConfig::default());
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0].probe, ProbeKind::Ssh);
        assert_eq!(attempts[1].probe, ProbeKind::Banner);
    }

    #[test]
    fn adaptive_strategy_schedules_bounded_initial_and_fallback_probes() {
        let config = ServiceDetectionConfig {
            strategy: ServiceDetectionStrategy::Adaptive,
            max_probes_per_endpoint: 7,
            ..ServiceDetectionConfig::default()
        };
        let initial = initial_attempts(&[port(9000)], &config);
        assert_eq!(initial.len(), 4);
        let fallback = fallback_attempts(&[port(9000)], &initial, &[], &config);
        assert_eq!(fallback.len(), 3);
        assert!(fallback.iter().all(|attempt| !initial.contains(attempt)));
        assert_eq!(fallback[0].probe, ProbeKind::Redis);
        assert_eq!(fallback[1].probe, ProbeKind::Mysql);
    }

    #[test]
    fn banner_signature_identifies_ssh_on_nonstandard_port() {
        let config = ServiceDetectionConfig {
            strategy: ServiceDetectionStrategy::Adaptive,
            ..ServiceDetectionConfig::default()
        };
        let results = aggregate(
            &[evidence(
                "banner",
                2222,
                "success",
                Some("SSH-2.0-OpenSSH_9.6"),
            )],
            &config,
        );
        assert_eq!(results[0].service.as_deref(), Some("ssh"));
        assert_eq!(results[0].data.as_ref().unwrap()["confidence"], 99);
    }

    #[test]
    fn application_protocol_wins_over_tls_wrapper() {
        let config = ServiceDetectionConfig {
            strategy: ServiceDetectionStrategy::Adaptive,
            ..ServiceDetectionConfig::default()
        };
        let results = aggregate(
            &[
                evidence("tls", 10443, "success", None),
                evidence("https", 10443, "success", Some("HTTP/1.1 200 OK")),
            ],
            &config,
        );
        assert_eq!(results[0].service.as_deref(), Some("https"));
    }

    #[test]
    fn failed_probes_are_aggregated_without_claiming_a_service() {
        let config = ServiceDetectionConfig {
            strategy: ServiceDetectionStrategy::Adaptive,
            ..ServiceDetectionConfig::default()
        };
        let results = aggregate(
            &[
                evidence("http", 9000, "protocol-error", None),
                evidence("tls", 9000, "connection-timeout", None),
            ],
            &config,
        );
        assert!(results[0].service.is_none());
        assert_eq!(results[0].data.as_ref().unwrap()["attempt_count"], 2);
    }

    #[test]
    fn equal_strength_conflicting_handshakes_remain_unidentified() {
        let config = ServiceDetectionConfig {
            strategy: ServiceDetectionStrategy::Adaptive,
            ..ServiceDetectionConfig::default()
        };
        let results = aggregate(
            &[
                evidence("http", 9000, "success", Some("HTTP/1.1 200 OK")),
                evidence("mysql", 9000, "success", None),
            ],
            &config,
        );
        assert!(results[0].service.is_none());
        assert_eq!(results[0].data.as_ref().unwrap()["confidence"], 0);
        assert_eq!(
            results[0].data.as_ref().unwrap()["candidates"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn duplicate_evidence_for_one_service_keeps_the_strongest_candidate() {
        let config = ServiceDetectionConfig {
            strategy: ServiceDetectionStrategy::Adaptive,
            ..ServiceDetectionConfig::default()
        };
        let results = aggregate(
            &[
                evidence("banner", 2222, "success", Some("SSH-2.0-OpenSSH_9.6")),
                evidence("ssh", 2222, "success", Some("SSH-2.0-OpenSSH_9.6")),
            ],
            &config,
        );
        assert_eq!(results[0].service.as_deref(), Some("ssh"));
        assert_eq!(results[0].data.as_ref().unwrap()["confidence"], 99);
        assert_eq!(
            results[0].data.as_ref().unwrap()["candidates"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn confident_first_round_result_skips_fallback() {
        let config = ServiceDetectionConfig {
            strategy: ServiceDetectionStrategy::Adaptive,
            max_probes_per_endpoint: 8,
            ..ServiceDetectionConfig::default()
        };
        let ports = [port(2222)];
        let initial = initial_attempts(&ports, &config);
        let evidence = [evidence(
            "banner",
            2222,
            "success",
            Some("SSH-2.0-OpenSSH_9.6"),
        )];
        assert!(fallback_attempts(&ports, &initial, &evidence, &config).is_empty());
    }

    #[test]
    fn exhaustive_strategy_schedules_every_probe_once() {
        let config = ServiceDetectionConfig {
            strategy: ServiceDetectionStrategy::Exhaustive,
            max_probes_per_endpoint: 1,
            ..ServiceDetectionConfig::default()
        };
        let attempts = initial_attempts(&[port(9000), port(9000)], &config);
        assert_eq!(attempts.len(), ProbeKind::ALL.len());
        assert_eq!(
            attempts
                .iter()
                .map(|attempt| attempt.probe)
                .collect::<HashSet<_>>()
                .len(),
            ProbeKind::ALL.len()
        );
    }
}
