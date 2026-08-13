use crate::error::ScannerError;
use crate::types::ServiceDetectionConfig;

pub(crate) const SCAN_PLAN_VERSION: u16 = 1;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub(crate) struct ScanPlan {
    pub(crate) version: u16,
    pub(crate) profile: String,
    pub(crate) stages: Vec<ScanStageSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub(crate) struct ScanStageSpec {
    #[serde(rename = "type")]
    pub(crate) kind: ScanStageKind,
    pub(crate) required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ScanStageKind {
    PortDiscovery,
    ServiceDetection,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ScanCapabilities {
    pub(crate) plan_versions: Vec<u16>,
    pub(crate) profiles: Vec<&'static str>,
    pub(crate) stages: Vec<&'static str>,
}

impl ScanCapabilities {
    pub(crate) fn from_config(service: &ServiceDetectionConfig) -> Self {
        let mut profiles = vec!["legacy", "port_only"];
        let mut stages = vec!["port_discovery"];
        if service.enabled {
            profiles.push("service_inventory");
            stages.push("service_detection");
        }
        Self {
            plan_versions: vec![SCAN_PLAN_VERSION],
            profiles,
            stages,
        }
    }
}

impl ScanPlan {
    pub(crate) fn legacy(service: &ServiceDetectionConfig) -> Self {
        let mut stages = vec![ScanStageSpec {
            kind: ScanStageKind::PortDiscovery,
            required: true,
        }];
        if service.enabled {
            stages.push(ScanStageSpec {
                kind: ScanStageKind::ServiceDetection,
                required: service.required,
            });
        }
        Self {
            version: SCAN_PLAN_VERSION,
            profile: "legacy".into(),
            stages,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ScannerError> {
        if self.version != SCAN_PLAN_VERSION {
            return Err(ScannerError::Scan(format!(
                "unsupported scan plan version {}; expected {}",
                self.version, SCAN_PLAN_VERSION
            )));
        }
        if !matches!(
            self.profile.as_str(),
            "legacy" | "port_only" | "service_inventory"
        ) {
            return Err(ScannerError::Scan(format!(
                "unsupported scan profile '{}'",
                self.profile
            )));
        }
        if self.stages.is_empty()
            || self.stages[0].kind != ScanStageKind::PortDiscovery
            || self
                .stages
                .iter()
                .filter(|stage| stage.kind == ScanStageKind::PortDiscovery)
                .count()
                != 1
            || self
                .stages
                .iter()
                .filter(|stage| stage.kind == ScanStageKind::ServiceDetection)
                .count()
                > 1
        {
            return Err(ScannerError::Scan(
                "scan plan must start with exactly one port_discovery stage and contain at most one service_detection stage".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_supported_linear_plan() {
        let plan: ScanPlan = serde_json::from_value(serde_json::json!({
            "version": 1,
            "profile": "port_only",
            "stages": [{"type": "port_discovery", "required": true}]
        }))
        .unwrap();
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn rejects_out_of_order_or_future_plans() {
        let mut plan = ScanPlan {
            version: 2,
            profile: "port_only".into(),
            stages: vec![],
        };
        assert!(plan.validate().is_err());
        plan.version = 1;
        assert!(plan.validate().is_err());
    }

    #[test]
    fn capabilities_follow_local_engine_configuration() {
        let ports = ScanCapabilities::from_config(&ServiceDetectionConfig::default());
        assert!(ports.profiles.contains(&"port_only"));
        assert!(!ports.profiles.contains(&"service_inventory"));

        let service = ServiceDetectionConfig {
            enabled: true,
            ..ServiceDetectionConfig::default()
        };
        let inventory = ScanCapabilities::from_config(&service);
        assert!(inventory.profiles.contains(&"service_inventory"));
    }
}
