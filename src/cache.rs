use crate::error::ScannerError;
use crate::scan::ScanObservation;
use crate::types::{CacheManager, ScannerResultBatchUpload};
#[cfg(test)]
use std::collections::HashSet;
use uuid::Uuid;

pub(crate) const UPLOAD_BATCH_SIZE: usize = 500;
const RESULT_PROTOCOL_VERSION: u16 = 2;

impl CacheManager {
    pub(crate) fn begin_task(&mut self, task_id: Uuid) -> Result<(), ScannerError> {
        if self.task_id.is_some() || !self.observations.is_empty() {
            return Err(ScannerError::Scan(
                "cannot start a new task while results are pending".into(),
            ));
        }
        self.task_id = Some(task_id);
        self.upload_id = Some(Uuid::now_v7());
        self.next_batch_index = 0;
        Ok(())
    }

    pub(crate) fn insert(&mut self, observation: &ScanObservation) -> Result<(), ScannerError> {
        if self.task_id.is_none() || self.upload_id.is_none() {
            return Err(ScannerError::Scan(
                "cannot cache an observation without task context".into(),
            ));
        }
        let identity = observation.identity();
        if !self
            .observations
            .iter()
            .any(|existing| existing.identity() == identity)
        {
            self.observations.push(observation.clone());
        }
        Ok(())
    }

    pub(crate) fn has_pending_task(&self) -> bool {
        self.task_id.is_some()
    }

    pub(crate) fn upload_batches(
        &self,
        scanner_id: Uuid,
    ) -> Result<Vec<ScannerResultBatchUpload>, ScannerError> {
        let task_id = self.task_id.ok_or_else(|| {
            ScannerError::Upload("missing task context for cached results".into())
        })?;
        let upload_id = self.upload_id.ok_or_else(|| {
            ScannerError::Upload("missing upload identity for cached results".into())
        })?;

        if self.observations.is_empty() {
            let batch = ScannerResultBatchUpload {
                protocol_version: RESULT_PROTOCOL_VERSION,
                scanner_id,
                task_id,
                upload_id,
                batch_index: 0,
                is_final: true,
                observations: Vec::new(),
            };
            return Ok(if self.next_batch_index == 0 {
                vec![batch]
            } else {
                Vec::new()
            });
        }

        let chunk_count = self.observations.len().div_ceil(UPLOAD_BATCH_SIZE);
        let batches = self
            .observations
            .chunks(UPLOAD_BATCH_SIZE)
            .enumerate()
            .skip(self.next_batch_index as usize)
            .map(|(index, observations)| ScannerResultBatchUpload {
                protocol_version: RESULT_PROTOCOL_VERSION,
                scanner_id,
                task_id,
                upload_id,
                batch_index: u32::try_from(index).expect("observation batch index fits in u32"),
                is_final: index + 1 == chunk_count,
                observations: observations.to_vec(),
            })
            .collect();
        Ok(batches)
    }

    pub(crate) fn mark_batch_uploaded(&mut self, batch_index: u32) -> Result<(), ScannerError> {
        if batch_index != self.next_batch_index {
            return Err(ScannerError::Upload(format!(
                "cannot acknowledge batch {batch_index}; expected {}",
                self.next_batch_index
            )));
        }
        self.next_batch_index = self.next_batch_index.checked_add(1).ok_or_else(|| {
            ScannerError::Upload("uploaded batch index exceeded protocol limit".into())
        })?;
        Ok(())
    }

    #[cfg(test)]
    fn observation_identities(&self) -> HashSet<String> {
        self.observations
            .iter()
            .map(ScanObservation::identity)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{PortObservation, ServiceObservation};

    fn uuid(value: &str) -> Uuid {
        Uuid::parse_str(value).expect("valid test UUID")
    }

    #[test]
    fn batches_keep_stable_upload_identity_and_final_marker() {
        let scanner_id = uuid("019c0000-0000-7000-8000-000000000001");
        let task_id = uuid("019c0000-0000-7000-8000-000000000002");
        let mut cache = CacheManager::default();
        cache.begin_task(task_id).unwrap();
        cache
            .insert(&ScanObservation::Port(PortObservation {
                ip: "192.0.2.1".into(),
                port: 443,
                protocol: "tcp".into(),
                state: "open",
                source: "masscan",
            }))
            .unwrap();
        cache
            .insert(&ScanObservation::Service(ServiceObservation {
                ip: "192.0.2.1".into(),
                port: 443,
                protocol: "tcp".into(),
                service: Some("https".into()),
                banner: None,
                source: "zgrab2",
                data: None,
            }))
            .unwrap();

        let first = cache.upload_batches(scanner_id).unwrap();
        let retry = cache.upload_batches(scanner_id).unwrap();
        assert_eq!(first.len(), 1);
        assert!(first[0].is_final);
        assert_eq!(first[0].upload_id, retry[0].upload_id);
        assert_eq!(first[0].observations.len(), 2);
        assert_eq!(cache.observation_identities().len(), 2);
        let json = serde_json::to_value(&first[0]).unwrap();
        assert_eq!(json["protocol_version"], 2);
        assert_eq!(json["observations"][0]["kind"], "port");
        assert_eq!(json["observations"][1]["kind"], "service");
    }

    #[test]
    fn empty_task_still_produces_a_final_batch() {
        let mut cache = CacheManager::default();
        cache.begin_task(Uuid::now_v7()).unwrap();
        let batches = cache.upload_batches(Uuid::now_v7()).unwrap();
        assert_eq!(batches.len(), 1);
        assert!(batches[0].is_final);
        assert!(batches[0].observations.is_empty());
    }

    #[test]
    fn large_tasks_are_split_at_the_protocol_limit() {
        let mut cache = CacheManager::default();
        cache.begin_task(Uuid::now_v7()).unwrap();
        for port in 1..=501 {
            cache
                .insert(&ScanObservation::Port(PortObservation {
                    ip: "192.0.2.1".into(),
                    port,
                    protocol: "tcp".into(),
                    state: "open",
                    source: "masscan",
                }))
                .unwrap();
        }
        let batches = cache.upload_batches(Uuid::now_v7()).unwrap();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].observations.len(), UPLOAD_BATCH_SIZE);
        assert!(!batches[0].is_final);
        assert_eq!(batches[1].observations.len(), 1);
        assert!(batches[1].is_final);
        assert_eq!(batches[0].upload_id, batches[1].upload_id);
        cache.mark_batch_uploaded(0).unwrap();
        let remaining = cache.upload_batches(Uuid::now_v7()).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].batch_index, 1);
    }
}
