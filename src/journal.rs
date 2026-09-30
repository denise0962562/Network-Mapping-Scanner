use crate::{error::ScannerError, scan::ScanObservation, storage::StateStore};

#[derive(Default)]
pub(crate) struct Checkpoint {
    pub(crate) stage: usize,
    pub(crate) chunk: usize,
    pub(crate) elapsed_ms: u64,
    pub(crate) observations: Vec<ScanObservation>,
}

/// One immutable task/configuration snapshot; only completed blocks are reusable.
pub(crate) struct ScanJournal<'a> {
    pub(crate) store: &'a StateStore,
    pub(crate) origin: &'a str,
    pub(crate) key: String,
    pub(crate) state: Checkpoint,
}

impl<'a> ScanJournal<'a> {
    pub(crate) fn open(
        store: &'a StateStore,
        origin: &'a str,
        key: String,
    ) -> Result<Self, ScannerError> {
        let state = store.load_checkpoint(origin, &key)?.unwrap_or_default();
        Ok(Self {
            store,
            origin,
            key,
            state,
        })
    }

    pub(crate) fn save(
        &mut self,
        stage: usize,
        chunk: usize,
        elapsed_ms: u64,
        observations: Option<&[ScanObservation]>,
    ) -> Result<(), ScannerError> {
        self.store.save_checkpoint(
            self.origin,
            &self.key,
            stage,
            chunk,
            elapsed_ms,
            observations,
        )?;
        self.state.stage = stage;
        self.state.chunk = chunk;
        self.state.elapsed_ms = elapsed_ms;
        Ok(())
    }
}
