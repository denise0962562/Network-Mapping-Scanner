use crate::error::ScannerError;
use crate::scan::ScanObservation;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

const SCHEMA_VERSION: i64 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredIdentity {
    pub(crate) scanner_id: String,
    pub(crate) runtime_token: String,
}

#[derive(Debug)]
pub(crate) struct StoredUpload {
    pub(crate) scanner_id: String,
    pub(crate) task_id: Uuid,
    pub(crate) upload_id: Uuid,
    pub(crate) next_batch_index: u32,
    pub(crate) observations: Vec<ScanObservation>,
}

#[derive(Debug)]
pub(crate) struct StoredRuntimeConfiguration {
    pub(crate) revision: i64,
    pub(crate) schema_version: i32,
    pub(crate) document: Vec<u8>,
}

pub(crate) struct StateStore {
    connection: Connection,
}

impl StateStore {
    pub(crate) fn open(path: PathBuf) -> Result<Self, ScannerError> {
        if let Some(parent) = path.parent().filter(|value| !value.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(ScannerError::Io)?;
        }

        let mut connection = Connection::open(&path)?;
        set_private_permissions(&path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.set_transaction_behavior(TransactionBehavior::Immediate);
        migrate(&mut connection)?;

        tracing::debug!(database_path = %path.display(), "SQLite state database opened");
        Ok(Self { connection })
    }

    pub(crate) fn load_identity(
        &self,
        server_origin: &str,
    ) -> Result<Option<StoredIdentity>, ScannerError> {
        self.connection
            .query_row(
                "SELECT scanner_id, runtime_token
                 FROM scanner_identity
                 WHERE server_origin = ?1",
                [server_origin],
                |row| {
                    Ok(StoredIdentity {
                        scanner_id: row.get(0)?,
                        runtime_token: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(ScannerError::from)
    }

    pub(crate) fn save_identity(
        &self,
        server_origin: &str,
        identity: &StoredIdentity,
    ) -> Result<(), ScannerError> {
        self.connection.execute(
            "INSERT INTO scanner_identity (
                 server_origin, scanner_id, runtime_token, updated_at
             ) VALUES (?1, ?2, ?3, unixepoch())
             ON CONFLICT(server_origin) DO UPDATE SET
                 scanner_id = excluded.scanner_id,
                 runtime_token = excluded.runtime_token,
                 updated_at = excluded.updated_at",
            params![server_origin, identity.scanner_id, identity.runtime_token],
        )?;
        Ok(())
    }

    pub(crate) fn load_runtime_configuration(
        &self,
        server_origin: &str,
    ) -> Result<Option<StoredRuntimeConfiguration>, ScannerError> {
        self.connection
            .query_row(
                "SELECT revision, schema_version, document_json FROM runtime_configuration WHERE server_origin = ?1",
                [server_origin],
                |row| Ok(StoredRuntimeConfiguration {
                    revision: row.get(0)?,
                    schema_version: row.get(1)?,
                    document: row.get(2)?,
                }),
            )
            .optional()
            .map_err(ScannerError::from)
    }

    pub(crate) fn save_runtime_configuration(
        &self,
        server_origin: &str,
        configuration: &crate::runtime_config::RuntimeConfigurationEnvelope,
    ) -> Result<(), ScannerError> {
        let document = serde_json::to_vec(&configuration.document)?;
        self.connection.execute(
            "INSERT INTO runtime_configuration (server_origin, revision, schema_version, document_json, updated_at) \
             VALUES (?1, ?2, ?3, ?4, unixepoch()) ON CONFLICT(server_origin) DO UPDATE SET \
             revision = excluded.revision, schema_version = excluded.schema_version, \
             document_json = excluded.document_json, updated_at = excluded.updated_at",
            params![server_origin, configuration.revision, configuration.schema_version, document],
        )?;
        Ok(())
    }

    pub(crate) fn load_upload(
        &self,
        server_origin: &str,
        scanner_id: &str,
    ) -> Result<Option<StoredUpload>, ScannerError> {
        let header: Option<(String, String, String, i64)> = self
            .connection
            .query_row(
                "SELECT scanner_id, task_id, upload_id, next_batch_index
                 FROM pending_upload
                 WHERE server_origin = ?1",
                [server_origin],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((stored_scanner_id, task_id, upload_id, next_batch_index)) = header else {
            return Ok(None);
        };
        if stored_scanner_id != scanner_id {
            return Err(ScannerError::Config(format!(
                "pending upload for {server_origin} belongs to scanner {stored_scanner_id}, not current scanner {scanner_id}"
            )));
        }

        let task_id = parse_uuid(&task_id, "stored task_id")?;
        let upload_id = parse_uuid(&upload_id, "stored upload_id")?;
        let next_batch_index = u32::try_from(next_batch_index).map_err(|_| {
            ScannerError::Config("stored next_batch_index is outside the u32 range".into())
        })?;
        let mut statement = self.connection.prepare(
            "SELECT payload_json
             FROM observation
             WHERE server_origin = ?1
             ORDER BY sequence ASC",
        )?;
        let rows = statement.query_map([server_origin], |row| row.get::<_, Vec<u8>>(0))?;
        let mut observations = Vec::new();
        for row in rows {
            observations.push(serde_json::from_slice(&row?)?);
        }

        Ok(Some(StoredUpload {
            scanner_id: stored_scanner_id,
            task_id,
            upload_id,
            next_batch_index,
            observations,
        }))
    }

    pub(crate) fn pending_upload_scanner_id(
        &self,
        server_origin: &str,
    ) -> Result<Option<String>, ScannerError> {
        self.connection
            .query_row(
                "SELECT scanner_id
                 FROM pending_upload
                 WHERE server_origin = ?1",
                [server_origin],
                |row| row.get(0),
            )
            .optional()
            .map_err(ScannerError::from)
    }

    pub(crate) fn begin_upload(
        &mut self,
        server_origin: &str,
        scanner_id: &str,
        task_id: Uuid,
        upload_id: Uuid,
        observations: &[ScanObservation],
    ) -> Result<(), ScannerError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO pending_upload (
                 server_origin, scanner_id, task_id, upload_id, next_batch_index, created_at
             ) VALUES (?1, ?2, ?3, ?4, 0, unixepoch())",
            params![
                server_origin,
                scanner_id,
                task_id.to_string(),
                upload_id.to_string()
            ],
        )?;

        {
            let mut statement = transaction.prepare(
                "INSERT OR IGNORE INTO observation (
                     server_origin, sequence, identity, payload_json
                 ) VALUES (?1, ?2, ?3, ?4)",
            )?;
            let mut sequence = 0i64;
            for observation in observations {
                let payload = serde_json::to_vec(observation)?;
                let inserted = statement.execute(params![
                    server_origin,
                    sequence,
                    observation.identity(),
                    payload
                ])?;
                sequence = sequence
                    .checked_add(i64::try_from(inserted).map_err(|_| {
                        ScannerError::Upload("observation sequence exceeded i64".into())
                    })?)
                    .ok_or_else(|| {
                        ScannerError::Upload("observation sequence exceeded i64".into())
                    })?;
            }
        }

        transaction.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn append_observation(
        &self,
        server_origin: &str,
        sequence: usize,
        observation: &ScanObservation,
    ) -> Result<bool, ScannerError> {
        let sequence = i64::try_from(sequence)
            .map_err(|_| ScannerError::Upload("observation sequence exceeded i64".into()))?;
        let payload = serde_json::to_vec(observation)?;
        let inserted = self.connection.execute(
            "INSERT OR IGNORE INTO observation (
                 server_origin, sequence, identity, payload_json
             ) VALUES (?1, ?2, ?3, ?4)",
            params![server_origin, sequence, observation.identity(), payload],
        )?;
        Ok(inserted == 1)
    }

    pub(crate) fn import_upload(
        &mut self,
        server_origin: &str,
        upload: &StoredUpload,
    ) -> Result<(), ScannerError> {
        self.begin_upload(
            server_origin,
            &upload.scanner_id,
            upload.task_id,
            upload.upload_id,
            &upload.observations,
        )?;
        if upload.next_batch_index > 0 {
            self.set_next_batch_index(server_origin, upload.next_batch_index)?;
        }
        Ok(())
    }

    pub(crate) fn set_next_batch_index(
        &self,
        server_origin: &str,
        next_batch_index: u32,
    ) -> Result<(), ScannerError> {
        let updated = self.connection.execute(
            "UPDATE pending_upload
             SET next_batch_index = ?2
             WHERE server_origin = ?1",
            params![server_origin, i64::from(next_batch_index)],
        )?;
        if updated != 1 {
            return Err(ScannerError::Upload(
                "cannot update upload progress without a pending task".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn clear_upload(&mut self, server_origin: &str) -> Result<(), ScannerError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "DELETE FROM pending_upload WHERE server_origin = ?1",
            [server_origin],
        )?;
        transaction.commit()?;
        Ok(())
    }
}

fn migrate(connection: &mut Connection) -> Result<(), ScannerError> {
    let current_version: i64 =
        connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current_version > SCHEMA_VERSION {
        return Err(ScannerError::Config(format!(
            "state database schema version {current_version} is newer than supported version {SCHEMA_VERSION}"
        )));
    }
    if current_version < 1 {
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "CREATE TABLE scanner_identity (
             server_origin TEXT PRIMARY KEY NOT NULL,
             scanner_id TEXT NOT NULL,
             runtime_token TEXT NOT NULL,
             updated_at INTEGER NOT NULL
         );

         CREATE TABLE pending_upload (
             server_origin TEXT PRIMARY KEY NOT NULL,
             scanner_id TEXT NOT NULL,
             task_id TEXT NOT NULL,
             upload_id TEXT NOT NULL,
             next_batch_index INTEGER NOT NULL CHECK(next_batch_index >= 0),
             created_at INTEGER NOT NULL
         );

         CREATE TABLE observation (
             server_origin TEXT NOT NULL,
             sequence INTEGER NOT NULL CHECK(sequence >= 0),
             identity TEXT NOT NULL,
             payload_json BLOB NOT NULL,
             PRIMARY KEY (server_origin, sequence),
             UNIQUE (server_origin, identity),
             FOREIGN KEY (server_origin) REFERENCES pending_upload(server_origin)
                 ON DELETE CASCADE
         );

             PRAGMA user_version = 1;",
        )?;
        transaction.commit()?;
    }
    if current_version < 2 {
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "CREATE TABLE runtime_configuration (
                 server_origin TEXT PRIMARY KEY NOT NULL,
                 revision INTEGER NOT NULL CHECK(revision > 0),
                 schema_version INTEGER NOT NULL CHECK(schema_version > 0),
                 document_json BLOB NOT NULL,
                 updated_at INTEGER NOT NULL
             );
             PRAGMA user_version = 2;",
        )?;
        transaction.commit()?;
    }
    Ok(())
}

fn parse_uuid(value: &str, field: &str) -> Result<Uuid, ScannerError> {
    Uuid::parse_str(value).map_err(|error| {
        ScannerError::Config(format!("invalid {field} in state database: {error}"))
    })
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<(), ScannerError> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)
        .map_err(ScannerError::Io)?
        .permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions).map_err(ScannerError::Io)
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<(), ScannerError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{PortObservation, ScanObservation};

    fn database_path() -> PathBuf {
        std::env::temp_dir().join(format!("scanner-state-{}.sqlite3", Uuid::now_v7()))
    }

    fn observation(port: u16) -> ScanObservation {
        ScanObservation::Port(PortObservation {
            ip: "192.0.2.1".into(),
            port,
            protocol: "tcp".into(),
            state: "open".into(),
            source: "masscan".into(),
            observed_at: 1,
        })
    }

    #[test]
    fn identity_is_scoped_to_server_origin() {
        let path = database_path();
        let store = StateStore::open(path.clone()).unwrap();
        let identity = StoredIdentity {
            scanner_id: Uuid::now_v7().to_string(),
            runtime_token: "secret".into(),
        };
        store
            .save_identity("https://scanner.example:443", &identity)
            .unwrap();

        assert_eq!(
            store.load_identity("https://scanner.example:443").unwrap(),
            Some(identity)
        );
        assert_eq!(
            store.load_identity("https://other.example:443").unwrap(),
            None
        );
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn upload_state_round_trips_in_stable_order() {
        let path = database_path();
        let mut store = StateStore::open(path.clone()).unwrap();
        let task_id = Uuid::now_v7();
        let upload_id = Uuid::now_v7();
        store
            .begin_upload(
                "https://scanner.example:443",
                "019c0000-0000-7000-8000-000000000001",
                task_id,
                upload_id,
                &[observation(443), observation(80), observation(443)],
            )
            .unwrap();
        store
            .set_next_batch_index("https://scanner.example:443", 1)
            .unwrap();

        let restored = store
            .load_upload(
                "https://scanner.example:443",
                "019c0000-0000-7000-8000-000000000001",
            )
            .unwrap()
            .unwrap();
        assert_eq!(restored.task_id, task_id);
        assert_eq!(restored.upload_id, upload_id);
        assert_eq!(restored.next_batch_index, 1);
        assert_eq!(restored.observations.len(), 2);
        assert_eq!(
            restored.observations[0].identity(),
            observation(443).identity()
        );
        assert_eq!(
            restored.observations[1].identity(),
            observation(80).identity()
        );

        store.clear_upload("https://scanner.example:443").unwrap();
        assert!(
            store
                .load_upload(
                    "https://scanner.example:443",
                    "019c0000-0000-7000-8000-000000000001",
                )
                .unwrap()
                .is_none()
        );
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn pending_upload_cannot_move_to_a_different_scanner_identity() {
        let path = database_path();
        let mut store = StateStore::open(path.clone()).unwrap();
        store
            .begin_upload(
                "https://scanner.example:443",
                "019c0000-0000-7000-8000-000000000001",
                Uuid::now_v7(),
                Uuid::now_v7(),
                &[observation(443)],
            )
            .unwrap();
        assert_eq!(
            store
                .pending_upload_scanner_id("https://scanner.example:443")
                .unwrap()
                .as_deref(),
            Some("019c0000-0000-7000-8000-000000000001")
        );

        let error = store
            .load_upload(
                "https://scanner.example:443",
                "019c0000-0000-7000-8000-000000000002",
            )
            .unwrap_err();
        assert!(error.to_string().contains("belongs to scanner"));
        drop(store);
        std::fs::remove_file(path).unwrap();
    }
}
