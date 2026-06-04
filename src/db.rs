use crate::error::ScannerError;
use crate::types::{CacheManager, DbConnectInfo};
use tokio_postgres::{Client, NoTls};

const MAX_RETRIES: u32 = 4;
const INITIAL_SLEEP_SECS: u64 = 1;

pub(crate) async fn create_conn(info: &DbConnectInfo) -> Result<Client, ScannerError> {
    let conn_str = info.conn_string();
    let mut sleep_secs = INITIAL_SLEEP_SECS;

    for attempt in 0..MAX_RETRIES {
        match tokio_postgres::connect(&conn_str, NoTls).await {
            Ok((client, connection)) => {
                tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        tracing::error!("database connection lost: {}", e);
                    }
                });
                return Ok(client);
            }
            Err(e) => {
                tracing::warn!(
                    "db connection attempt {}/{} failed: {}",
                    attempt + 1,
                    MAX_RETRIES,
                    e
                );
                if attempt + 1 < MAX_RETRIES {
                    tokio::time::sleep(std::time::Duration::from_secs(sleep_secs)).await;
                    sleep_secs *= 2;
                }
            }
        }
    }

    Err(ScannerError::Database(format!(
        "failed to connect after {} attempts",
        MAX_RETRIES
    )))
}

pub(crate) async fn init_tables(client: &mut Client) -> Result<(), ScannerError> {
    let txn = client.transaction().await.map_err(|e| {
        ScannerError::Database(format!("BEGIN transaction failed: {}", e))
    })?;

    let ddl = [
        // ips
        "CREATE TABLE IF NOT EXISTS ips(
            task_id INT NOT NULL,
            ip_id SERIAL PRIMARY KEY,
            ip_address INET NOT NULL UNIQUE,
            asn TEXT DEFAULT NULL,
            isp TEXT DEFAULT NULL,
            create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,
            update_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT
        );",
        // ports
        "CREATE TABLE IF NOT EXISTS ports(
            ip_id INT NOT NULL,
            port_id SERIAL PRIMARY KEY,
            port INT NOT NULL CHECK (port >= 0 AND port <= 65535),
            create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,
            update_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,
            UNIQUE(ip_id, port),
            CONSTRAINT fk_ip FOREIGN KEY (ip_id) REFERENCES ips(ip_id)
                ON DELETE CASCADE ON UPDATE CASCADE
        );",
        // scaninfo
        "CREATE TABLE IF NOT EXISTS scaninfo(
            port_id INT NOT NULL,
            scan_info_id SERIAL PRIMARY KEY,
            scanner_name TEXT NOT NULL,
            scan_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,
            protocol TEXT DEFAULT NULL,
            service TEXT DEFAULT NULL,
            banner TEXT DEFAULT NULL,
            other JSONB DEFAULT NULL,
            CONSTRAINT fk_port FOREIGN KEY (port_id) REFERENCES ports(port_id)
                ON DELETE CASCADE ON UPDATE CASCADE
        );",
        // scan_task
        "CREATE TABLE IF NOT EXISTS scan_task(
            task_id SERIAL PRIMARY KEY,
            task_initiator VARCHAR(10) NOT NULL,
            task_target INET NOT NULL,
            task_create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,
            task_level INT NOT NULL CHECK (task_level >= 0 AND task_level <= 4),
            task_start_time BIGINT DEFAULT NULL,
            task_end_time BIGINT DEFAULT NULL,
            remarks TEXT DEFAULT NULL
        );",
    ];

    for (i, stmt) in ddl.iter().enumerate() {
        txn.batch_execute(*stmt).await.map_err(|e| {
            ScannerError::Database(format!("DDL statement {} failed: {}", i + 1, e))
        })?;
    }

    txn.commit().await.map_err(|e| {
        ScannerError::Database(format!("COMMIT transaction failed: {}", e))
    })?;

    tracing::info!("database tables initialized");
    Ok(())
}

pub(crate) async fn flush_cache(
    client: &mut Client,
    mgr: &CacheManager,
) -> Result<(), ScannerError> {
    let txn = client.transaction().await.map_err(|e| {
        ScannerError::Database(format!("BEGIN batch transaction failed: {}", e))
    })?;

    for (ip, entry) in &mgr.ip_table {
        let ip_row = txn
            .query_one(
                "INSERT INTO ips (ip_address, task_id) VALUES ($1::inet, $2)
                 ON CONFLICT (ip_address) DO UPDATE SET
                 update_time = (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT
                 RETURNING ip_id",
                &[&ip, &"2"],
            )
            .await
            .map_err(|e| ScannerError::Database(format!("ips insert failed for {}: {}", ip, e)))?;

        let ip_id: i32 = ip_row.get(0);

        for port_info in &entry.ports {
            let port_i32 = port_info.port as i32;
            let port_row = txn
                .query_one(
                    "INSERT INTO ports (ip_id, port) VALUES ($1, $2)
                     ON CONFLICT (ip_id, port) DO UPDATE SET
                     update_time = (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT
                     RETURNING port_id",
                    &[&ip_id, &port_i32],
                )
                .await
                .map_err(|e| {
                    ScannerError::Database(format!(
                        "ports insert failed for {} port {}: {}",
                        ip, port_info.port, e
                    ))
                })?;

            let port_id: i32 = port_row.get(0);

            for svc in &port_info.services {
                txn.execute(
                    "INSERT INTO scaninfo (port_id, scanner_name, protocol, service, banner)
                     VALUES ($1, $2, $3, $4, $5)",
                    &[
                        &port_id,
                        &entry.scanner_name,
                        &port_info.protocol,
                        &svc.name,
                        &svc.banner,
                    ],
                )
                .await
                .map_err(|e| {
                    ScannerError::Database(format!(
                        "scaninfo insert failed for {} port {} svc {:?}: {}",
                        ip, port_info.port, svc.name, e
                    ))
                })?;
            }
        }
    }

    txn.commit().await.map_err(|e| {
        ScannerError::Database(format!("COMMIT batch transaction failed: {}", e))
    })?;

    tracing::info!("batch write complete, {} total records", mgr.total_records);
    Ok(())
}
