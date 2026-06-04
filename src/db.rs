use crate::error::ScannerError;
use crate::types::{CacheManager, DbConnectInfo};
use tokio_postgres::{Client, NoTls};

const MAX_RETRY_TIMES: u32 = 4;
const RETRY_SLEEP_TIME_SECS: u64 = 1;

/// Create a database connection using the provided connection info.
///
/// Supports retry with exponential backoff (matching C version's
/// `connect_to_postgresql` with MAX_RETRY_TIMES=4, starting at 1s).
pub async fn create_conn(info: &DbConnectInfo) -> Result<Client, ScannerError> {
    let conn_str = format!(
        "host={} port={} dbname={} user={} password={} client_encoding=UTF8",
        info.ip, info.port, info.db_name, info.username, info.password
    );

    let mut sleep_time = RETRY_SLEEP_TIME_SECS;

    for attempt in 0..MAX_RETRY_TIMES {
        match tokio_postgres::connect(&conn_str, NoTls).await {
            Ok((client, connection)) => {
                // Spawn the connection handler in the background
                tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        tracing::error!("数据库连接出错: {}", e);
                    }
                });
                return Ok(client);
            }
            Err(e) => {
                tracing::warn!(
                    "连接数据库失败 (尝试 {}/{}): {}",
                    attempt + 1,
                    MAX_RETRY_TIMES,
                    e
                );
                if attempt < MAX_RETRY_TIMES - 1 {
                    tokio::time::sleep(std::time::Duration::from_secs(sleep_time)).await;
                    sleep_time *= 2; // Exponential backoff
                }
            }
        }
    }

    Err(ScannerError::Database(format!(
        "超过最大重试次数 ({})，放弃连接数据库",
        MAX_RETRY_TIMES
    )))
}

/// Initialize database tables (CREATE TABLE IF NOT EXISTS).
///
/// All statements run inside a single transaction, matching the C version's
/// `postgresql_init` function. Creates: ips, ports, scaninfo, scan_task tables.
pub async fn postgresql_init(client: &mut Client) -> Result<(), ScannerError> {
    let transaction = client.transaction().await.map_err(|e| {
        ScannerError::Database(format!("开启数据库事务失败: {}", e))
    })?;

    // Create ips table
    transaction
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS ips(
                task_id INT NOT NULL,
                ip_id SERIAL PRIMARY KEY,
                ip_address INET NOT NULL UNIQUE,
                asn TEXT DEFAULT NULL,
                isp TEXT DEFAULT NULL,
                create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,
                update_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT
            );",
        )
        .await
        .map_err(|e| ScannerError::Database(format!("创建 ips 表失败: {}", e)))?;

    // Create ports table
    transaction
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS ports(
                ip_id INT NOT NULL,
                port_id SERIAL PRIMARY KEY,
                port INT NOT NULL CHECK (port >= 0 AND port <= 65535),
                create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,
                update_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,
                UNIQUE(ip_id, port),
                CONSTRAINT fk_ip
                    FOREIGN KEY (ip_id)
                    REFERENCES ips(ip_id)
                    ON DELETE CASCADE
                    ON UPDATE CASCADE
            );",
        )
        .await
        .map_err(|e| ScannerError::Database(format!("创建 ports 表失败: {}", e)))?;

    // Create scaninfo table
    transaction
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS scaninfo(
                port_id INT NOT NULL,
                scan_info_id SERIAL PRIMARY KEY,
                scanner_name TEXT NOT NULL,
                scan_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,
                protocol TEXT DEFAULT NULL,
                service TEXT DEFAULT NULL,
                banner TEXT DEFAULT NULL,
                other JSONB DEFAULT NULL,
                CONSTRAINT fk_port
                    FOREIGN KEY (port_id)
                    REFERENCES ports(port_id)
                    ON DELETE CASCADE
                    ON UPDATE CASCADE
            );",
        )
        .await
        .map_err(|e| ScannerError::Database(format!("创建 scaninfo 表失败: {}", e)))?;

    // Create scan_task table
    transaction
        .batch_execute(
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
        )
        .await
        .map_err(|e| ScannerError::Database(format!("创建 scan_task 表失败: {}", e)))?;

    transaction.commit().await.map_err(|e| {
        ScannerError::Database(format!("提交数据库初始化事务失败: {}", e))
    })?;

    tracing::info!("数据库表初始化完成");
    Ok(())
}

/// Insert all cached scan results into the database in a single batch transaction.
///
/// Uses UPSERT semantics (INSERT ... ON CONFLICT DO UPDATE) matching the C version.
/// All inserts happen within a transaction — if any statement fails, the entire
/// batch is rolled back.
pub async fn insert_batch_data(
    client: &mut Client,
    manager: &CacheManager,
) -> Result<(), ScannerError> {
    let transaction = client.transaction().await.map_err(|e| {
        ScannerError::Database(format!("开启批量写入事务失败: {}", e))
    })?;

    for (ip, entry) in &manager.ip_table {
        // Insert into ips table, get ip_id
        let ip_row = transaction
            .query_one(
                "INSERT INTO ips (ip_address, task_id) VALUES ($1::inet, $2)
                 ON CONFLICT (ip_address) DO UPDATE SET
                 update_time = (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT
                 RETURNING ip_id",
                &[&ip, &"2"],
            )
            .await
            .map_err(|e| ScannerError::Database(format!("插入 ips 表失败 {}: {}", ip, e)))?;

        let ip_id: i32 = ip_row.get(0);

        for port_info in &entry.ports {
            // Insert into ports table, get port_id
            let port_i32 = port_info.port as i32;
            let port_row = transaction
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
                        "插入 ports 表失败 {}:{}: {}",
                        ip, port_info.port, e
                    ))
                })?;

            let port_id: i32 = port_row.get(0);

            for svc in &port_info.services {
                transaction
                    .execute(
                        "INSERT INTO scaninfo (port_id, scanner_name, protocol, service, banner)
                         VALUES ($1, $2, $3, $4, $5)",
                        &[
                            &port_id,
                            &entry.scanner_name,
                            &port_info.protocol,
                            &svc.service,
                            &svc.banner,
                        ],
                    )
                    .await
                    .map_err(|e| {
                        ScannerError::Database(format!(
                            "插入 scaninfo 表失败 {}:{}/{:?}: {}",
                            ip, port_info.port, svc.service, e
                        ))
                    })?;
            }
        }
    }

    transaction.commit().await.map_err(|e| {
        ScannerError::Database(format!("提交批量写入事务失败: {}", e))
    })?;

    tracing::info!("批量写入完成，共处理 {} 条记录", manager.total_records);
    Ok(())
}
