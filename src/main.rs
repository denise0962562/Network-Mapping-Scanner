mod cache;
mod config;
mod db;
mod error;
mod health;
mod http_client;
mod logging;
mod scanner;
mod types;

use crate::config::load_config;
use crate::db::{create_conn, insert_batch_data, postgresql_init};
use crate::error::ScannerError;
use crate::health::{check_target, get_target_test};
use crate::http_client::http_requests;
use crate::logging::{init_logging, log_to};
use crate::scanner::run_scan;
use crate::types::{CacheManager, DbConnectInfo};
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::{sleep, Duration};

/// 网络扫描器 — 从 HTTP API 获取目标，调用 masscan 执行端口扫描，结果写入 PostgreSQL。
#[derive(Parser, Debug)]
#[command(name = "scanner-rs", version = "0.1.0", about = "网络端口扫描器")]
struct Cli {
    /// 启用健康检查模式（不发动真实扫描）
    #[arg(short = 'c', long = "health-check")]
    health_check: bool,

    /// 显示帮助信息
    #[arg(short = 'H', short_alias = 'h', long = "help")]
    help_flag: bool,

    /// 启用 DEBUG 模式
    #[arg(short = 'd', long = "debug")]
    debug: bool,

    /// 指定配置文件路径（默认: config.toml）
    #[arg(short = 'f', long = "config", default_value = "config.toml")]
    config_file: String,
}

/// Global stop signal (replaces the C `stop_signal` global variable).
static STOP_SIGNAL: AtomicBool = AtomicBool::new(false);

/// Check if data should be written to the database.
///
/// Matches the C `check_write` function: returns true only when
/// stop_signal is set, meaning data accumulates in cache during
/// normal scanning and is flushed only on shutdown/completion.
fn check_write(_manager: &CacheManager) -> bool {
    STOP_SIGNAL.load(Ordering::Relaxed)
}

#[tokio::main]
async fn main() -> Result<(), ScannerError> {
    let cli = Cli::parse();

    // Handle --help manually (clap handles this, but we match C behavior)
    if cli.help_flag {
        Cli::parse_from(["scanner-rs", "--help"]);
        return Ok(());
    }

    // Initialize logging
    init_logging(cli.debug).map_err(|e| ScannerError::Io(e))?;

    log_to("INFO", "SCANNER-START", "扫描器启动", "main.rs->main");

    // Setup Ctrl+C signal handler
    setup_signal_handler();

    // Health check mode
    if cli.health_check {
        println!("HEALTH CHECKING");

        match get_target_test("http://127.0.0.1:9999/scanner/target").await {
            Ok(()) => {
                log_to("INFO", "HEALTH-CHECK", "健康检查成功", "main.rs->main->health_mode");
                println!("\x1b[32m健康检查通过\x1b[0m");
            }
            Err(e) => {
                log_to("WARN", "HEALTH-CHECK", "健康检查出现错误", "main.rs->main->health_mode");
                eprintln!("\x1b[31m获取目标测试错误: {}\x1b[0m", e);
            }
        }

        return Ok(());
    }

    // Load configuration
    let config = match load_config(&cli.config_file) {
        Ok(cfg) => cfg,
        Err(e) => {
            log_to(
                "ERROR",
                "LOADING-CONFIG-ERROR",
                "加载配置文件错误",
                "main.rs->main->loading_config",
            );
            eprintln!("\x1b[31m加载配置文件出现错误，退出: {}\x1b[0m", e);
            return Err(e);
        }
    };

    // Print config values (matching C output)
    println!("scanner.c_server = {}", config.scanner.c_server);
    println!("scanner.rate = {}", config.scanner.rate);
    println!("email_notify.email = {}", config.email_notify.email);
    println!(
        "database.host = {}\ndatabase.port = {}\ndatabase.db_name = {}",
        config.database.host, config.database.port, config.database.db_name
    );
    println!("\n配置文件通过所有检查\n");

    log_to("INFO", "CONFIG-CHECK", "配置文件检查成功", "main.rs->main");

    println!("启动中");

    // Build database connection info
    let db_info = DbConnectInfo {
        ip: config.database.host.clone(),
        port: config.database.port as u16,
        db_type: 0, // PostgreSQL
        db_name: config.database.db_name.clone(),
        username: config.database.username.clone(),
        password: config.database.password.clone(),
    };

    // Connect to database
    let mut client = match create_conn(&db_info).await {
        Ok(conn) => conn,
        Err(e) => {
            log_to(
                "ERROR",
                "DB-CONNECT-ERROR",
                &format!("连接数据库失败: {}", e),
                "main.rs->main->create_conn",
            );
            eprintln!("\x1b[31m连接数据库失败: {}\x1b[0m", e);
            return Err(e);
        }
    };

    println!("开始初始化数据库");

    if let Err(e) = postgresql_init(&mut client).await {
        log_to(
            "ERROR",
            "DB-INIT-ERROR",
            &format!("初始化数据库失败: {}", e),
            "main.rs->main->postgresql_init",
        );
        eprintln!("\x1b[31m初始化数据库失败: {}\x1b[0m", e);
        return Err(e);
    }

    // Create cache manager
    let mut manager = CacheManager::new();

    // Main scan loop
    if !STOP_SIGNAL.load(Ordering::Relaxed) {
        scan_loop(&mut client, &config.scanner.c_server, &mut manager).await;
        println!("扫描完成");
        log_to(
            "INFO",
            "SCAN-DONE",
            "扫描结束",
            "main.rs->main->stop_signal",
        );
    }

    // Cleanup: flush remaining cache to database
    if manager.total_records > 0 {
        if let Err(e) = insert_batch_data(&mut client, &manager).await {
            log_to(
                "ERROR",
                "WRITE-DATABASE-ERROR",
                &format!("最终写入数据库错误: {}", e),
                "main.rs->main->cleanup",
            );
            eprintln!("\x1b[31m最终写入数据库失败: {}\x1b[0m", e);
        }
        manager.clear_cache_data();
    }

    log_to(
        "INFO",
        "CLEAN-DONE",
        "垃圾清理完毕，退出",
        "main.rs->main->clear",
    );

    println!("垃圾清理完毕");
    Ok(())
}

/// Set up Ctrl+C (SIGINT) signal handler.
fn setup_signal_handler() {
    tokio::spawn(async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                STOP_SIGNAL.store(true, Ordering::Relaxed);
                eprintln!("\n收到停止信号，正在清理资源...");
                log_to(
                    "INFO",
                    "STOP-SIGNAL",
                    "收到停止信号 (SIGINT/SIGTERM)",
                    "main.rs->signal_handler",
                );
            }
            Err(e) => {
                tracing::error!("信号处理错误: {}", e);
            }
        }
    });
}

/// Main scan loop: fetch targets from HTTP API, spawn masscan, parse output,
/// cache results, and periodically write to database.
async fn scan_loop(
    client: &mut tokio_postgres::Client,
    target_server: &str,
    manager: &mut CacheManager,
) {
    let target_url = format!("{}/scanner/target", target_server);
    let mut req_count = 0u32;

    while !STOP_SIGNAL.load(Ordering::Relaxed) {
        // Fetch target from HTTP API
        let http_result = match http_requests(&target_url).await {
            Ok(body) => body,
            Err(e) => {
                tracing::warn!("获取目标失败 (尝试 {}): {}", req_count + 1, e);
                req_count += 1;

                if req_count >= 5 {
                    log_to(
                        "INFO",
                        "MAX-RETRIES",
                        "达到最大重试次数，结束扫描",
                        "main.rs->scan_loop",
                    );
                    break;
                }

                sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        req_count = 0; // Reset retry counter on success

        // Validate and parse target JSON
        let target = match check_target(&http_result, false) {
            Ok(t) => t,
            Err(e) => {
                log_to(
                    "ERROR",
                    "CHECK-TARGET-ERROR",
                    &format!("检查目标出现错误: {}", e),
                    "main.rs->scan_loop->check_target",
                );
                continue;
            }
        };

        // Run masscan scan
        tracing::info!(
            "开始扫描: {}:{} rate={} source-port={}",
            target.ip,
            target.port,
            target.rate,
            target.source_port
        );

        let scan_results = match run_scan(
            &target.ip,
            &target.port,
            target.rate,
            target.source_port,
        )
        .await
        {
            Ok(results) => results,
            Err(e) => {
                log_to(
                    "ERROR",
                    "SCAN-ERROR",
                    &format!("扫描出错: {}", e),
                    "main.rs->scan_loop->run_scan",
                );
                continue;
            }
        };

        // Process scan results: cache them, and write to DB if stop signal received
        for result in &scan_results {
            if check_write(manager) {
                log_to(
                    "INFO",
                    "WRITE",
                    "检查写入条件成功，符合写入条件",
                    "main.rs->scan_loop",
                );

                // Flush cache to database
                if let Err(e) = insert_batch_data(client, manager).await {
                    log_to(
                        "ERROR",
                        "WRITE-DATABASE-ERROR",
                        &format!("写入数据库错误: {}", e),
                        "main.rs->scan_loop->write_to_database",
                    );
                    STOP_SIGNAL.store(true, Ordering::Relaxed);
                    return;
                }
            }

            // Add result to cache
            if let Err(e) = manager.add_scan_result(
                &result.ip,
                "masscan",
                result.port,
                result.service.as_deref(),
                &result.protocol,
                result.banner.as_deref(),
            ) {
                log_to(
                    "ERROR",
                    "ADD-RESULT-TO-CACHE-ERROR",
                    &format!("向缓存添加数据失败: {}", e),
                    "main.rs->scan_loop->add_scan_result_to_cache",
                );
                return;
            }
        }
    }

    // Final flush: write all cached data to DB
    if manager.total_records > 0 {
        if let Err(e) = insert_batch_data(client, manager).await {
            log_to(
                "ERROR",
                "FINAL-WRITE-ERROR",
                &format!("最终写入数据库错误: {}", e),
                "main.rs->scan_loop->final_flush",
            );
        }
        manager.clear_cache_data();
    }
}
