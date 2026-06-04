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
use crate::db::{create_conn, flush_cache, init_tables};
use crate::error::ScannerError;
use crate::health::{health_check, validate_target};
use crate::http_client::fetch_target;
use crate::logging::{init_logging, LogLevel};
use crate::scanner::run_scan;
use crate::types::{CacheManager, DbConnectInfo};
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::{sleep, Duration};

// ---- CLI ----------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "scanner-rs", version, about = "Network port scanner orchestrator")]
struct Cli {
    /// Run health-check only (no scanning)
    #[arg(short = 'c', long)]
    health_check: bool,

    /// Enable debug output
    #[arg(short = 'd', long)]
    debug: bool,

    /// Path to config file (default: config.toml)
    #[arg(short = 'f', long, default_value = "config.toml")]
    config: String,
}

// ---- globals ------------------------------------------------------------

static STOP: AtomicBool = AtomicBool::new(false);

fn stop_requested() -> bool {
    STOP.load(Ordering::Relaxed)
}

fn request_stop() {
    STOP.store(true, Ordering::Relaxed);
}

// ---- entry point --------------------------------------------------------

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("\x1b[31mfatal: {}\x1b[0m", e);
        std::process::exit(1);
    }
}

async fn run() -> Result<(), ScannerError> {
    let cli = Cli::parse();

    init_logging(cli.debug)?;

    log_event!(LogLevel::Info, "SCANNER-START", "scanner started", "main");

    spawn_signal_handler();

    // ---- load config (needed by both health-check and scan) ----
    let cfg = load_config(&cli.config).inspect_err(|e| {
        log_event!(LogLevel::Error, "CONFIG-LOAD", "failed to load config", "main");
        eprintln!("\x1b[31mconfig error: {}\x1b[0m", e);
    })?;

    let target_url = cfg.scanner.target_url();

    println!("scanner.c_server = {}", cfg.scanner.c_server);
    println!("scanner.c_port = {}", cfg.scanner.c_port);
    println!("scanner.rate = {}", cfg.scanner.rate);
    println!("scanner.verify_tls = {}", cfg.scanner.verify_tls);
    println!("target URL = {}", target_url);
    println!("email_notify.email = {}", cfg.email_notify.email);
    println!(
        "database.host = {}\ndatabase.port = {}\ndatabase.db_name = {}",
        cfg.database.host, cfg.database.port, cfg.database.db_name
    );
    println!("\nconfig validated\n");

    log_event!(LogLevel::Info, "CONFIG-OK", "config validated", "main");

    // ---- health-check mode ----
    if cli.health_check {
        println!("HEALTH CHECKING");
        match health_check(&target_url, cfg.scanner.verify_tls).await {
            Ok(()) => {
                log_event!(LogLevel::Info, "HEALTH-CHECK", "health check passed", "main");
                println!("\x1b[32mhealth check passed\x1b[0m");
            }
            Err(e) => {
                log_event!(LogLevel::Warn, "HEALTH-CHECK", "health check failed", "main");
                eprintln!("\x1b[31mhealth check error: {}\x1b[0m", e);
            }
        }
        return Ok(());
    }
    println!("starting...");

    // ---- database ----
    let db_info = DbConnectInfo::from(&cfg.database);

    let mut client = create_conn(&db_info).await.inspect_err(|e| {
        log_event!(LogLevel::Error, "DB-CONNECT", "db connection failed", "main");
        eprintln!("\x1b[31mdb connect error: {}\x1b[0m", e);
    })?;

    println!("initializing database...");
    init_tables(&mut client).await.inspect_err(|e| {
        log_event!(LogLevel::Error, "DB-INIT", "db init failed", "main");
        eprintln!("\x1b[31mdb init error: {}\x1b[0m", e);
    })?;

    // ---- scan loop ----
    let mut cache = CacheManager::default();

    if !stop_requested() {
        scan_loop(&mut client, &target_url, cfg.scanner.verify_tls, &mut cache).await;
        println!("scan complete");
        log_event!(LogLevel::Info, "SCAN-DONE", "scan loop finished", "main");
    }

    // ---- final flush ----
    if cache.total_records > 0 {
        if let Err(e) = flush_cache(&mut client, &cache).await {
            log_event!(LogLevel::Error, "FINAL-FLUSH", "final flush failed", "main");
            eprintln!("\x1b[31mflush error: {}\x1b[0m", e);
        }
        cache.clear();
    }

    log_event!(LogLevel::Info, "CLEANUP", "shutdown complete", "main");
    println!("shutdown complete");
    Ok(())
}

// ---- signal handler -----------------------------------------------------

fn spawn_signal_handler() {
    tokio::spawn(async {
        if tokio::signal::ctrl_c().await.is_ok() {
            request_stop();
            eprintln!("\nSIGINT received, shutting down gracefully...");
            log_event!(LogLevel::Info, "SIGNAL", "SIGINT received", "main");
        }
    });
}

// ---- scan loop ----------------------------------------------------------

async fn scan_loop(
    client: &mut tokio_postgres::Client,
    target_url: &str,
    verify_tls: bool,
    cache: &mut CacheManager,
) {
    let mut failures = 0u32;

    while !stop_requested() {
        // Fetch target
        let body = match fetch_target(target_url, verify_tls).await {
            Ok(b) => b,
            Err(e) => {
                failures += 1;
                tracing::warn!("fetch target failed ({}/5): {}", failures, e);
                if failures >= 5 {
                    log_event!(LogLevel::Info, "MAX-RETRIES", "max fetch retries reached", "scan_loop");
                    break;
                }
                sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        failures = 0;

        // Validate
        let target = match validate_target(&body, false) {
            Ok(t) => t,
            Err(e) => {
                log_event!(LogLevel::Error, "TARGET-PARSE", "target parse error", "scan_loop");
                tracing::error!("target validation failed: {}", e);
                continue;
            }
        };

        tracing::info!(
            "scanning {}:{} rate={} sport={}",
            target.ip, target.port, target.rate, target.source_port
        );

        // Run masscan
        let results = match run_scan(&target.ip, &target.port, target.rate, target.source_port).await {
            Ok(r) => r,
            Err(e) => {
                log_event!(LogLevel::Error, "SCAN-ERROR", "scan failed", "scan_loop");
                tracing::error!("scan error: {}", e);
                continue;
            }
        };

        // Cache results
        for r in &results {
            // On stop signal, flush first
            if stop_requested() {
                log_event!(LogLevel::Info, "FLUSH", "flushing on stop signal", "scan_loop");
                if let Err(e) = flush_cache(client, cache).await {
                    log_event!(LogLevel::Error, "FLUSH-ERROR", "flush failed", "scan_loop");
                    tracing::error!("flush error: {}", e);
                    request_stop();
                    return;
                }
            }

            if let Err(e) = cache.insert(
                &r.ip, "masscan", r.port,
                r.service.as_deref(), &r.protocol, r.banner.as_deref(),
            ) {
                log_event!(LogLevel::Error, "CACHE-ERROR", "cache insert failed", "scan_loop");
                tracing::error!("cache error: {}", e);
                return;
            }
        }
    }

    // Final flush
    if cache.total_records > 0 {
        if let Err(e) = flush_cache(client, cache).await {
            log_event!(LogLevel::Error, "FINAL-FLUSH", "flush failed", "scan_loop");
            tracing::error!("final flush error: {}", e);
        }
        cache.clear();
    }
}
