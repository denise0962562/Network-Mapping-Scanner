mod cache;
mod config;
mod error;
mod health;
mod http_client;
mod logging;
mod scanner;
mod types;
mod upload;

use crate::config::load_config;
use crate::error::ScannerError;
use crate::health::{health_check, validate_target};
use crate::http_client::fetch_target;
use crate::logging::{init_logging, LogLevel};
use crate::scanner::run_scan;
use crate::types::CacheManager;
use crate::upload::Uploader;
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

    // ---- load config ----
    let cfg = load_config(&cli.config).inspect_err(|e| {
        log_event!(LogLevel::Error, "CONFIG-LOAD", "failed to load config", "main");
        eprintln!("\x1b[31mconfig error: {}\x1b[0m", e);
    })?;

    let target_url = cfg.scanner.target_url();

    println!("scanner.c_server   = {}", cfg.scanner.c_server);
    println!("scanner.c_port     = {}", cfg.scanner.c_port);
    println!("scanner.rate       = {}", cfg.scanner.rate);
    println!("scanner.verify_tls = {}", cfg.scanner.verify_tls);
    println!("scanner.path       = {}", cfg.scanner.scanner_path);
    println!("upload.endpoint    = {}", cfg.upload.endpoint);
    println!("target URL         = {}", target_url);
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

    // ---- build pipeline components ----
    let uploader = Uploader::new(cfg.upload.endpoint.clone(), cfg.scanner.verify_tls);

    // ---- scan loop ----
    let mut cache = CacheManager::default();

    if !stop_requested() {
        scan_loop(
            &cfg.scanner.scanner_path,
            &target_url,
            cfg.scanner.verify_tls,
            &uploader,
            &mut cache,
        )
        .await;
        println!("scan complete");
        log_event!(LogLevel::Info, "SCAN-DONE", "scan loop finished", "main");
    }

    // ---- final flush ----
    flush(&uploader, &mut cache).await;

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

// ---- pipeline helpers ---------------------------------------------------

/// Flatten the cache, upload via HTTPS POST, then clear.
async fn flush(uploader: &Uploader, cache: &mut CacheManager) {
    if cache.total_records == 0 {
        return;
    }

    let entries = cache.flatten();
    match uploader.upload(&entries).await {
        Ok(()) => {
            log_event!(LogLevel::Info, "UPLOAD", "upload complete", "flush");
            cache.clear();
        }
        Err(e) => {
            // Keep data in cache on failure — it will be retried on next flush
            log_event!(LogLevel::Error, "UPLOAD-ERROR", "upload failed", "flush");
            tracing::error!("upload failed ({} entries kept in cache): {}", entries.len(), e);
        }
    }
}

// ---- scan loop ----------------------------------------------------------

async fn scan_loop(
    scanner_path: &str,
    target_url: &str,
    verify_tls: bool,
    uploader: &Uploader,
    cache: &mut CacheManager,
) {
    let mut failures = 0u32;

    while !stop_requested() {
        // ---- fetch target ----
        let body = match fetch_target(target_url, verify_tls).await {
            Ok(b) => {
                failures = 0;
                b
            }
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

        // ---- validate target ----
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

        // ---- run scan ----
        let results = match run_scan(scanner_path, &target).await {
            Ok(r) => r,
            Err(e) => {
                log_event!(LogLevel::Error, "SCAN-ERROR", "scan failed", "scan_loop");
                tracing::error!("scan error: {}", e);
                continue;
            }
        };

        // ---- cache results ----
        for r in &results {
            if stop_requested() {
                log_event!(LogLevel::Info, "FLUSH", "flushing on stop signal", "scan_loop");
                flush(uploader, cache).await;
                if stop_requested() {
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
    flush(uploader, cache).await;
}
