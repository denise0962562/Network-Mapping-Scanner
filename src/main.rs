mod cache;
mod config;
mod error;
mod health;
mod heartbeat;
mod http_client;
mod logging;
mod register;
mod scanner;
mod sysinfo;
mod types;
mod upload;

use crate::config::load;
use crate::error::ScannerError;
use crate::health::health_check;
use crate::heartbeat::{ActiveTask, HeartbeatClient};
use crate::http_client::{FetchTaskOutcome, fetch_task};
use crate::logging::{LogLevel, init_logging};
use crate::scanner::{ScanOutcome, run_scan};
use crate::sysinfo::SystemInfo;
use crate::types::{CacheManager, TargetParams};
use crate::upload::Uploader;
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::{Duration, sleep};
use uuid::Uuid;

// ---- CLI ----------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "scanner-rs",
    version,
    about = "Network port scanner orchestrator"
)]
struct Cli {
    /// Run health-check only (no scanning)
    #[arg(short = 'c', long)]
    health_check: bool,

    /// Enable debug output
    #[arg(short = 'd', long)]
    debug: bool,

    /// Print system information and exit
    #[arg(short = 'i', long)]
    get_system_info: bool,

    /// Scanner identity (UUIDv7)
    #[arg(long)]
    id: Option<String>,

    /// Registration token from server
    #[arg(long)]
    token: Option<String>,

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

    // ---- system info ----
    match SystemInfo::gather() {
        Ok(info) => info.print(),
        Err(e) => tracing::warn!("failed to gather system info: {}", e),
    }

    if cli.get_system_info {
        return Ok(());
    }

    // ---- load config ----
    let mut loaded = load(&cli.config).inspect_err(|e| {
        log_event!(
            LogLevel::Error,
            "CONFIG-LOAD",
            "failed to load config",
            "main"
        );
        eprintln!("\x1b[31mconfig error: {}\x1b[0m", e);
    })?;

    // ---- handle --id / --token ----
    let identity_changed = handle_identity(&cli, &mut loaded).await?;

    if identity_changed {
        // Identity was updated — save back to config preserving comments.
        loaded.save_scanner_identity()?;
        println!("\x1b[32mconfig updated\x1b[0m");
        // When --id/--token are explicitly passed, registration is the goal; exit.
        if cli.id.is_some() || cli.token.is_some() {
            return Ok(());
        }
    }

    let cfg = &loaded.app;
    let task_url = cfg.scanner.task_url(false);

    println!("scanner.c_server   = {}", cfg.scanner.c_server);
    println!("scanner.c_port     = {}", cfg.scanner.c_port);
    println!("scanner.rate       = {}", cfg.scanner.rate);
    println!("scanner.source_port = {}", cfg.scanner.source_port);
    println!("scanner.verify_tls = {}", cfg.scanner.verify_tls);
    println!("scanner.path       = {}", cfg.scanner.scanner_path);
    println!("scanner.id         = {}", cfg.scanner.scanner_id);
    println!(
        "scanner.runtime_token = {}",
        if cfg.scanner.runtime_token.is_empty() {
            "(not set)"
        } else {
            "****"
        }
    );
    println!("upload.endpoint    = {}", cfg.upload.endpoint);
    println!(
        "heartbeat.interval = {}s",
        cfg.scanner.heartbeat_interval_seconds
    );
    println!("task URL           = {}", task_url);
    println!("\nconfig validated\n");

    log_event!(LogLevel::Info, "CONFIG-OK", "config validated", "main");

    // ---- health-check mode ----
    if cli.health_check {
        if cfg.scanner.runtime_token.is_empty() {
            return Err(ScannerError::Config(
                "scanner.runtime_token is required; register the scanner first".into(),
            ));
        }
        println!("HEALTH CHECKING");
        match health_check(
            &cfg.scanner.task_url(true),
            cfg.scanner.verify_tls,
            &cfg.scanner.runtime_token,
        )
        .await
        {
            Ok(()) => {
                log_event!(
                    LogLevel::Info,
                    "HEALTH-CHECK",
                    "health check passed",
                    "main"
                );
                println!("\x1b[32mhealth check passed\x1b[0m");
            }
            Err(e) => {
                log_event!(
                    LogLevel::Warn,
                    "HEALTH-CHECK",
                    "health check failed",
                    "main"
                );
                eprintln!("\x1b[31mhealth check error: {}\x1b[0m", e);
            }
        }
        return Ok(());
    }

    println!("starting...");

    if cfg.scanner.runtime_token.is_empty() {
        return Err(ScannerError::Config(
            "scanner.runtime_token is required; register the scanner first".into(),
        ));
    }
    let scanner_id = Uuid::parse_str(&cfg.scanner.scanner_id)
        .map_err(|error| ScannerError::Config(format!("invalid scanner.scanner_id: {error}")))?;

    let uploader = Uploader::new(
        cfg.upload.endpoint.clone(),
        cfg.scanner.verify_tls,
        cfg.scanner.runtime_token.clone(),
    );
    let heartbeat_client = HeartbeatClient::new(
        cfg.scanner.heartbeat_url(),
        cfg.scanner.task_failure_url(),
        cfg.scanner.task_cancelled_url(),
        cfg.scanner.verify_tls,
        cfg.scanner.runtime_token.clone(),
        scanner_id,
    )?;
    let active_task = ActiveTask::default();
    let heartbeat_handle = spawn_heartbeat(
        heartbeat_client.clone(),
        active_task.clone(),
        cfg.scanner.heartbeat_interval_seconds,
    );
    let mut cache = CacheManager::default();

    if !stop_requested() {
        scan_loop(
            ScanLoopConfig {
                scanner_path: &cfg.scanner.scanner_path,
                task_url: &task_url,
                verify_tls: cfg.scanner.verify_tls,
                runtime_token: &cfg.scanner.runtime_token,
                scanner_id,
                rate: cfg.scanner.rate as i32,
                source_port: cfg.scanner.source_port,
            },
            &uploader,
            &heartbeat_client,
            &active_task,
            &mut cache,
        )
        .await;
        println!("scan complete");
        log_event!(LogLevel::Info, "SCAN-DONE", "scan loop finished", "main");
    }

    match flush(&uploader, scanner_id, &mut cache).await {
        Ok(()) => active_task.clear().await,
        Err(error) => tracing::error!("final result upload failed: {}", error),
    }
    if let Err(error) = heartbeat_client.send(active_task.get().await, true).await {
        tracing::warn!("final heartbeat failed: {}", error);
    }
    heartbeat_handle.abort();

    log_event!(LogLevel::Info, "CLEANUP", "shutdown complete", "main");
    println!("shutdown complete");
    Ok(())
}

// ---- identity management ------------------------------------------------

/// Returns `true` if any config field was changed.
async fn handle_identity(
    cli: &Cli,
    loaded: &mut config::LoadedConfig,
) -> Result<bool, ScannerError> {
    let id_provided = cli.id.is_some();
    let token_provided = cli.token.is_some();

    if !id_provided && !token_provided {
        return Ok(false);
    }

    if !id_provided || !token_provided {
        return Err(ScannerError::Config(
            "--id and --token must be provided together for registration".into(),
        ));
    }

    let scanner_id = cli.id.as_deref().expect("checked above");
    let registration_token = cli.token.as_deref().expect("checked above");
    match register::register(
        &loaded.app.scanner.c_server,
        loaded.app.scanner.c_port,
        loaded.app.scanner.verify_tls,
        scanner_id,
        registration_token,
    )
    .await?
    {
        register::RegisterOutcome::Registered { runtime_token } => {
            loaded.app.scanner.scanner_id = scanner_id.to_owned();
            loaded.app.scanner.runtime_token = runtime_token;
            println!("\x1b[32mregistration successful\x1b[0m");
            log_event!(LogLevel::Info, "REGISTER", "registration accepted", "main");
            Ok(true)
        }
        register::RegisterOutcome::Unauthorized => Err(ScannerError::Http(
            "registration rejected: invalid or expired credentials".into(),
        )),
    }
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

fn spawn_heartbeat(
    client: HeartbeatClient,
    active_task: ActiveTask,
    interval_seconds: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match client.send(active_task.get().await, false).await {
                Ok(response) => client.apply_command(response, &active_task).await,
                Err(error) => {
                    tracing::warn!("heartbeat failed: {}", error);
                    if error.to_string().contains("401 Unauthorized") {
                        request_stop();
                        tracing::error!("runtime token rejected by heartbeat endpoint; stopping");
                        break;
                    }
                }
            }
            sleep(Duration::from_secs(interval_seconds)).await;
        }
    })
}

// ---- pipeline helpers ---------------------------------------------------

async fn flush(
    uploader: &Uploader,
    scanner_id: Uuid,
    cache: &mut CacheManager,
) -> Result<(), ScannerError> {
    if !cache.has_pending_task() {
        return Ok(());
    }

    let payload = cache.upload_payload(scanner_id)?;
    uploader.upload(&payload).await?;
    log_event!(LogLevel::Info, "UPLOAD", "upload complete", "flush");
    cache.clear();
    Ok(())
}

// ---- scan loop ----------------------------------------------------------

struct ScanLoopConfig<'a> {
    scanner_path: &'a str,
    task_url: &'a str,
    verify_tls: bool,
    runtime_token: &'a str,
    scanner_id: Uuid,
    rate: i32,
    source_port: i32,
}

async fn scan_loop(
    config: ScanLoopConfig<'_>,
    uploader: &Uploader,
    heartbeat_client: &HeartbeatClient,
    active_task: &ActiveTask,
    cache: &mut CacheManager,
) {
    let mut failures = 0u32;

    while !stop_requested() {
        if cache.has_pending_task() {
            if let Err(error) = flush(uploader, config.scanner_id, cache).await {
                log_event!(
                    LogLevel::Error,
                    "UPLOAD-ERROR",
                    "upload failed",
                    "scan_loop"
                );
                tracing::error!("upload failed; cached task retained: {}", error);
                sleep(Duration::from_secs(5)).await;
                continue;
            }
            active_task.clear().await;
        }

        let assigned_task =
            match fetch_task(config.task_url, config.verify_tls, config.runtime_token).await {
                Ok(FetchTaskOutcome::Task(task)) => {
                    failures = 0;
                    task
                }
                Ok(FetchTaskOutcome::NoTask) => {
                    failures = 0;
                    tracing::debug!("no scan task available");
                    sleep(Duration::from_secs(5)).await;
                    continue;
                }
                Ok(FetchTaskOutcome::Unauthorized { detail }) => {
                    log_event!(
                        LogLevel::Error,
                        "AUTH",
                        "runtime token rejected",
                        "scan_loop"
                    );
                    tracing::error!(
                        "runtime token rejected; register the scanner again: {}",
                        detail
                    );
                    break;
                }
                Ok(FetchTaskOutcome::Forbidden { detail }) => {
                    log_event!(
                        LogLevel::Error,
                        "SERVER-POLICY",
                        "task request forbidden",
                        "scan_loop"
                    );
                    tracing::error!(
                        "task request was blocked by server security middleware: {}",
                        detail
                    );
                    break;
                }
                Err(e) => {
                    failures += 1;
                    let delay = u64::from(failures.min(12)) * 5;
                    tracing::warn!("fetch task failed (attempt {}): {}", failures, e);
                    sleep(Duration::from_secs(delay)).await;
                    continue;
                }
            };
        active_task.set(assigned_task.task_id).await;

        let target = TargetParams {
            ip: assigned_task.task_target.join(","),
            port: assigned_task.task_port.clone(),
            rate: config.rate,
            source_port: config.source_port,
        };

        tracing::info!(
            "scanning {}:{} rate={} sport={}",
            target.ip,
            target.port,
            target.rate,
            target.source_port
        );

        let cancel_flag = active_task.cancellation_flag();
        let results = match run_scan(config.scanner_path, &target, &cancel_flag).await {
            Ok(ScanOutcome::Completed(results)) => results,
            Ok(ScanOutcome::Cancelled) => {
                match heartbeat_client
                    .report_cancelled(assigned_task.task_id)
                    .await
                {
                    Ok(()) => {
                        tracing::info!("task {} cancelled by server", assigned_task.task_id);
                        active_task.clear().await;
                        continue;
                    }
                    Err(error) => {
                        tracing::error!("failed to acknowledge task cancellation: {error}");
                        break;
                    }
                }
            }
            Err(e) => {
                log_event!(LogLevel::Error, "SCAN-ERROR", "scan failed", "scan_loop");
                tracing::error!("scan error: {}", e);
                let mut reported = false;
                for attempt in 1..=3 {
                    match heartbeat_client
                        .report_failure(assigned_task.task_id, &e.to_string())
                        .await
                    {
                        Ok(()) => {
                            reported = true;
                            active_task.clear().await;
                            break;
                        }
                        Err(error) => {
                            tracing::warn!("failed to report task failure ({attempt}/3): {error}");
                            sleep(Duration::from_secs(2)).await;
                        }
                    }
                }
                if reported {
                    continue;
                }
                tracing::error!(
                    "task failure could not be reported; stopping to preserve lease ownership"
                );
                break;
            }
        };

        if let Err(error) = cache.begin_task(assigned_task.task_id) {
            tracing::error!("failed to bind results to task: {}", error);
            break;
        }

        for r in &results {
            if stop_requested() {
                log_event!(
                    LogLevel::Info,
                    "FLUSH",
                    "flushing on stop signal",
                    "scan_loop"
                );
                if let Err(error) = flush(uploader, config.scanner_id, cache).await {
                    tracing::error!("upload during shutdown failed: {}", error);
                }
                if stop_requested() {
                    return;
                }
            }

            if let Err(e) = cache.insert(
                &r.ip,
                r.port,
                r.service.as_deref(),
                &r.protocol,
                r.banner.as_deref(),
            ) {
                log_event!(
                    LogLevel::Error,
                    "CACHE-ERROR",
                    "cache insert failed",
                    "scan_loop"
                );
                tracing::error!("cache error: {}", e);
                return;
            }
        }
    }

    match flush(uploader, config.scanner_id, cache).await {
        Ok(()) if !cache.has_pending_task() => active_task.clear().await,
        Ok(()) => {}
        Err(error) => tracing::error!("final scan-loop upload failed: {}", error),
    }
}
