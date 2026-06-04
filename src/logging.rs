use chrono::Local;
use std::path::Path;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize the tracing/logging system.
///
/// Logs are written both to:
/// - Console (stderr, human-readable)
/// - File (JSON format, rotated daily, stored in `./logs/`)
pub fn init_logging(debug_mode: bool) -> Result<(), std::io::Error> {
    // Ensure logs directory exists
    let log_dir = Path::new("./logs");
    if !log_dir.exists() {
        std::fs::create_dir_all(log_dir)?;
    }

    // File appender with daily rotation
    let file_appender = tracing_appender::rolling::daily("./logs", "scanner.log");

    // Filter: DEBUG level if debug_mode, INFO otherwise
    let default_level = if debug_mode { "debug" } else { "info" };
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_level));

    // Console layer (human-readable)
    let console_layer = fmt::layer()
        .with_target(true)
        .with_thread_ids(false)
        .with_file(true)
        .with_line_number(true);

    // File layer (JSON format)
    let file_layer = fmt::layer()
        .json()
        .with_writer(file_appender)
        .with_target(true)
        .with_file(true)
        .with_line_number(true);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(console_layer)
        .with(file_layer)
        .init();

    Ok(())
}

/// Log a structured event, matching the C version's `log_to` function.
///
/// Parameters match the original C function signature:
/// `log_to(level, event, message, event_path, log_type)`
pub fn log_to(level: &str, event: &str, message: &str, event_path: &str) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%z").to_string();

    match level.to_uppercase().as_str() {
        "ERROR" => {
            tracing::error!(
                timestamp = %timestamp,
                event = %event,
                path = %event_path,
                message = %message,
                ""
            );
        }
        "WARN" => {
            tracing::warn!(
                timestamp = %timestamp,
                event = %event,
                path = %event_path,
                message = %message,
                ""
            );
        }
        "DEBUG" => {
            tracing::debug!(
                timestamp = %timestamp,
                event = %event,
                path = %event_path,
                message = %message,
                ""
            );
        }
        _ => {
            tracing::info!(
                timestamp = %timestamp,
                event = %event,
                path = %event_path,
                message = %message,
                ""
            );
        }
    }
}

/// Get current milliseconds timestamp (replaces `get_milliseconds_timestamp`)
#[allow(dead_code)]
pub fn get_milliseconds_timestamp() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
