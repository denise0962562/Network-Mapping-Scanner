use std::path::Path;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub(crate) fn init_logging(debug: bool) -> Result<(), std::io::Error> {
    let log_dir = Path::new("./logs");
    if !log_dir.exists() {
        std::fs::create_dir_all(log_dir)?;
    }

    let file_appender = tracing_appender::rolling::daily("./logs", "scanner.log");

    let default_level = if debug { "debug" } else { "info" };
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));

    let console = fmt::layer()
        .with_target(false)
        .with_file(true)
        .with_line_number(true);

    let file = fmt::layer()
        .json()
        .with_writer(file_appender)
        .with_target(true)
        .with_file(true)
        .with_line_number(true);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(console)
        .with(file)
        .init();

    Ok(())
}

/// Convenience macro wrapping `tracing` field-value syntax for structured log events.
#[macro_export]
macro_rules! log_event {
    ($level:expr, $event:expr, $msg:expr, $path:expr) => {
        match $level {
            $crate::logging::LogLevel::Error => {
                ::tracing::error!(event = $event, path = $path, message = $msg)
            }
            $crate::logging::LogLevel::Warn => {
                ::tracing::warn!(event = $event, path = $path, message = $msg)
            }
            $crate::logging::LogLevel::Debug => {
                ::tracing::debug!(event = $event, path = $path, message = $msg)
            }
            $crate::logging::LogLevel::Info => {
                ::tracing::info!(event = $event, path = $path, message = $msg)
            }
        }
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogLevel {
    #[allow(dead_code)]
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    #[allow(dead_code)]
    pub(crate) fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "ERROR" => Self::Error,
            "WARN" => Self::Warn,
            "DEBUG" => Self::Debug,
            _ => Self::Info,
        }
    }
}
