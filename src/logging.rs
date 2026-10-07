use std::{
    io::Write,
    path::{Path, PathBuf},
};
use tracing_appender::non_blocking::{NonBlocking, NonBlockingBuilder, WorkerGuard};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

pub(crate) struct LoggingGuard {
    _file_guard: WorkerGuard,
    directory: PathBuf,
}

impl LoggingGuard {
    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }
}

pub(crate) fn init_logging(
    debug_enabled: bool,
    log_directory: &Path,
) -> Result<LoggingGuard, std::io::Error> {
    std::fs::create_dir_all(log_directory)?;
    let log_directory = log_directory.canonicalize()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&log_directory, std::fs::Permissions::from_mode(0o700))?;
    }

    let file_appender = tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("scanner.log")
        .max_log_files(14)
        .build(&log_directory)
        .map_err(std::io::Error::other)?;
    let (file_writer, file_guard) = NonBlockingBuilder::default()
        .lossy(false)
        .finish(file_appender);

    let default_level = if debug_enabled { "debug" } else { "info" };
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));

    let console = fmt::layer()
        .with_target(false)
        .with_file(true)
        .with_line_number(true);

    let file = fmt::layer()
        .json()
        .with_writer(JsonDiagnosticWriter(file_writer))
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_current_span(true);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(console)
        .with(file)
        .init();

    tracing::debug!(
        debug_flag = debug_enabled,
        rust_log = ?std::env::var_os("RUST_LOG"),
        log_directory = %log_directory.display(),
        log_file_pattern = "scanner.log.YYYY-MM-DD",
        lossless_file_logging = true,
        "logging initialized"
    );

    Ok(LoggingGuard {
        _file_guard: file_guard,
        directory: log_directory,
    })
}

#[derive(Clone)]
struct JsonDiagnosticWriter(NonBlocking);

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for JsonDiagnosticWriter {
    type Writer = JsonEventWriter;
    fn make_writer(&'a self) -> Self::Writer {
        JsonEventWriter {
            output: self.0.clone(),
            buffer: Vec::new(),
        }
    }
}

struct JsonEventWriter {
    output: NonBlocking,
    buffer: Vec<u8>,
}
impl Write for JsonEventWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Drop for JsonEventWriter {
    fn drop(&mut self) {
        if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&self.buffer) {
            value["fields"]["boot_id"] = serde_json::json!(crate::diagnostics::boot_id());
            if matches!(value["level"].as_str(), Some("WARN" | "ERROR"))
                || value
                    .pointer("/fields/event")
                    .and_then(serde_json::Value::as_str)
                    == Some("ScannerOperationRecovered")
            {
                value["fields"]["event_id"] = serde_json::json!(uuid::Uuid::now_v7());
                crate::diagnostics::capture(&value);
            }
            if let Ok(mut bytes) = serde_json::to_vec(&value) {
                bytes.push(b'\n');
                let _ = self.output.write_all(&bytes);
                return;
            }
        }
        let _ = self.output.write_all(&self.buffer);
    }
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
