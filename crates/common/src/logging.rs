// Shared logging initialization — tees output to stderr + rolling daily file.

use std::path::{Path, PathBuf};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::EnvFilter;

/// Guards for the non-blocking writers. Must be held for the process lifetime.
pub struct LogGuard {
    _file: WorkerGuard,
    _stderr: WorkerGuard,
}

/// Default log directory: `<state_dir>/hole/logs`.
///
/// Falls back to `<data_local_dir>/hole/logs` when `state_dir` is not available
/// (macOS and Windows don't define a distinct state dir).
pub fn default_log_dir() -> PathBuf {
    crate::paths::default_user_subdir("logs")
}

/// Initialize logging to stderr + rolling daily file.
///
/// Creates `log_dir` if it doesn't exist. Returns a guard that must be held
/// for the process lifetime to ensure logs are flushed.
pub fn init(log_dir: &Path, log_filename: &str, default_directive: &str) -> LogGuard {
    let _ = std::fs::create_dir_all(log_dir);

    let file_appender = tracing_appender::rolling::daily(log_dir, log_filename);
    let (file_nb, file_guard) = tracing_appender::non_blocking(file_appender);
    let (stderr_nb, stderr_guard) = tracing_appender::non_blocking(std::io::stderr());

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive(default_directive.parse().expect("valid tracing directive")),
        )
        .with_writer(file_nb.and(stderr_nb))
        .try_init();

    LogGuard {
        _file: file_guard,
        _stderr: stderr_guard,
    }
}
