// Daemon logging initialization.

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

/// Returns the daemon log directory path.
pub fn log_dir() -> std::path::PathBuf {
    if cfg!(target_os = "windows") {
        std::path::PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into()))
            .join("hole")
            .join("logs")
    } else {
        std::path::PathBuf::from("/var/log/hole")
    }
}

/// Initialize daemon logging (rolling daily file appender).
///
/// Returns a guard that must be held for the lifetime of the daemon process;
/// dropping it flushes and closes the log file.
pub fn init() -> WorkerGuard {
    let dir = log_dir();
    let _ = std::fs::create_dir_all(&dir);

    let file_appender = tracing_appender::rolling::daily(&dir, "hole-daemon.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("hole_daemon=info".parse().expect("valid tracing directive")),
        )
        .with_writer(non_blocking)
        .init();

    guard
}
