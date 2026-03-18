// Logging setup with daily rotation.

use std::path::Path;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

/// Initialize tracing with daily log rotation.
///
/// Returns a [`WorkerGuard`] that must be held for the lifetime of the application
/// to ensure all logs are flushed.
pub fn init(log_dir: &Path) -> WorkerGuard {
    let _ = std::fs::create_dir_all(log_dir);

    let file_appender = tracing_appender::rolling::daily(log_dir, "hole.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // Use try_init to avoid panicking if a global subscriber is already set (e.g. in tests).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("hole_gui=info".parse().unwrap()))
        .with_writer(non_blocking)
        .try_init();

    guard
}

#[cfg(test)]
#[path = "logging_tests.rs"]
mod logging_tests;
