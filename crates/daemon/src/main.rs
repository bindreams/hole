use tracing::info;
use tracing_subscriber::EnvFilter;

fn main() {
    // Initialize logging
    let log_dir = if cfg!(target_os = "windows") {
        std::path::PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into()))
            .join("hole")
            .join("logs")
    } else {
        std::path::PathBuf::from("/var/log/hole")
    };
    let _ = std::fs::create_dir_all(&log_dir);

    let file_appender = tracing_appender::rolling::daily(&log_dir, "hole-daemon.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("hole_daemon=info".parse().unwrap()))
        .with_writer(non_blocking)
        .init();

    info!("hole-daemon starting");

    // Crash recovery: clean up stale split routes from a previous crash
    hole_daemon::routing::teardown_split_routes().ok();

    // Platform-specific service entry
    #[cfg(target_os = "windows")]
    {
        if let Err(e) = hole_daemon::platform::os::run_as_service() {
            eprintln!("failed to start as Windows service: {e}");
            std::process::exit(1);
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Err(e) = hole_daemon::platform::os::run_daemon() {
            eprintln!("daemon error: {e}");
            std::process::exit(1);
        }
    }
}
