// Daemon logging initialization.

use std::io;
use std::path::PathBuf;

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

/// Returns the daemon log directory path.
pub fn log_dir() -> PathBuf {
    if cfg!(target_os = "windows") {
        PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into()))
            .join("hole")
            .join("logs")
    } else {
        PathBuf::from("/var/log/hole")
    }
}

/// Create the log directory and restrict its permissions.
///
/// On macOS the directory is set to `root:hole 0750` (or `root:root 0700` if
/// the `hole` group does not exist yet).  On Windows the default ACLs on
/// `ProgramData` are sufficient.
///
/// Requires elevated privileges (root on macOS, Administrator on Windows).
pub fn ensure_log_dir() -> io::Result<PathBuf> {
    let dir = log_dir();
    std::fs::create_dir_all(&dir)?;

    #[cfg(all(target_os = "macos", not(test)))]
    restrict_log_dir_permissions(&dir)?;

    Ok(dir)
}

/// Initialize daemon logging (rolling daily file appender).
///
/// Creates the log directory with restricted permissions, then sets up a
/// rolling daily file appender.  Returns a guard that must be held for the
/// lifetime of the daemon process; dropping it flushes and closes the log file.
pub fn init() -> io::Result<WorkerGuard> {
    let dir = ensure_log_dir()?;

    let file_appender = tracing_appender::rolling::daily(&dir, "hole-daemon.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("hole_daemon=info".parse().expect("valid tracing directive")),
        )
        .with_writer(non_blocking)
        .init();

    Ok(guard)
}

/// Initialize daemon logging for foreground/dev mode (log to stderr).
///
/// The returned `WorkerGuard` must be held for the lifetime of the process;
/// dropping it flushes pending writes. Callers should bind it in the same
/// scope that calls the foreground runner, not inside the runner itself.
pub fn init_foreground() -> WorkerGuard {
    let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stderr());
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("hole_daemon=debug".parse().expect("valid tracing directive")),
        )
        .with_writer(non_blocking)
        .init();
    guard
}

// Restrict log directory permissions on macOS -------------------------------------------------------------------------

/// Restrict the log directory to `root:hole 0750`, falling back to `root 0700`.
///
/// Locks down to 0700 first (closing any window where the directory is
/// world-readable), then attempts to chown to `root:hole` and widen to 0750.
#[cfg(all(target_os = "macos", not(test)))]
fn restrict_log_dir_permissions(dir: &std::path::Path) -> io::Result<()> {
    use std::ffi::CString;

    let path_str = dir
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "log dir path is not valid UTF-8"))?;
    let c_path = CString::new(path_str).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    // Immediately restrict to root-only so the directory is never exposed with
    // its umask-derived permissions while we attempt chown below.
    if unsafe { libc::chmod(c_path.as_ptr(), 0o700) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let group_name = CString::new(crate::group::GROUP_NAME).unwrap();
    let grp = unsafe { libc::getgrnam(group_name.as_ptr()) };

    if grp.is_null() {
        return Ok(()); // Already 0700 — group doesn't exist yet.
    }

    let gid = unsafe { (*grp).gr_gid };

    if unsafe { libc::chown(c_path.as_ptr(), 0, gid) } != 0 {
        eprintln!(
            "warning: chown {dir:?} to root:{} failed, log directory will be root-only",
            crate::group::GROUP_NAME
        );
        return Ok(()); // Already 0700 — safe fallback.
    }

    // Widen to group-readable now that ownership is correct.
    if unsafe { libc::chmod(c_path.as_ptr(), 0o750) } != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}
