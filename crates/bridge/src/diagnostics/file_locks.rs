//! Answer the question "which processes hold a handle to this file?"
//!
//! Triggered from [`crate::diagnostics::spawn::spawn_with_diagnostics`]
//! when a `Command::spawn()` fails with an OS error that means
//! "someone else has this file open": `ERROR_ACCESS_DENIED` (5) or
//! `ERROR_SHARING_VIOLATION` (32) on Windows, `ETXTBSY` / `EBUSY` on
//! Unix. The typical culprit on Windows CI is Windows Defender
//! scanning a freshly-built `hole.exe`; on macOS it's a writer still
//! holding the file while we try to exec it.
//!
//! Best-effort. Never introduces a new failure mode: a diagnostic that
//! can't run should log and return empty, not error.
//!
//! # Platform support
//!
//! | Platform | Implementation |
//! |----------|----------------|
//! | Windows  | `NtQuerySystemInformation(SystemExtendedHandleInformation)` + kernel-path match |
//! | macOS    | `libproc::processes::pids_by_path` |
//! | other    | returns `Ok(vec![])`; logs at `debug!` |

use std::io;
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
mod unsupported;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "macos")]
use macos::find_holders_impl;
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
use unsupported::find_holders_impl;
#[cfg(target_os = "windows")]
use windows::find_holders_impl;

/// A process that currently holds an open handle to the target file.
///
/// Only verified holders are reported — for a PID that the platform
/// impl couldn't verify (e.g. Windows PPL processes on a non-elevated
/// session), we omit the entry rather than list a noisy "suspect" PID.
/// Windows logs an aggregate `info!` count of inaccessible PIDs so
/// coverage gaps are observable.
#[derive(Debug, Clone)]
pub struct FileHolder {
    /// The holder's process ID.
    pub pid: u32,
    /// Executable path of the holder. `None` if lookup failed — e.g. a
    /// kernel-managed PID like `System` (PID 4).
    pub image: Option<PathBuf>,
}

/// Returns every process that currently holds an open handle to `path`,
/// excluding the current process.
///
/// Returns `Ok(vec![])` when `path` doesn't exist. Returns `Err` only
/// for unexpected OS errors while enumerating the handle table;
/// per-process permission failures during enumeration are swallowed
/// and the offending PID is either skipped or reported with
/// `verified: false`.
pub fn find_holders(path: &Path) -> io::Result<Vec<FileHolder>> {
    if !path.try_exists()? {
        return Ok(Vec::new());
    }
    find_holders_impl(path)
}

/// Log every process currently holding `path` at `tracing::error!` —
/// one line per holder. Diagnostic gaps (canonicalization failure,
/// enumeration error, empty-holders result) are logged at `warn!` and
/// swallowed: this helper is best-effort and must not introduce new
/// failure modes.
pub fn log_holders(path: &Path) {
    let canonical = match std::fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "could not canonicalize path; skipping holder enumeration",
            );
            return;
        }
    };

    let holders = match find_holders(&canonical) {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %canonical.display(),
                "failed to enumerate file-lock holders",
            );
            return;
        }
    };

    if holders.is_empty() {
        tracing::warn!(
            path = %canonical.display(),
            "file-lock contention detected but no holders found (caller may lack privilege, or holder released before we looked)",
        );
        return;
    }

    for h in &holders {
        tracing::error!(
            pid = h.pid,
            image = ?h.image.as_ref().map(|p| p.display().to_string()),
            file = %canonical.display(),
            "file-lock holder",
        );
    }
}

#[cfg(test)]
#[path = "file_locks_tests.rs"]
mod file_locks_tests;
