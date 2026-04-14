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
#[derive(Debug, Clone)]
pub struct FileHolder {
    /// The holder's process ID.
    pub pid: u32,
    /// Executable path of the holder. `None` if lookup failed — e.g. a
    /// kernel-managed PID like `System` (PID 4), or a protected process
    /// (PPL) that denies `PROCESS_QUERY_LIMITED_INFORMATION`.
    pub image: Option<PathBuf>,
    /// `true` when we verified the handle refers to `path`. `false`
    /// when we could only prove "this PID holds *some* file handle"
    /// — e.g. `DuplicateHandle` was denied by PPL protection on
    /// Windows. Unverified holders should be presented as "suspect".
    pub verified: bool,
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

/// Log, at `tracing::error!`, every process currently holding `path`.
/// Best-effort: canonicalization failures, enumeration errors, and
/// empty-holder results are all logged at lower severity and don't
/// propagate.
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
            verified = h.verified,
            file = %canonical.display(),
            "file-lock holder",
        );
    }
}

#[cfg(test)]
#[path = "file_locks_tests.rs"]
mod file_locks_tests;
