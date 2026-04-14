//! Thin wrapper around `Command::spawn` that attaches file-lock
//! holder diagnostics when the spawn fails with an OS error that
//! typically means "some other process holds this file open".
//!
//! This is the sanctioned way to spawn a `Command` in the bridge.
//! A `clippy.toml` `disallowed_methods` entry forces direct callers
//! through this wrapper so future spawn sites automatically get the
//! diagnostic on `ERROR_ACCESS_DENIED` / `ETXTBSY` — without the
//! caller needing to remember to wire it up.
//!
//! Best-effort: diagnostics are fire-and-forget; the original
//! `io::Error` always propagates unchanged.

use crate::diagnostics::file_locks;
use std::io;
use std::path::Path;
use std::process::{Child, Command};

/// Returns `true` for the OS-specific error codes that typically mean
/// "another process holds a handle that blocks spawning this file":
/// `ERROR_ACCESS_DENIED` (5) and `ERROR_SHARING_VIOLATION` (32) on
/// Windows, `ETXTBSY` / `EBUSY` on Unix.
pub fn is_file_contention(err: &io::Error) -> bool {
    match err.raw_os_error() {
        #[cfg(windows)]
        Some(5 | 32) => true,
        #[cfg(unix)]
        Some(e) if e == libc::ETXTBSY || e == libc::EBUSY => true,
        _ => false,
    }
}

/// Call `cmd.spawn()` and on file-contention errors, log every
/// process currently holding the target executable before returning
/// the original error.
///
/// Callers should pass an absolute program path; if `cmd.get_program()`
/// isn't canonicalizable, `log_holders` logs a `warn!` and returns
/// without enumerating.
#[allow(clippy::disallowed_methods)] // this IS the sanctioned wrapper
pub fn spawn_with_diagnostics(cmd: &mut Command) -> io::Result<Child> {
    match cmd.spawn() {
        Ok(child) => Ok(child),
        Err(e) => {
            if is_file_contention(&e) {
                let program = Path::new(cmd.get_program());
                tracing::error!(
                    error = %e,
                    program = %program.display(),
                    "spawn failed with file-contention error; enumerating handle holders",
                );
                file_locks::log_holders(program);
            }
            Err(e)
        }
    }
}

#[cfg(test)]
#[path = "spawn_tests.rs"]
mod spawn_tests;
