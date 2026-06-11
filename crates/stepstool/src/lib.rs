//! Elevation primitives for the "unprivileged parent, one elevated child"
//! model (bindreams/hole#452/#455): the parent process never gains or sheds
//! privilege; exactly the children that need root are wrapped.
//!
//! Salvaged from the reusable half of the abandoned `elevated:`-flag work
//! (bindreams/hole PR #456). Deliberately NOT here (YAGNI until a consumer
//! exists; see PR #456 for ready references): Windows `self_elevate` via
//! `ShellExecuteExW(runas)`, `CommandLineToArgvW`-faithful arg quoting,
//! linked-token queries, and everything de-elevation — the latter is dead by
//! design, not deferred.

#[cfg(unix)]
pub mod posix;
#[cfg(unix)]
pub use posix::{prime_sudo, sudo_command, PrimeSudoError};

#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub use windows::{is_elevated, require_elevated, NotElevated};

/// True when the current process is privileged: euid 0 on Unix, an elevated
/// token on Windows.
pub fn is_privileged() -> bool {
    #[cfg(unix)]
    // SAFETY: geteuid has no preconditions and never fails.
    return unsafe { libc::geteuid() } == 0;
    #[cfg(windows)]
    return windows::is_elevated().unwrap_or(false);
}

/// `--preserve-env=A,B,C` — the single owner of sudo's env-preservation
/// argument shape; consumers building their own sudo argv use this instead
/// of re-formatting the literal (drift here silently changes which env
/// survives sudo's scrub). Pure and cross-platform so callers can pin it in
/// tests on any host.
pub fn preserve_env_arg(vars: &[&str]) -> String {
    format!("--preserve-env={}", vars.join(","))
}

#[cfg(test)]
hole_test_observability::register!();

#[cfg(test)]
fn main() {
    skuld::run_all();
}
