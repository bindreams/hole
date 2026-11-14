//! Elevation primitives for the "unprivileged parent, one elevated child"
//! model: the parent process never gains or sheds privilege; exactly the
//! children that need root are wrapped.
//!
//! Deliberately NOT here: Windows `self_elevate` via `ShellExecuteExW(runas)`,
//! `CommandLineToArgvW`-faithful arg quoting and linked-token queries. They are
//! deferred until a consumer exists, not ruled out.
//! De-elevation is excluded by the model, not deferred.

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
