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

/// What measuring the privilege of the current process found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Privilege {
    /// euid 0 on Unix, an elevated token on Windows.
    Privileged,
    Unprivileged,
    /// The measurement failed (a failed Windows token query).
    Unreadable,
}

impl Privilege {
    /// Whether to act as a privileged process. A privilege that could not be read counts as one: a process that
    /// guessed wrong the other way would follow a user's links as the system.
    pub fn is_privileged(self) -> bool {
        match self {
            Privilege::Privileged => true,
            Privilege::Unprivileged => false,
            Privilege::Unreadable => true,
        }
    }
}

/// The privilege of the current process.
pub fn privilege() -> Privilege {
    #[cfg(unix)]
    // SAFETY: geteuid has no preconditions and never fails.
    let measured = Ok::<bool, std::convert::Infallible>(unsafe { libc::geteuid() } == 0);
    #[cfg(windows)]
    let measured = windows::is_elevated();
    match measured {
        Ok(true) => Privilege::Privileged,
        Ok(false) => Privilege::Unprivileged,
        Err(_) => Privilege::Unreadable,
    }
}

/// [`Privilege::is_privileged`] of this process: only a measured "not privileged" is not.
pub fn is_privileged() -> bool {
    privilege().is_privileged()
}

/// The principal of this process for a file it handles in a folder a user may own: [`util::dir::Principal::System`]
/// when it is privileged ([`is_privileged`]), the user's own otherwise. Read it once at the entry point and hand it to
/// whatever opens a log, a crash marker or a config file, so no callee guesses it.
pub fn principal() -> util::dir::Principal {
    match is_privileged() {
        true => util::dir::Principal::System,
        false => util::dir::Principal::User,
    }
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
#[path = "lib_tests.rs"]
mod lib_tests;

#[cfg(test)]
hole_test_observability::register!();

#[cfg(test)]
fn main() {
    skuld::run_all();
}
