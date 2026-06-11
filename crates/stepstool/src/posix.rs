//! POSIX side: sudo credential priming and sudo-wrapped command construction.
//! Adapted from PR #456's `xtask/src/privilege/posix.rs` (`prime_sudo`).

use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum PrimeSudoError {
    /// sudo itself could not be spawned (not on PATH / not executable).
    /// Message text = dev.py:489 verbatim.
    #[error("sudo not found on PATH; cannot elevate the bridge ({0})")]
    SudoNotFound(std::io::Error),
    /// A TTY was available, the interactive prompt ran, and it FAILED
    /// (wrong password / Ctrl+C at the prompt). Message = dev.py:486.
    #[error("sudo authentication failed")]
    AuthFailed,
    /// No cached credentials and no TTY to prompt on.
    #[error(
        "sudo credentials are unavailable and there is no TTY to prompt on; \
             run `sudo -v` in this terminal first, or re-run from an interactive shell"
    )]
    NoTty,
}

/// Prime sudo's credential cache so the immediately-following sudo-wrapped
/// spawns do not prompt: probe `sudo -n true` (cached cred / NOPASSWD); on
/// failure run interactive `sudo -v` — but only when stdin is a TTY (a blind
/// `sudo -v` hangs or fails TTY-less, e.g. on macOS under an IDE runner).
pub fn prime_sudo() -> Result<(), PrimeSudoError> {
    // SAFETY: isatty has no preconditions.
    let has_tty = unsafe { libc::isatty(libc::STDIN_FILENO) } == 1;
    prime_sudo_with(Path::new("sudo"), has_tty)
}

/// Testable core: `sudo` binary and TTY-ness injected.
pub fn prime_sudo_with(sudo: &Path, has_tty: bool) -> Result<(), PrimeSudoError> {
    let probe = Command::new(sudo)
        .args(["-n", "true"])
        .status()
        .map_err(PrimeSudoError::SudoNotFound)?;
    if probe.success() {
        return Ok(());
    }
    if !has_tty {
        return Err(PrimeSudoError::NoTty);
    }
    let interactive = Command::new(sudo)
        .arg("-v")
        .status()
        .map_err(PrimeSudoError::SudoNotFound)?;
    if interactive.success() {
        Ok(())
    } else {
        Err(PrimeSudoError::AuthFailed)
    }
}

/// A `Command` running `program` under sudo with the given env vars
/// preserved across sudo's scrub. The caller appends program args and stdio
/// config. `program` should be an absolute path (sudoers `secure_path`
/// ignores the caller's PATH).
pub fn sudo_command(program: impl AsRef<OsStr>, preserve_env: &[&str]) -> Command {
    let mut cmd = Command::new("sudo");
    cmd.arg(crate::preserve_env_arg(preserve_env));
    cmd.arg(program.as_ref());
    cmd
}

#[cfg(test)]
#[path = "posix_tests.rs"]
mod posix_tests;
