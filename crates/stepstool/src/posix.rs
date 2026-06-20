//! POSIX side: sudo credential priming and sudo-wrapped command construction.
//! Adapted from PR #456's `xtask/src/privilege/posix.rs` (`prime_sudo`).

use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum PrimeSudoError {
    /// sudo itself could not be spawned (not on PATH / not executable).
    #[error("sudo not found on PATH; cannot elevate the bridge ({0})")]
    SudoNotFound(std::io::Error),
    /// `sudo -v` ran but did not cache credentials: a wrong password, a
    /// Ctrl+C at the prompt, or no terminal / askpass helper to prompt on.
    #[error(
        "could not cache sudo credentials (wrong password, or no terminal to \
         prompt on); run `sudo -v` in this terminal first, or re-run from an \
         interactive shell"
    )]
    PrimingFailed,
}

/// Prime sudo's credential cache so the immediately-following sudo-wrapped
/// spawns do not prompt: probe `sudo -n true` (cached cred / NOPASSWD); on
/// failure run interactive `sudo -v`.
///
/// `sudo -v` reads the password from the controlling terminal (`/dev/tty`),
/// not stdin — so we always attempt it and let sudo prompt (or fall back to
/// an askpass helper, or fail fast with "a terminal is required" when neither
/// is available). We deliberately do NOT gate on `isatty(stdin)`: under
/// `cargo xtask run hole` the orchestrator spawns dev-console with
/// stdin = /dev/null, so a stdin check is always false even from an
/// interactive shell (bindreams/hole#567).
pub fn prime_sudo() -> Result<(), PrimeSudoError> {
    prime_sudo_with(Path::new("sudo"))
}

/// Testable core: the `sudo` binary is injected.
pub fn prime_sudo_with(sudo: &Path) -> Result<(), PrimeSudoError> {
    let probe = Command::new(sudo)
        .args(["-n", "true"])
        .status()
        .map_err(PrimeSudoError::SudoNotFound)?;
    if probe.success() {
        return Ok(());
    }
    let interactive = Command::new(sudo)
        .arg("-v")
        .status()
        .map_err(PrimeSudoError::SudoNotFound)?;
    if interactive.success() {
        Ok(())
    } else {
        Err(PrimeSudoError::PrimingFailed)
    }
}

/// A `Command` running `program` under sudo with the given env vars
/// preserved across sudo's scrub. The caller appends program args and stdio
/// config. `program` should be an absolute path (sudoers `secure_path`
/// ignores the caller's PATH).
///
/// Set `stdin(Stdio::null())` on the result before spawning: with a null
/// stdin an expired sudo timestamp gets EOF and exits non-zero instead of
/// hanging on an invisible password prompt (pair with [`prime_sudo`]).
///
/// Library surface: no in-repo consumer exercises this yet (dev-console
/// builds its argv via its own policy layer for exact-pin testability);
/// it exists for external consumers and the planned `elevated:`-flag
/// revival (bindreams/hole#453).
pub fn sudo_command(program: impl AsRef<OsStr>, preserve_env: &[&str]) -> Command {
    let mut cmd = Command::new("sudo");
    cmd.arg(crate::preserve_env_arg(preserve_env));
    cmd.arg(program.as_ref());
    cmd
}

#[cfg(test)]
#[path = "posix_tests.rs"]
mod posix_tests;
