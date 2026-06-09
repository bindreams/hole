//! Cross-platform process privilege control.
//!
//! Reusable by the build orchestrator (per-step `elevated:`) and the future
//! Rust dev supervisor (bindreams/hole#454). Operates only on
//! [`std::process::Command`] + the plain types below; it knows nothing about
//! `build.yaml` or [`crate::manifest::Step`]. All platform code lives in the
//! `posix`/`windows` submodules; signatures here are platform-neutral.
//!
//! The pure decision core is [`Host::plan`] — no side effects, no privileges,
//! exhaustively unit-tested on every OS via the [`ElevateStrategy`] data field.

use std::path::PathBuf;
use std::process::Command;

use anyhow::Result;

#[cfg(unix)]
#[path = "privilege/posix.rs"]
mod posix;
#[cfg(windows)]
#[path = "privilege/win_quote.rs"]
mod win_quote;
#[cfg(windows)]
#[path = "privilege/windows.rs"]
mod windows;

/// The privilege a step is *declared* to run at — independent of the ambient.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Privilege {
    Unprivileged,
    Elevated,
}

/// How this platform *gains* privilege when unprivileged work needs root/admin.
/// Stored as data (set by [`Host::detect`]) so [`Host::plan`] is pure and both
/// branches are testable on any host.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ElevateStrategy {
    /// POSIX: prefix the child with `sudo`.
    Posix,
    /// Windows: re-launch the whole process via UAC.
    Windows,
}

/// The user a privileged process drops down to. The variant matches the host by
/// construction in [`Host::detect`]; [`Host::plan`] only checks `is_some()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvokingUser {
    Posix {
        name: String,
        uid: u32,
        gid: u32,
        home: PathBuf,
    },
    /// Windows: a linked (limited) token is available to de-elevate a child.
    WindowsLinkedToken,
}

/// Supplementary-group policy for a POSIX drop (ignored on Windows).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Groups {
    Full,
    Only(Vec<String>),
}

/// Ambient privilege facts, resolved once. `detect()` in production; construct
/// directly in tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Host {
    pub elevated: bool,
    pub invoking_user: Option<InvokingUser>,
    pub is_ci: bool,
    /// POSIX-only signal (Windows never prompts on a TTY — UAC is GUI).
    pub has_tty: bool,
    pub strategy: ElevateStrategy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transition {
    RunAsIs,
    DropTo(InvokingUser),
    ElevateChild,       // POSIX: sudo prefix
    SelfElevateProcess, // Windows: UAC re-launch (handled up front)
    WarnVacuous(String),
    HardFail(String),
}

/// Outcome of the up-front readiness pass (acted on at the CLI boundary).
#[derive(Debug)]
pub enum Readiness {
    Proceed,
    /// Windows only: we re-launched elevated; child exited with this code.
    ElevatedChildExited(i32),
}

impl Host {
    pub fn detect() -> Self {
        let is_ci = std::env::var_os("CI").is_some();
        #[cfg(unix)]
        {
            posix::detect(is_ci)
        }
        #[cfg(windows)]
        {
            windows::detect(is_ci)
        }
        #[cfg(not(any(unix, windows)))]
        {
            Host {
                elevated: false,
                invoking_user: None,
                is_ci,
                has_tty: false,
                strategy: ElevateStrategy::Posix,
            }
        }
    }

    /// Pure decision. No side effects, no privileges.
    pub fn plan(&self, target: Privilege) -> Transition {
        match (target, self.elevated) {
            (Privilege::Unprivileged, false) => Transition::RunAsIs,
            (Privilege::Unprivileged, true) => match &self.invoking_user {
                Some(user) => Transition::DropTo(user.clone()),
                None if self.is_ci => Transition::HardFail(
                    "running elevated under CI with no invoking user to drop to \
                     (set HOLE_BUILD_USER=<user> to designate a drop target)"
                        .into(),
                ),
                None => Transition::WarnVacuous(
                    "running elevated with no unprivileged user to honor; proceeding \
                     as-is (set HOLE_BUILD_USER=<user> to drop)"
                        .into(),
                ),
            },
            (Privilege::Elevated, true) => Transition::RunAsIs,
            (Privilege::Elevated, false) => match self.strategy {
                ElevateStrategy::Posix => Transition::ElevateChild,
                ElevateStrategy::Windows => Transition::SelfElevateProcess,
            },
        }
    }
}

/// Up-front, process-level. If `any_elevated_ahead` and we are not elevated:
/// POSIX primes sudo credentials (see posix.rs); Windows self-elevates the
/// whole process via UAC and reports the child's exit code.
pub fn ensure_can_elevate(host: &Host, any_elevated_ahead: bool) -> Result<Readiness> {
    if !any_elevated_ahead || host.elevated {
        return Ok(Readiness::Proceed);
    }
    #[cfg(unix)]
    {
        posix::prime_sudo(host)?;
        Ok(Readiness::Proceed)
    }
    #[cfg(windows)]
    {
        windows::self_elevate()
    }
    #[cfg(not(any(unix, windows)))]
    {
        anyhow::bail!("privilege elevation unsupported on this platform")
    }
}

/// Spawn `cmd` at `target` privilege relative to `host`, inheriting stdio, wait.
pub fn run_command(host: &Host, target: Privilege, cmd: Command, groups: &Groups, label: &str) -> Result<()> {
    let transition = host.plan(target);
    #[cfg(unix)]
    {
        posix::run_command(transition, cmd, groups, label)
    }
    #[cfg(windows)]
    {
        let _ = groups;
        windows::run_command(transition, cmd, label)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (transition, cmd, groups, label);
        anyhow::bail!("unsupported platform")
    }
}

/// Spawn `cmd` inheriting stdio and map a non-zero exit to an error. Shared by
/// both effect layers for the run-as-is / drop / elevate-child paths
/// (cross-platform — the name carries no POSIX semantics).
pub(crate) fn run_inherit(mut cmd: Command, label: &str) -> Result<()> {
    use std::process::Stdio;
    cmd.stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let status = cmd.status().map_err(|e| anyhow::anyhow!("spawning {label}: {e}"))?;
    if !status.success() {
        return Err(anyhow::anyhow!("{label} failed: exit status {status}"));
    }
    Ok(())
}
