//! Cross-platform exit-wait relaunch.
//!
//! When the GUI must replace itself with a new on-disk image (self-heal, or
//! post-update), it can't just spawn-and-exit: the new instance would lose the
//! `com.hole.app` single-instance lock to the still-running old one and
//! silently forward-and-exit. Instead the old GUI spawns the new image with
//! [`spawn_successor`] and blocks on a `READY` line; the new image's
//! [`await_predecessor`] prints it and then waits for the old process to exit,
//! after which a normal launch wins the now-free lock.
//!
//! The successor reads the predecessor's identity — pid plus the kernel's start
//! token — while the predecessor is provably alive, because the predecessor
//! blocks on `READY` before exiting. The token makes every later step immune to
//! pid recycling: cosca re-verifies it inside `wait()`, and a mismatch reads as
//! "already exited" rather than a wait on a stranger. Nothing is held across the
//! gap. The window is closed by that ordering plus the token, not by cosca
//! alone — `wait` takes an identity as input and cannot manufacture one.
//!
//! `READY` also sequences the single-instance lock handoff and proves the
//! successor viable before the predecessor commits to exiting.
//!
//! Nothing here may log through `tracing` or `log`: this runs before the
//! subscriber exists, and stdout carries the handshake.

use std::path::Path;

const AWAIT_ENV: &str = "HOLE_AWAIT_EXIT_PID";
const READY: &str = "READY";

/// argv the successor needs to reproduce an open dashboard. Explicit rather than
/// relying on the default: an older successor (a rollback) defaults to tray-only,
/// which would silently drop the user's open window.
fn successor_args(show_dashboard: bool) -> &'static [&'static str] {
    if show_dashboard {
        &[crate::launch::SHOW_DASHBOARD]
    } else {
        &[]
    }
}

/// Env var to set so the successor suppresses its dashboard, or `None`.
///
/// Suppression travels out-of-band because the successor may predate the flag,
/// and an unknown env var is inert where an unknown flag is a parse error.
fn successor_env(show_dashboard: bool) -> Option<&'static str> {
    if show_dashboard {
        None
    } else {
        Some(crate::launch::NO_DASHBOARD_ENV)
    }
}

/// Spawn the canonical image to take over after we exit, blocking until it has
/// read our identity (the `READY` line). The caller exits next, at which point
/// the successor's wait fires.
///
/// The wire protocol is unchanged and must stay so: `spawn_successor` can spawn
/// an OLDER image (a rollback), so `HOLE_AWAIT_EXIT_PID` keeps its name and its
/// bare-decimal-pid value and the successor still writes the literal `READY`.
pub fn spawn_successor(canonical: &Path, show_dashboard: bool) -> std::io::Result<()> {
    use std::io::BufRead;
    let mut command = std::process::Command::new(canonical);
    command
        .args(successor_args(show_dashboard))
        .env(AWAIT_ENV, std::process::id().to_string())
        .stdout(std::process::Stdio::piped());
    if let Some(key) = successor_env(show_dashboard) {
        command.env(key, "1");
    }
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().expect("stdout was piped");
    let mut line = String::new();
    std::io::BufReader::new(stdout).read_line(&mut line)?;
    if line.trim_end() != READY {
        return Err(std::io::Error::other("successor did not arm exit-wait"));
    }
    Ok(())
}

/// Called at the very top of GUI launch. If we were spawned to take over a
/// predecessor, resolve its identity, signal `READY` (so it may exit), then
/// block until it does — after which a normal launch proceeds uncontested.
/// A no-op (returns immediately) for an ordinary launch.
pub fn await_predecessor() -> std::io::Result<()> {
    let Some(pid) = std::env::var(AWAIT_ENV).ok().and_then(|s| s.parse::<u32>().ok()) else {
        return Ok(());
    };
    // edition 2021: env mutation is still safe-callable.
    std::env::remove_var(AWAIT_ENV);
    let predecessor = cosca::Process::from_pid(pid);
    handshake_then_wait(pid, predecessor, &mut std::io::stdout())
}

/// Print `READY`, then act on the already-resolved predecessor. The resolution
/// is an INPUT, so there is no way to reach the `READY` print without having
/// resolved first — the pid-reuse ordering guard is structural.
///
/// An unassessable predecessor proceeds rather than failing. The old Windows arm
/// did the same (any `OpenProcess` failure became a no-op wait); the old macOS
/// arm returned `Err` BEFORE printing `READY`, so the predecessor's `read_line`
/// never saw the line and `spawn_successor` reported a broken handshake while
/// the successor launched anyway. Unifying on the Windows arm removes that
/// failed-handshake case: both processes agree on the handover, and the fallback
/// is the pre-existing single-instance forward-and-exit.
fn handshake_then_wait<W: std::io::Write>(
    pid: cosca::identity::RawPid,
    predecessor: cosca::identity::Resolved<cosca::Process>,
    out: &mut W,
) -> std::io::Result<()> {
    writeln!(out, "{READY}")?;
    out.flush()?;
    match predecessor {
        cosca::identity::Resolved::Found(p) => p.wait().map_err(std::io::Error::other),
        cosca::identity::Resolved::Gone => Ok(()),
        cosca::identity::Resolved::Unknown => {
            // No subscriber exists yet, and stdout carries the handshake.
            eprintln!("hole: predecessor pid {pid} could not be assessed; proceeding");
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "relaunch_tests.rs"]
mod relaunch_tests;
