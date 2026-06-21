//! Preflight steps: tool resolution, npm install, per-pid staging. Children
//! here run with INHERITED stdio (the user watches
//! cargo/npm output directly) and are not process-grouped — terminal Ctrl+C
//! reaches the step child via the console group AND resolves our interrupt
//! watcher: we reap the child and unwind with `Interrupted`, so guards Drop
//! (dev.py's atexit-on-KeyboardInterrupt equivalent, Delta 2 extends it to
//! SIGTERM).

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};

use crate::ansi::{BOLD, RESET, YELLOW};
use crate::interrupts::Interrupts;

/// A preflight child failed; carries its exit code for propagation.
/// dev.py message parity: npm/cargo failures exit with the child's code and
/// print NOTHING extra; only the stage step has a message (dev.py:467).
#[derive(Debug)]
pub struct StepFailed {
    pub what: &'static str,
    pub code: i32,
    /// Printed (yellow) by the top-level handler when present.
    pub message: Option<String>,
}

impl std::fmt::Display for StepFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed (exit {})", self.what, self.code)
    }
}
impl std::error::Error for StepFailed {}

/// The user interrupted a preflight step (Ctrl+C/SIGTERM). Unwinds to
/// `supervise::main`, which exits 0 after guards drop.
#[derive(Debug)]
pub struct Interrupted;

impl std::fmt::Display for Interrupted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "interrupted")
    }
}
impl std::error::Error for Interrupted {}

/// Resolve a tool on PATH. `which` 8 performs Windows PATHEXT resolution
/// (`npm` → `npm.cmd`), which `CreateProcess` alone does not — the single
/// most-cited dev.py porting trap (§5.17/§6.4); pinned by
/// `resolve_tool_appends_windows_extension`.
pub fn resolve_tool(name: &str) -> Result<PathBuf> {
    which::which(name).with_context(|| format!("{YELLOW}{name} not found on PATH{RESET}"))
}

async fn run_step(
    mut cmd: tokio::process::Command,
    what: &'static str,
    message_on_failure: bool,
    interrupts: &mut Interrupts,
) -> Result<()> {
    let mut child = cmd.spawn().with_context(|| format!("spawning {what}"))?;
    // biased: if the interrupt and the (interrupt-induced) child exit race,
    // report Interrupted — the exit code of a SIGINT-killed cargo is noise.
    tokio::select! {
        biased;
        _ = interrupts.recv() => {
            let _ = child.kill().await;
            Err(Interrupted.into())
        }
        status = child.wait() => {
            let status = status.with_context(|| format!("waiting for {what}"))?;
            if status.success() {
                Ok(())
            } else {
                let code = status.code().unwrap_or(1);
                let message = message_on_failure.then(|| format!("{what} failed (exit {code})"));
                Err(StepFailed { what, code, message }.into())
            }
        }
    }
}

/// `npm install` unconditionally — a skip-on-exists would silently miss
/// dependency additions pulled from a new commit and leave Vite failing to
/// resolve the import; ~1s on a healthy tree (dev.py §5.12).
pub async fn ensure_node_modules(npm: &Path, interrupts: &mut Interrupts) -> Result<()> {
    note!("{BOLD}Syncing npm dependencies...{RESET}");
    let mut cmd = tokio::process::Command::new(npm);
    cmd.args(["install", "--no-audit", "--no-fund"]);
    run_step(cmd, "npm install", false, interrupts).await
}

/// `$TMPDIR/hole-dev-<pid>` — per-pid so concurrent runs don't collide and
/// the running bridge's file lock can't block a later `cargo build`; the
/// staged-name contract (`hole-dev-<pid>/hole(.exe)`) is load-bearing for
/// scripts/network-reset.py's WMI process match.
pub fn stage_dir_path(pid: u32) -> PathBuf {
    std::env::temp_dir().join(format!("hole-dev-{pid}"))
}

/// Removes the registered path on drop (ignore-errors). Register BEFORE
/// creating the dir so a partially-created dir is still cleaned up. Lives
/// until the end of supervision; `run()` returns ExitCode instead of calling
/// process::exit precisely so this Drop always runs.
pub struct StageDirGuard {
    path: PathBuf,
}

impl StageDirGuard {
    pub fn register(path: PathBuf) -> Self {
        Self { path }
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StageDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// `cargo xtask stage --profile debug --out-dir <stage>` — the BINDIR
/// contents/naming are owned by xtask (`xtask/src/bindir.rs`, #143). The
/// only preflight step with a failure message (dev.py:467).
pub async fn stage_bindir(cargo: &Path, out_dir: &Path, interrupts: &mut Interrupts) -> Result<()> {
    let mut cmd = tokio::process::Command::new(cargo);
    cmd.args(["xtask", "stage", "--profile", "debug", "--out-dir"]);
    cmd.arg(out_dir);
    run_step(cmd, "cargo xtask stage", true, interrupts).await
}

#[cfg(test)]
#[path = "steps_tests.rs"]
mod steps_tests;
