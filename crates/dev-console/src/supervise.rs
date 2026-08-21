//! The supervision sequence (dev.py main(), with the spec's Deltas).

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context as _, Result};
use cosca::containment::Nesting;
use cosca::tokio::{Child, Command};
use cosca::{ContainMode, Stdio};
use tokio::sync::mpsc;

use crate::ansi::{BOLD, RESET, YELLOW};
use crate::banner::{startup_banner, webview_debug_hint, CDP_PORT, VITE_PORT};
use crate::interrupts::Interrupts;
use crate::mux::{pump, Entry, StreamMode};
use crate::policy::{
    bridge_argv, bridge_hard_kill_permitted, elevation_action, grace_timeout_action, grant_access_argv,
    supervision_exit_code, ChildRole, ElevationAction, ExitCause, GraceTimeoutAction, Os, NETWORK_RESET_WARNING,
};
use crate::ready::{port_in_use, wait_for_port, ReadyListener};
use crate::steps;

const SOCKET_READY_TIMEOUT: Duration = Duration::from_secs(15);
const VITE_READY_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const GRACE_TIMEOUT: Duration = Duration::from_secs(10);
/// dev.py joined its prefix threads with timeout=5 (dev.py:352-354) for the
/// same reason: the WarnRecovery bridge keeps its pipes open forever.
const PRINTER_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// dev.py:306-307 parity (`terminate_tree`: `if proc.poll() is not None:
/// return`). The guard must not be deleted as redundant with anything cosca
/// does internally: `terminate_tree`'s `killpg` takes an **unpinned pgid**
/// (bindreams/cosca#54), so signalling an exited child's group can land on an
/// unrelated one. The lone `terminate()` is identity-bound and needs no such
/// guard — which is exactly what makes this one look droppable.
///
/// cosca also refuses a graceful op on Windows once an exit has been *reported*,
/// because its async backend can release the process handle and stop pinning
/// the pid. That is **not** live here: every spawn in this crate sets
/// `executable()` and so takes the raw backend, which owns its handle for the
/// child's whole life. An argv-only spawn added later would re-open it.
pub(crate) fn has_exited(child: &mut Child) -> bool {
    matches!(child.try_wait(), Ok(Some(_)))
}

/// Create the per-run dir `<parent>/<name>`. On a same-second collision (the
/// dir already exists — a concurrent run the Vite-port guard will reject), fall
/// back to `<name>-<pid>` so the doomed run can't truncate the live run's logs.
pub(crate) fn create_run_dir(parent: &Path, name: &str, pid: u32) -> std::io::Result<std::path::PathBuf> {
    std::fs::create_dir_all(parent)?;
    let primary = parent.join(name);
    match std::fs::create_dir(&primary) {
        Ok(()) => Ok(primary),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let alt = parent.join(format!("{name}-{pid}"));
            std::fs::create_dir_all(&alt)?;
            Ok(alt)
        }
        Err(e) => Err(e),
    }
}

pub async fn main() -> ExitCode {
    // FIRST: interrupt ownership (the dev.py try/finally equivalent). From
    // here on Ctrl+C/SIGTERM never kills us by default disposition — every
    // phase below watches `interrupts` and routes through teardown/Drops.
    let mut interrupts = Interrupts::install();
    match run(&mut interrupts).await {
        Ok(code) => code,
        Err(e) => {
            if e.downcast_ref::<steps::Interrupted>().is_some() {
                // Interrupt during preflight: `run_step` already tore the
                // child's tree down, guards Drop on return. Same exit code as
                // a steady-state interrupt.
                return ExitCode::from(supervision_exit_code(ExitCause::Interrupted));
            }
            if let Some(step) = e.downcast_ref::<steps::StepFailed>() {
                // dev.py parity: npm/cargo failures exit with the child's
                // code and no extra line; stage prints its yellow message.
                if let Some(msg) = &step.message {
                    enote!("{YELLOW}{msg}{RESET}");
                }
                return ExitCode::from(step.code.clamp(1, 255) as u8);
            }
            enote!("{YELLOW}dev-console: {e:#}{RESET}");
            ExitCode::FAILURE
        }
    }
}

async fn run(interrupts: &mut Interrupts) -> Result<ExitCode> {
    let repo_root = xtask_lib::repo_root::repo_root()
        .context("run from inside the hole workspace (or via `cargo xtask run hole`)")?;
    // dev.py:425-428 parity: a workspace that isn't hole must be refused
    // before we npm-install into it.
    if !repo_root.join("crates").join("hole").is_dir() {
        eprintln!(
            "Error: run this from the hole project root (crates/hole not found under {})",
            repo_root.display()
        );
        return Ok(ExitCode::FAILURE);
    }
    std::env::set_current_dir(&repo_root).context("cd to repo root")?;

    // Dev-run capture: <repo>/.tmp/dev-run/<datetime>/ with bridge.log +
    // gui.log (trace, native file sinks redirected here) and dev-console.log
    // (this supervisor's status + the runtime mux at info, ANSI stripped).
    let run_parent = repo_root.join(".tmp").join("dev-run");
    let run_dir = create_run_dir(
        &run_parent,
        &crate::policy::dev_run_subdir_name(chrono::Local::now().naive_local()),
        std::process::id(),
    )
    .context("creating dev-run dir")?;
    crate::transcript::set_global(crate::transcript::Transcript::create(&run_dir.join("dev-console.log")));

    // 1. Privilege policy (dev.py §5.10) ==============================================================================
    let euid: Option<u32>;
    #[cfg(unix)]
    {
        // SAFETY: geteuid never fails.
        euid = Some(unsafe { libc::geteuid() });
    }
    #[cfg(windows)]
    {
        euid = None;
    }
    match elevation_action(Os::host(), euid) {
        ElevationAction::WindowsRequireAdmin =>
        {
            #[cfg(windows)]
            if let Err(e) = stepstool::require_elevated() {
                enote!("ERROR: {e}");
                return Ok(ExitCode::FAILURE);
            }
        }
        ElevationAction::PosixErrorRoot => {
            enote!(
                "ERROR: do not run dev mode as root / under sudo.\n\
                 Run `cargo xtask run hole` (no sudo) — dev-console elevates only the\n\
                 bridge itself. Running as root leaves root-owned files in target/."
            );
            return Ok(ExitCode::FAILURE);
        }
        ElevationAction::PosixOk => {}
    }

    // 2. Tools + preflight steps (interrupt-aware; see steps.rs) ======================================================
    let cargo = steps::resolve_tool("cargo")?;
    let npm = steps::resolve_npm()?;
    steps::ensure_node_modules(&npm, interrupts).await?;
    // No workspace build here: dev-console supervises only (#564). The xtask
    // cascade built everything; a standalone run reuses the existing build,
    // which `stage_bindir` (cargo xtask stage) validates.

    // 3. Per-pid stage (guard registered BEFORE mkdir; dev.py §5.11) ==================================================
    let stage_guard = steps::StageDirGuard::register(steps::stage_dir_path(std::process::id()));
    steps::stage_bindir(&cargo, stage_guard.path(), interrupts).await?;

    let bin_name = if cfg!(windows) { "hole.exe" } else { "hole" };
    let bridge_bin = stage_guard.path().join(bin_name);
    let gui_bin = repo_root.join("target").join("debug").join(bin_name);
    let socket_path = std::env::temp_dir().join("hole-dev.sock");
    let state_dir = std::env::temp_dir().join("hole-dev").join("state");
    std::fs::create_dir_all(&state_dir).context("creating bridge state dir")?;

    // 4. Leaked-vite preflight (Delta 7): vite uses strictPort 1420 ===================================================
    if port_in_use(VITE_PORT).await {
        enote!(
            "{YELLOW}Port {VITE_PORT} is already in use — a previous dev run's Vite may have \
             leaked. Kill it (or whatever holds the port) and re-run.{RESET}"
        );
        return Ok(ExitCode::FAILURE);
    }

    // 5. sudo preflight (POSIX; dev.py §5.8) ==========================================================================
    #[cfg(unix)]
    {
        note!("{BOLD}Dev mode needs root for the bridge — caching sudo credentials...{RESET}");
        if let Err(e) = stepstool::prime_sudo() {
            enote!("{YELLOW}{e}{RESET}");
            return Ok(ExitCode::FAILURE);
        }
    }

    // 6. grant-access via the production path (dev.py §5.15) ==========================================================
    note!("{BOLD}Granting IPC access (creates hole group, adds user)...{RESET}");
    let ga = grant_access_argv(Os::host(), &bridge_bin.to_string_lossy());
    // Not a supervised child: it runs to completion here and owns no tree.
    let mut cmd = tokio::process::Command::new(&ga[0]);
    cmd.args(&ga[1..]);
    let status = cmd.status().await.context("spawning bridge grant-access")?;
    if !status.success() {
        let code = status.code().unwrap_or(1);
        enote!("{YELLOW}bridge grant-access failed (exit {code}){RESET}");
        return Ok(ExitCode::from(code.clamp(1, 255) as u8));
    }

    // 7. hole-group session gate (POSIX; dev.py §5.14) ================================================================
    #[cfg(unix)]
    {
        let gid = match crate::group_gate::hole_gid() {
            Ok(g) => g,
            Err(warn) => {
                enote!("{YELLOW}warning: could not look up 'hole' group: {warn}{RESET}");
                None
            }
        };
        if crate::group_gate::missing_hole_group(gid, &crate::group_gate::current_gids()) {
            enote!(
                "\n{YELLOW}Added you to the 'hole' group, but your current login session \
                 predates it,\nso the dashboard can't reach the bridge yet. Log out and back \
                 in (or reboot),\nthen run `cargo xtask run hole` again. One-time per machine. \
                 (`newgrp hole` may also work.){RESET}"
            );
            return Ok(ExitCode::FAILURE);
        }
    }

    // 8. Banner =======================================================================================================
    let sudo_note = if cfg!(windows) { "" } else { "sudo " };
    note!(
        "{}",
        startup_banner(&socket_path, &state_dir, &run_dir, &bridge_bin, &gui_bin, sudo_note).trim_end()
    );
    note!("");

    supervise_children(
        interrupts,
        &npm,
        &bridge_bin,
        &gui_bin,
        &socket_path,
        &state_dir,
        &run_dir,
    )
    .await
}

/// Spawn-and-supervise with a SINGLE exit funnel: whatever the startup or
/// steady state produced, `shutdown` runs over every child that exists
/// (dev.py's `finally`), then the printer is drained (bounded).
async fn supervise_children(
    interrupts: &mut Interrupts,
    npm: &steps::NpmLaunch,
    bridge_bin: &Path,
    gui_bin: &Path,
    socket_path: &Path,
    state_dir: &Path,
    run_dir: &Path,
) -> Result<ExitCode> {
    let (tx, rx) = mpsc::channel::<Entry>(256);
    let (enter_drain_tx, enter_drain_rx) = tokio::sync::oneshot::channel();
    let (finalize_tx, finalize_rx) = tokio::sync::oneshot::channel();
    let mut printer = tokio::spawn(crate::mux::printer(
        rx,
        tokio::io::stdout(),
        crate::transcript::global(),
        enter_drain_rx,
        finalize_rx,
    ));

    let mut bridge: Option<Child> = None;
    let mut vite: Option<Child> = None;
    let mut gui: Option<Child> = None;

    use futures_util::FutureExt as _;
    // The startup+steady body. Early returns are FINE here — the funnel
    // below always runs, on panics too.
    // AssertUnwindSafe: after a panic the funnel touches only the slot
    // Options, which are coherent at every await point.
    let caught = std::panic::AssertUnwindSafe(startup_and_supervise(
        interrupts,
        npm,
        bridge_bin,
        gui_bin,
        socket_path,
        state_dir,
        run_dir,
        &tx,
        &mut bridge,
        &mut vite,
        &mut gui,
    ))
    .catch_unwind()
    .await;
    // We are now shutting down: stop streaming so the trailing entries are
    // collected and emitted in timestamp order (#568). Fired ONCE, before
    // both the panic-arm shutdown and the normal shutdown.
    let _ = enter_drain_tx.send(());
    let outcome: Result<ExitCause> = match caught {
        Ok(outcome) => outcome,
        Err(panic) => {
            // dev.py's `finally` ran on arbitrary exceptions: tear down the
            // children (the root bridge above all) before resuming the panic.
            shutdown(bridge.as_mut(), vite.as_mut(), gui.as_mut()).await;
            std::panic::resume_unwind(panic);
        }
    };

    shutdown(bridge.as_mut(), vite.as_mut(), gui.as_mut()).await;

    drop(tx);
    // Drain. The printer is collecting the post-`enter_drain` tail; on rx
    // close it sorts + flushes. Class-2 bound (external pipes that may never
    // EOF): the WarnRecovery bridge is deliberately never killed, so its pump
    // can hold its sender forever and `rx` never closes. On that timeout fire
    // `finalize` so the printer still sorts + writes what it collected, then
    // re-bound the flush so a wedged stdout can't hang teardown (dev.py
    // join(timeout=5)).
    if tokio::time::timeout(PRINTER_DRAIN_TIMEOUT, &mut printer).await.is_err() {
        let _ = finalize_tx.send(());
        if tokio::time::timeout(PRINTER_DRAIN_TIMEOUT, &mut printer).await.is_err() {
            printer.abort();
        }
    }

    let cause = outcome?;
    Ok(ExitCode::from(supervision_exit_code(cause)))
}

#[allow(clippy::too_many_arguments)] // private seam; the funnel needs the slots
async fn startup_and_supervise(
    interrupts: &mut Interrupts,
    npm: &steps::NpmLaunch,
    bridge_bin: &Path,
    gui_bin: &Path,
    socket_path: &Path,
    state_dir: &Path,
    run_dir: &Path,
    tx: &mpsc::Sender<Entry>,
    bridge_slot: &mut Option<Child>,
    vite_slot: &mut Option<Child>,
    gui_slot: &mut Option<Child>,
) -> Result<ExitCause> {
    // Bridge FIRST: the sudo spawns stay back-to-back behind the preflight
    // cache; Vite's readiness wait can't straddle it (dev.py §5.8).
    let ready = ReadyListener::bind().await.context("binding ready listener")?;
    let argv = bridge_argv(
        Os::host(),
        &bridge_bin.to_string_lossy(),
        &socket_path.to_string_lossy(),
        &state_dir.to_string_lossy(),
        &ready.notify_arg(),
    );
    let mut cmd = Command::new();
    cmd.executable(&argv[0]);
    cmd.args(&argv);
    // Per-sink dev logging: file=trace into the run dir, stderr=info to the
    // terminal. These ride the sudo boundary via SUDO_PRESERVE_ENV.
    for (k, v) in crate::policy::dev_run_child_env(run_dir, crate::policy::DEV_RUN_STDERR_BRIDGE) {
        cmd.env(k, v);
    }
    // stdin=null: an expired sudo timestamp gets EOF and exits non-zero
    // instead of hanging on an invisible prompt (with the session detach in
    // spawn_bridge); also the console-corruption discipline every child gets
    // (dev.py §5.3).
    cmd.stdin(Stdio::null())?;
    cmd.stdout(Stdio::pipe())?;
    cmd.stderr(Stdio::pipe())?;
    let bridge = bridge_slot.insert(spawn_bridge(cmd).context("spawning the bridge")?);
    pump_child_output(bridge, ChildRole::Bridge, StreamMode::EntryBuffered, tx);

    // Ready rendezvous: bridge-exit checked before the token (dev.py polls
    // proc death first); interrupt anywhere tears down via the funnel. The
    // sleep is the class-2 human-failure bound for an out-of-process startup
    // that might never succeed.
    tokio::select! {
        biased;
        status = bridge.wait() => {
            let status = status?;
            // Supervisor status lines print directly (not via the mux
            // printer) — dev.py parity: its prints didn't take the print
            // lock either; a rare interleave with a child entry is accepted.
            // dev.py:578-585 (stdout, like dev.py's print):
            note!(
                "{YELLOW}Bridge exited with code {} (sudo credentials may have expired, or a \
                 restrictive sudoers env_check/env_delete rejected --preserve-env){RESET}",
                status.code().unwrap_or(-1)
            );
            return Ok(ExitCause::StartupFailed);
        }
        _ = interrupts.recv() => return Ok(ExitCause::Interrupted),
        r = ready.wait() => {
            r.context("ready listener failed")?;
        }
        _ = tokio::time::sleep(SOCKET_READY_TIMEOUT) => {
            note!("{YELLOW}Bridge did not signal readiness within {}s{RESET}", SOCKET_READY_TIMEOUT.as_secs());
            return Ok(ExitCause::StartupFailed);
        }
    }

    // Vite (after the bridge). FORCE_COLOR=1 restores the colors a piped
    // child disables (Delta 3).
    let mut cmd = Command::new();
    cmd.executable(npm.program());
    cmd.args(npm.full_argv(&["run", "dev"]));
    cmd.env("FORCE_COLOR", "1");
    cmd.stdin(Stdio::null())?;
    cmd.stdout(Stdio::pipe())?;
    cmd.stderr(Stdio::pipe())?;
    cmd.kill_on_drop(true).contain().nesting(Nesting::Mark);
    let vite = vite_slot.insert(cmd.spawn().context("spawning vite (npm run dev)")?);
    pump_child_output(vite, ChildRole::Vite, StreamMode::PerLine, tx);

    // biased + exit-arm-first: a dead Vite is reported as such, never as a
    // false "port up" from an unrelated listener (dev.py:246-248 checks
    // poll() before each probe round).
    tokio::select! {
        biased;
        status = vite.wait() => {
            note!("{YELLOW}Vite exited with code {}{RESET}", status?.code().unwrap_or(-1));
            return Ok(ExitCause::StartupFailed);
        }
        _ = interrupts.recv() => return Ok(ExitCause::Interrupted),
        up = wait_for_port(VITE_PORT, VITE_READY_TIMEOUT) => {
            if !up {
                note!("{YELLOW}Vite did not start on port {VITE_PORT} within {}s{RESET}", VITE_READY_TIMEOUT.as_secs());
                return Ok(ExitCause::StartupFailed);
            }
        }
    }

    // GUI (as the invoking user), webview debug plumbing (dev.py §5.16):
    // append to WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS, never overwrite.
    let existing = std::env::var("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS").unwrap_or_default();
    let cdp = format!("--remote-debugging-port={CDP_PORT}");
    let webview_args = if existing.trim().is_empty() {
        cdp
    } else {
        format!("{} {cdp}", existing.trim())
    };
    if !webview_debug_hint().is_empty() {
        note!("{}", webview_debug_hint());
    }
    let mut cmd = Command::new();
    cmd.executable(gui_bin);
    cmd.arg(gui_bin);
    cmd.env("HOLE_BRIDGE_SOCKET", socket_path);
    cmd.env("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", webview_args);
    for (k, v) in crate::policy::dev_run_child_env(run_dir, crate::policy::DEV_RUN_STDERR_GUI) {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::null())?;
    cmd.stdout(Stdio::pipe())?;
    cmd.stderr(Stdio::pipe())?;
    cmd.kill_on_drop(true).contain().nesting(Nesting::Mark);
    let gui = gui_slot.insert(cmd.spawn().context("spawning the GUI")?);
    pump_child_output(gui, ChildRole::Gui, StreamMode::EntryBuffered, tx);

    // Steady state: first exit / Ctrl+C / SIGTERM wins (replaces dev.py's
    // done.wait(0.5) poll loop and reaper threads — tokio makes them events).
    Ok(tokio::select! {
        status = bridge.wait() => exited("bridge", status),
        status = vite.wait() => exited("vite", status),
        status = gui.wait() => exited("client", status),
        _ = interrupts.recv() => ExitCause::Interrupted,
    })
}

/// Steady-state child exit → cause. A CLEAN exit (e.g. the user quit the
/// GUI from the tray) ends the session with code 0, dev.py parity; a failed
/// exit is Delta 1's non-zero path.
fn exited(name: &str, status: Result<std::process::ExitStatus, cosca::error::Error>) -> ExitCause {
    match status {
        Ok(s) if s.success() => {
            note!("{YELLOW}{name} exited; shutting down{RESET}");
            ExitCause::ChildExitedClean
        }
        Ok(s) => {
            enote!("{YELLOW}{name} exited unexpectedly ({s}){RESET}");
            ExitCause::ChildFailed
        }
        Err(e) => {
            enote!("{YELLOW}{name} exited unexpectedly (wait error: {e}){RESET}");
            ExitCause::ChildFailed
        }
    }
}

/// Graceful → bounded wait → policy action, per child (dev.py shutdown(),
/// §5.7). Tolerates partially-started runs (None slots).
async fn shutdown(bridge: Option<&mut Child>, vite: Option<&mut Child>, gui: Option<&mut Child>) {
    if bridge.is_none() && vite.is_none() && gui.is_none() {
        return;
    }
    note!("\n{BOLD}Shutting down...{RESET}");
    if let Some(bridge) = bridge {
        // See has_exited: an exited bridge means a possibly-recycled pgid and,
        // on Windows, a released handle — never signal it, and there is
        // nothing left to grace-wait for.
        if !has_exited(bridge) {
            // The group signal, not the lone one: on POSIX the bridge is a
            // sudo wrapper that relays SIGTERM to the root bridge whose
            // handler runs route/DNS teardown. A member this process may not
            // signal is expected there (the root-owned bridge behind sudo),
            // and is non-fatal — but it is logged rather than discarded.
            if let Err(e) = bridge.terminate_tree() {
                // Transcript only, not the terminal: expected on POSIX, where
                // the root-owned bridge behind sudo cannot be probed. Dropping
                // the typed error silently is what this avoids.
                crate::transcript::global()
                    .write_line(&format!("bridge group SIGTERM did not reach every member: {e}"));
            }
            // Class-2 bound: an out-of-process exit that might never come
            // (10s, dev.py parity).
            if tokio::time::timeout(GRACE_TIMEOUT, bridge.wait()).await.is_err() {
                match grace_timeout_action(ChildRole::Bridge, Os::host()) {
                    GraceTimeoutAction::WarnRecovery => enote!("{NETWORK_RESET_WARNING}"),
                    GraceTimeoutAction::HardKill if bridge_hard_kill_permitted(Os::host()) => {
                        if let Err(e) = bridge.kill_tree() {
                            enote!("{YELLOW}bridge tree kill: {e}{RESET}");
                        }
                        let _ = bridge.wait().await;
                    }
                    // Unreachable while the policy is correct — which is the
                    // point. The assert reports a regression in debug; this arm
                    // is what still refuses it in release, where the assert is
                    // gone. Falling through would SIGKILL the sudo relay and
                    // orphan the root-owned bridge.
                    GraceTimeoutAction::HardKill => {
                        debug_assert!(
                            bridge_hard_kill_permitted(Os::host()),
                            "policy regression: grace_timeout_action routed the POSIX bridge to a hard kill; \
                             killing through the sudo relay kills sudo and orphans the root bridge"
                        );
                        enote!("{NETWORK_RESET_WARNING}");
                    }
                }
            }
        }
    }
    for (role, slot) in [(ChildRole::Vite, vite), (ChildRole::Gui, gui)] {
        if let Some(gc) = slot {
            teardown_grouped(gc, role).await;
        }
    }
}

/// Graceful group signal → bounded wait → hard tree-kill. Shared by
/// shutdown() and the grandchild-reap integration test.
pub(crate) async fn teardown_grouped(child: &mut Child, role: ChildRole) {
    // See has_exited. Lingering group members (if any) are reaped by the Drop
    // backstop's tree kill.
    if has_exited(child) {
        return;
    }
    // The group signal, not the lone one: Vite is `npm run dev`, and npm exits
    // on SIGTERM without forwarding it — a lone signal would satisfy the grace
    // wait while node and esbuild survived to be SIGKILLed by the Drop
    // backstop, silently downgrading a graceful teardown to a hard kill.
    if let Err(e) = child.terminate_tree() {
        // Every error from this call means NO signal went out and the tree is
        // still running, so the grace wait below is about to look like a stall
        // with no cause. Say which it was.
        enote!("{YELLOW}{role:?} did not receive the cooperative signal: {e}{RESET}");
    }
    // Class-2 bound: out-of-process exit that may never come (10s).
    if tokio::time::timeout(GRACE_TIMEOUT, child.wait()).await.is_err() {
        debug_assert_eq!(grace_timeout_action(role, Os::host()), GraceTimeoutAction::HardKill);
        // Signal-only: the wait below is what reaps, and it must run even if
        // the tree teardown reported a refusal — that report is what tells us
        // whether the root actually died.
        if let Err(e) = child.kill_tree() {
            enote!("{YELLOW}{role:?} tree kill did not reach every member: {e}{RESET}");
        }
        let _ = child.wait().await;
    }
}

/// `ContainMode::Session` is the dev.py `start_new_session` parity (dev.py:296):
/// on POSIX it is `setsid`, detaching the controlling TTY so an expired-timestamp
/// sudo cannot prompt on /dev/tty (it EOFs on the null stdin instead) and making
/// the child a group leader for the graceful killpg; on Windows it takes the same
/// root flags as `Strongest`, so the bridge is its own console group inside a
/// kill-on-close job (a crashed supervisor can no longer leak a routing-active
/// bridge, Delta 6).
///
/// `Nesting::Opaque` on both platforms: the mark would stop the bridge's own
/// garter from containing its plugin chains, which must nest inside this tree.
fn spawn_bridge(mut cmd: Command) -> Result<Child, cosca::error::Error> {
    // Drop-kill exactly when the policy would force-kill this child anyway. One
    // owner for both decisions, so they cannot drift: on POSIX a SIGKILL through
    // the sudo relay kills sudo and silently ORPHANS the root bridge.
    let kill_on_drop = grace_timeout_action(ChildRole::Bridge, Os::host()) == GraceTimeoutAction::HardKill;
    cmd.kill_on_drop(kill_on_drop)
        .contain_with(ContainMode::Session)
        .nesting(Nesting::Opaque);
    cmd.spawn()
}

/// Two pumps per child — a DECIDED divergence from dev.py's OS-level
/// `stderr=subprocess.STDOUT` merge (signed off 2026-06-11): per-stream
/// entries stay atomic via the single printer, but a child's stdout↔stderr
/// write order is not preserved. Verified premise: bridge/GUI tracing AND
/// panic output land on stderr only (crates/common/src/logging.rs), so
/// multi-line entries never split across the two pipes today.
fn pump_child_output(child: &mut Child, role: ChildRole, mode: StreamMode, tx: &mpsc::Sender<Entry>) {
    if let Some(stdout) = child.stdout() {
        tokio::spawn(pump(stdout, mode, role.prefix(), tx.clone()));
    }
    if let Some(stderr) = child.stderr() {
        tokio::spawn(pump(stderr, mode, role.prefix(), tx.clone()));
    }
}

#[cfg(test)]
#[path = "supervise_tests.rs"]
mod supervise_tests;
