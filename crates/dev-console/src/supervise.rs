//! The supervision sequence (dev.py main(), with the spec's Deltas).

use std::path::Path;
use std::process::{ExitCode, Stdio};
use std::time::Duration;

use anyhow::{Context as _, Result};
use kill_group::{GroupedChild, Nesting};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

use crate::ansi::{BOLD, RESET, YELLOW};
use crate::banner::{startup_banner, webview_debug_hint, CDP_PORT, VITE_PORT};
use crate::interrupts::Interrupts;
use crate::mux::{pump, Entry, StreamMode};
use crate::policy::{
    bridge_argv, elevation_action, grace_timeout_action, grant_access_argv, supervision_exit_code, ChildRole,
    ElevationAction, ExitCause, GraceTimeoutAction, Os, NETWORK_RESET_WARNING,
};
use crate::ready::{port_in_use, wait_for_port, ReadyListener};
use crate::steps;

const SOCKET_READY_TIMEOUT: Duration = Duration::from_secs(15);
const VITE_READY_TIMEOUT: Duration = Duration::from_secs(30);
const GRACE_TIMEOUT: Duration = Duration::from_secs(10);
/// dev.py joined its prefix threads with timeout=5 (dev.py:352-354) for the
/// same reason: the WarnRecovery bridge keeps its pipes open forever.
const PRINTER_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// The bridge child differs per platform — see the spec's spawn table.
enum BridgeChild {
    /// POSIX: sudo-wrapped, own SESSION (setsid — controlling-TTY detach is
    /// the sudo-prompt scar fix; also makes it a pgid leader for the
    /// graceful killpg). NOT a kill-group: Drop's SIGKILL would kill sudo
    /// and silently ORPHAN the root bridge; and the nesting mark would stop
    /// the bridge's garter from creating plugin kill-groups.
    /// `pgid` is captured at spawn (child.id() goes None after reaping, but
    /// the group may still need signalling).
    #[cfg(unix)]
    Posix { child: Child, pgid: u32 },
    /// Windows: kill-on-close job, Nesting::Opaque (the bridge's own garter
    /// keeps creating plugin groups, which nest inside this job). A crashed
    /// supervisor can no longer leak a routing-active bridge (Delta 6).
    #[cfg(windows)]
    Windows(GroupedChild),
}

/// dev.py:306-307 parity (`terminate_tree`: `if proc.poll() is not None:
/// return`): a reaped child's pid — and therefore its pgid — may already
/// have been recycled by the OS, so signalling it can land on an unrelated
/// process group. `term_group`'s contract requires holding an un-reaped
/// leader. tokio's `wait()` fuses: after reaping, `id()` is `None`.
pub(crate) fn is_reaped(child: &Child) -> bool {
    child.id().is_none()
}

impl BridgeChild {
    fn child_mut(&mut self) -> &mut Child {
        match self {
            #[cfg(unix)]
            Self::Posix { child, .. } => child,
            #[cfg(windows)]
            Self::Windows(gc) => &mut gc.child,
        }
    }

    fn signal_term(&mut self) {
        match self {
            #[cfg(unix)]
            Self::Posix { pgid, .. } => {
                // killpg(SIGTERM) with kill-group's ESRCH/EPERM semantics
                // (EPERM → direct-to-sudo fallback; sudo relays SIGTERM to
                // the bridge whose handler runs route/DNS teardown).
                let _ = kill_group::term_group(*pgid);
            }
            #[cfg(windows)]
            Self::Windows(gc) => {
                let _ = gc.signal_group_term();
            }
        }
    }

    async fn hard_kill(&mut self) {
        match self {
            #[cfg(unix)]
            Self::Posix { .. } => {
                // Policy (grace_timeout_action) routes the POSIX bridge to
                // WarnRecovery, never here; a no-op (not a panic) keeps a
                // policy bug from also breaking teardown.
                debug_assert!(false, "policy: POSIX bridge is never force-killed");
            }
            #[cfg(windows)]
            Self::Windows(gc) => {
                gc.kill_tree().await;
            }
        }
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
                // Interrupt during preflight: children got the console
                // signal, guards Drop on return. Same exit code as a
                // steady-state interrupt.
                return ExitCode::from(supervision_exit_code(ExitCause::Interrupted));
            }
            if let Some(step) = e.downcast_ref::<steps::StepFailed>() {
                // dev.py parity: npm/cargo failures exit with the child's
                // code and no extra line; stage prints its yellow message.
                if let Some(msg) = &step.message {
                    eprintln!("{YELLOW}{msg}{RESET}");
                }
                return ExitCode::from(step.code.clamp(1, 255) as u8);
            }
            eprintln!("{YELLOW}dev-console: {e:#}{RESET}");
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
                eprintln!("ERROR: {e}");
                return Ok(ExitCode::FAILURE);
            }
        }
        ElevationAction::PosixErrorRoot => {
            eprintln!(
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
    let npm = steps::resolve_tool("npm")?;
    steps::ensure_node_modules(&npm, interrupts).await?;
    steps::cargo_build(&cargo, interrupts).await?;

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
        eprintln!(
            "{YELLOW}Port {VITE_PORT} is already in use — a previous dev run's Vite may have \
             leaked. Kill it (or whatever holds the port) and re-run.{RESET}"
        );
        return Ok(ExitCode::FAILURE);
    }

    // 5. sudo preflight (POSIX; dev.py §5.8) ==========================================================================
    #[cfg(unix)]
    {
        println!("{BOLD}Dev mode needs root for the bridge — caching sudo credentials...{RESET}");
        if let Err(e) = stepstool::prime_sudo() {
            eprintln!("{YELLOW}{e}{RESET}");
            return Ok(ExitCode::FAILURE);
        }
    }

    // 6. grant-access via the production path (dev.py §5.15) ==========================================================
    println!("{BOLD}Granting IPC access (creates hole group, adds user)...{RESET}");
    let ga = grant_access_argv(Os::host(), &bridge_bin.to_string_lossy());
    let mut cmd = Command::new(&ga[0]);
    cmd.args(&ga[1..]);
    let status = cmd.status().await.context("spawning bridge grant-access")?;
    if !status.success() {
        let code = status.code().unwrap_or(1);
        eprintln!("{YELLOW}bridge grant-access failed (exit {code}){RESET}");
        return Ok(ExitCode::from(code.clamp(1, 255) as u8));
    }

    // 7. hole-group session gate (POSIX; dev.py §5.14) ================================================================
    #[cfg(unix)]
    {
        let gid = match crate::group_gate::hole_gid() {
            Ok(g) => g,
            Err(warn) => {
                eprintln!("{YELLOW}warning: could not look up 'hole' group: {warn}{RESET}");
                None
            }
        };
        if crate::group_gate::missing_hole_group(gid, &crate::group_gate::current_gids()) {
            eprintln!(
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
    print!(
        "{}",
        startup_banner(&socket_path, &state_dir, &bridge_bin, &gui_bin, sudo_note)
    );
    println!();

    supervise_children(interrupts, &npm, &bridge_bin, &gui_bin, &socket_path, &state_dir).await
}

/// Spawn-and-supervise with a SINGLE exit funnel: whatever the startup or
/// steady state produced, `shutdown` runs over every child that exists
/// (dev.py's `finally`), then the printer is drained (bounded).
async fn supervise_children(
    interrupts: &mut Interrupts,
    npm: &Path,
    bridge_bin: &Path,
    gui_bin: &Path,
    socket_path: &Path,
    state_dir: &Path,
) -> Result<ExitCode> {
    let (tx, rx) = mpsc::channel::<Entry>(256);
    let mut printer = tokio::spawn(crate::mux::printer(rx, tokio::io::stdout()));

    let mut bridge: Option<BridgeChild> = None;
    let mut vite: Option<GroupedChild> = None;
    let mut gui: Option<GroupedChild> = None;

    use futures_util::FutureExt as _;
    // The startup+steady body. Early returns are FINE here — the funnel
    // below always runs, on panics too.
    // AssertUnwindSafe: after a panic the funnel touches only the slot
    // Options, which are coherent at every await point.
    let outcome: Result<ExitCause> = match std::panic::AssertUnwindSafe(startup_and_supervise(
        interrupts,
        npm,
        bridge_bin,
        gui_bin,
        socket_path,
        state_dir,
        &tx,
        &mut bridge,
        &mut vite,
        &mut gui,
    ))
    .catch_unwind()
    .await
    {
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
    // Class-2 bound (external pipes that may never EOF): the WarnRecovery
    // bridge is deliberately never killed, so its pump can hold its sender
    // forever; drain what's buffered, then abandon (dev.py join(timeout=5)).
    if tokio::time::timeout(PRINTER_DRAIN_TIMEOUT, &mut printer).await.is_err() {
        printer.abort();
    }

    let cause = outcome?;
    Ok(ExitCode::from(supervision_exit_code(cause)))
}

#[allow(clippy::too_many_arguments)] // private seam; the funnel needs the slots
async fn startup_and_supervise(
    interrupts: &mut Interrupts,
    npm: &Path,
    bridge_bin: &Path,
    gui_bin: &Path,
    socket_path: &Path,
    state_dir: &Path,
    tx: &mpsc::Sender<Entry>,
    bridge_slot: &mut Option<BridgeChild>,
    vite_slot: &mut Option<GroupedChild>,
    gui_slot: &mut Option<GroupedChild>,
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
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    // stdin=null: an expired sudo timestamp gets EOF and exits non-zero
    // instead of hanging on an invisible prompt (with the setsid TTY detach
    // in spawn_bridge); also the console-corruption discipline every child
    // gets (dev.py §5.3).
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let bridge = bridge_slot.insert(spawn_bridge(cmd).context("spawning the bridge")?);
    pump_child_output(bridge.child_mut(), ChildRole::Bridge, StreamMode::EntryBuffered, tx);

    // Ready rendezvous: bridge-exit checked before the token (dev.py polls
    // proc death first); interrupt anywhere tears down via the funnel. The
    // sleep is the class-2 human-failure bound for an out-of-process startup
    // that might never succeed.
    tokio::select! {
        biased;
        status = bridge.child_mut().wait() => {
            let status = status?;
            // Supervisor status lines print directly (not via the mux
            // printer) — dev.py parity: its prints didn't take the print
            // lock either; a rare interleave with a child entry is accepted.
            // dev.py:578-585 (stdout, like dev.py's print):
            println!(
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
            println!("{YELLOW}Bridge did not signal readiness within {}s{RESET}", SOCKET_READY_TIMEOUT.as_secs());
            return Ok(ExitCause::StartupFailed);
        }
    }

    // Vite (after the bridge). FORCE_COLOR=1 restores the colors a piped
    // child disables (Delta 3).
    let mut cmd = Command::new(npm);
    cmd.args(["run", "dev"]);
    cmd.env("FORCE_COLOR", "1");
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.kill_on_drop(true);
    let vite = vite_slot.insert(GroupedChild::spawn(&mut cmd, Nesting::Mark).context("spawning vite (npm run dev)")?);
    pump_child_output(&mut vite.child, ChildRole::Vite, StreamMode::PerLine, tx);

    // biased + exit-arm-first: a dead Vite is reported as such, never as a
    // false "port up" from an unrelated listener (dev.py:246-248 checks
    // poll() before each probe round).
    tokio::select! {
        biased;
        status = vite.child.wait() => {
            println!("{YELLOW}Vite exited with code {}{RESET}", status?.code().unwrap_or(-1));
            return Ok(ExitCause::StartupFailed);
        }
        _ = interrupts.recv() => return Ok(ExitCause::Interrupted),
        up = wait_for_port(VITE_PORT, VITE_READY_TIMEOUT) => {
            if !up {
                println!("{YELLOW}Vite did not start on port {VITE_PORT} within {}s{RESET}", VITE_READY_TIMEOUT.as_secs());
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
        println!("{}", webview_debug_hint());
    }
    let mut cmd = Command::new(gui_bin);
    cmd.arg("--show-dashboard");
    cmd.env("HOLE_BRIDGE_SOCKET", socket_path);
    cmd.env("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", webview_args);
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.kill_on_drop(true);
    let gui = gui_slot.insert(GroupedChild::spawn(&mut cmd, Nesting::Mark).context("spawning the GUI")?);
    pump_child_output(&mut gui.child, ChildRole::Gui, StreamMode::EntryBuffered, tx);

    // Steady state: first exit / Ctrl+C / SIGTERM wins (replaces dev.py's
    // done.wait(0.5) poll loop and reaper threads — tokio makes them events).
    Ok(tokio::select! {
        status = bridge.child_mut().wait() => exited("bridge", status),
        status = vite.child.wait() => exited("vite", status),
        status = gui.child.wait() => exited("client", status),
        _ = interrupts.recv() => ExitCause::Interrupted,
    })
}

/// Steady-state child exit → cause. A CLEAN exit (e.g. the user quit the
/// GUI from the tray) ends the session with code 0, dev.py parity; a failed
/// exit is Delta 1's non-zero path.
fn exited(name: &str, status: std::io::Result<std::process::ExitStatus>) -> ExitCause {
    match status {
        Ok(s) if s.success() => {
            println!("{YELLOW}{name} exited; shutting down{RESET}");
            ExitCause::ChildExitedClean
        }
        Ok(s) => {
            eprintln!("{YELLOW}{name} exited unexpectedly ({s}){RESET}");
            ExitCause::ChildFailed
        }
        Err(e) => {
            eprintln!("{YELLOW}{name} exited unexpectedly (wait error: {e}){RESET}");
            ExitCause::ChildFailed
        }
    }
}

/// Graceful → bounded wait → policy action, per child (dev.py shutdown(),
/// §5.7). Tolerates partially-started runs (None slots).
async fn shutdown(bridge: Option<&mut BridgeChild>, vite: Option<&mut GroupedChild>, gui: Option<&mut GroupedChild>) {
    if bridge.is_none() && vite.is_none() && gui.is_none() {
        return;
    }
    println!("\n{BOLD}Shutting down...{RESET}");
    if let Some(bridge) = bridge {
        // dev.py poll() guard (see is_reaped): a reaped bridge means a
        // possibly-recycled pgid — never signal it, and there is nothing
        // left to grace-wait for.
        if !is_reaped(bridge.child_mut()) {
            bridge.signal_term();
            // Class-2 bound: an out-of-process exit that might never come
            // (10s, dev.py parity).
            if tokio::time::timeout(GRACE_TIMEOUT, bridge.child_mut().wait())
                .await
                .is_err()
            {
                match grace_timeout_action(ChildRole::Bridge, Os::host()) {
                    GraceTimeoutAction::WarnRecovery => eprintln!("{NETWORK_RESET_WARNING}"),
                    GraceTimeoutAction::HardKill => bridge.hard_kill().await,
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
pub(crate) async fn teardown_grouped(gc: &mut GroupedChild, role: ChildRole) {
    // dev.py poll() parity: a reaped leader means a possibly-recycled pgid —
    // never signal it. Lingering group members (if any) are reaped by the
    // Drop backstop's group kill, accepting kill-group's documented
    // stored-pgid semantics there (garter parity).
    if is_reaped(&gc.child) {
        return;
    }
    let _ = gc.signal_group_term();
    // Class-2 bound: out-of-process exit that may never come (10s).
    if tokio::time::timeout(GRACE_TIMEOUT, gc.child.wait()).await.is_err() {
        debug_assert_eq!(grace_timeout_action(role, Os::host()), GraceTimeoutAction::HardKill);
        gc.kill_tree().await;
    }
}

fn spawn_bridge(mut cmd: Command) -> std::io::Result<BridgeChild> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        // Full new session (dev.py start_new_session parity, dev.py:296):
        // detaches the controlling TTY so an expired-timestamp sudo cannot
        // prompt on /dev/tty (it EOFs on the null stdin instead), and makes
        // the child a process-group leader for the graceful killpg.
        // SAFETY: setsid is async-signal-safe and the closure does nothing
        // else (last_os_error only reads errno).
        unsafe {
            cmd.as_std_mut().pre_exec(|| {
                // A failed setsid would silently break the pgid==pid leader
                // assumption killpg relies on; failing the spawn surfaces it.
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn()?;
        let pgid = child.id().expect("freshly spawned child has a pid");
        Ok(BridgeChild::Posix { child, pgid })
    }
    #[cfg(windows)]
    {
        cmd.kill_on_drop(true);
        Ok(BridgeChild::Windows(GroupedChild::spawn(&mut cmd, Nesting::Opaque)?))
    }
}

/// Two pumps per child — a DECIDED divergence from dev.py's OS-level
/// `stderr=subprocess.STDOUT` merge (signed off 2026-06-11): per-stream
/// entries stay atomic via the single printer, but a child's stdout↔stderr
/// write order is not preserved. Verified premise: bridge/GUI tracing AND
/// panic output land on stderr only (crates/common/src/logging.rs), so
/// multi-line entries never split across the two pipes today.
fn pump_child_output(child: &mut Child, role: ChildRole, mode: StreamMode, tx: &mpsc::Sender<Entry>) {
    if let Some(stdout) = child.stdout.take() {
        tokio::spawn(pump(stdout, mode, role.prefix(), tx.clone()));
    }
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(pump(stderr, mode, role.prefix(), tx.clone()));
    }
}

#[cfg(test)]
#[path = "supervise_tests.rs"]
mod supervise_tests;
