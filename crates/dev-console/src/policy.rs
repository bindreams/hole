//! Pure supervision policy: every decision dev.py made with platform
//! branches, as data — testable on any host (the PR #456 strategy-as-data
//! pattern).

/// Env vars carried across the sudo boundary into the elevated bridge — log
/// filtering, backtraces, per-sink levels, and the dev-run log dir. sudo
/// scrubs the environment otherwise, silently changing dev logging behavior.
pub const SUDO_PRESERVE_ENV: [&str; 6] = [
    "RUST_LOG",
    "RUST_BACKTRACE",
    "HOLE_BRIDGE_LOG",
    "HOLE_LOG",
    "HOLE_LOG_STDERR",
    "HOLE_LOG_DIR",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Posix,
    Windows,
}

impl Os {
    pub fn host() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Posix
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElevationAction {
    /// Windows: require an already-elevated shell (UAC token-based; nothing
    /// is dropped, all children inherit).
    WindowsRequireAdmin,
    /// POSIX as root: refuse — dev mode runs unprivileged and elevates only
    /// the bridge; running as root re-poisons target/ (#452).
    PosixErrorRoot,
    /// POSIX as a normal user: the supported path.
    PosixOk,
}

/// `euid` is None on Windows (unused there).
pub fn elevation_action(os: Os, euid: Option<u32>) -> ElevationAction {
    match os {
        Os::Windows => ElevationAction::WindowsRequireAdmin,
        Os::Posix if euid == Some(0) => ElevationAction::PosixErrorRoot,
        Os::Posix => ElevationAction::PosixOk,
    }
}

fn sudo_prefix(os: Os) -> Vec<String> {
    match os {
        Os::Windows => vec![],
        Os::Posix => vec![
            "sudo".into(),
            // One owner for the literal: stepstool builds the same argument
            // for its sudo_command — drift between the two would silently
            // change which env survives the scrub.
            stepstool::preserve_env_arg(&SUDO_PRESERVE_ENV),
        ],
    }
}

/// argv for `hole bridge grant-access`, sudo-prefixed on POSIX.
pub fn grant_access_argv(os: Os, bridge_bin: &str) -> Vec<String> {
    let mut argv = sudo_prefix(os);
    argv.extend([bridge_bin, "bridge", "grant-access"].map(String::from));
    argv
}

/// argv for `hole bridge run`, sudo-prefixed on POSIX.
pub fn bridge_argv(os: Os, bridge_bin: &str, socket: &str, state_dir: &str, ready_notify: &str) -> Vec<String> {
    let mut argv = sudo_prefix(os);
    argv.extend(
        [
            bridge_bin,
            "bridge",
            "run",
            "--socket-path",
            socket,
            "--state-dir",
            state_dir,
            "--ready-notify",
            ready_notify,
        ]
        .map(String::from),
    );
    argv
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildRole {
    Bridge,
    Vite,
    Gui,
}

impl ChildRole {
    /// Colored, width-aligned display label (dev.py: `[bridge]` cyan,
    /// `[client]` magenta, `[  vite]` yellow).
    pub fn prefix(self) -> String {
        use crate::ansi::{BOLD, CYAN, MAGENTA, RESET, YELLOW};
        let (color, label) = match self {
            Self::Bridge => (CYAN, "bridge"),
            Self::Gui => (MAGENTA, "client"),
            Self::Vite => (YELLOW, "  vite"),
        };
        format!("{color}{BOLD}[{label}]{RESET} ")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraceTimeoutAction {
    HardKill,
    /// POSIX bridge only: an unprivileged parent cannot force-kill through
    /// sudo (pty/monitor mode on sudo >= 1.9.14 puts the bridge in its own
    /// session; sudo cannot relay SIGKILL). Print the network-reset recovery
    /// pointer instead (dev.py §5.7).
    WarnRecovery,
}

pub fn grace_timeout_action(role: ChildRole, os: Os) -> GraceTimeoutAction {
    match (role, os) {
        (ChildRole::Bridge, Os::Posix) => GraceTimeoutAction::WarnRecovery,
        _ => GraceTimeoutAction::HardKill,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitCause {
    /// A supervised child exited with a FAILURE status (Delta 1: non-zero).
    ChildFailed,
    /// A supervised child exited cleanly (e.g. the user quit the GUI from
    /// the tray — a normal way to end a dev session). dev.py exits 0 here.
    ChildExitedClean,
    /// A readiness phase failed (bridge/vite died or timed out) — dev.py
    /// exits 1 from these paths.
    StartupFailed,
    /// Ctrl+C / SIGTERM — orderly user stop.
    Interrupted,
}

pub fn supervision_exit_code(cause: ExitCause) -> u8 {
    match cause {
        ExitCause::ChildFailed | ExitCause::StartupFailed => 1,
        ExitCause::ChildExitedClean | ExitCause::Interrupted => 0,
    }
}

/// The POSIX bridge-timeout recovery message, verbatim from dev.py:344-349
/// (fidelity item 12 demands the exact text; pinned by a test).
pub const NETWORK_RESET_WARNING: &str = "\x1b[33mThe bridge did not exit within 10s and may still be running as root with routing changes in place.\nRun `sudo scripts/network-reset.py` to restore connectivity.\x1b[0m";

// Dev-run log filtering ===============================================================================================

/// First-party crates pinned to TRACE in the dev-run file logs. Deps stay at
/// the `debug` default. Mirrors `hole_test_observability::DEFAULT_FILTER`'s
/// crate list (kept separate: that crate is a dev-dep and `util` is
/// deliberately Hole-agnostic, so there is no shared home without a heavyweight
/// dep — a new first-party crate must be added to both lists).
const DEV_RUN_TRACE_CRATES: &[&str] = &[
    "hole",
    "hole_common",
    "hole_bridge",
    "tun_engine",
    "tun_engine_macros",
    "garter",
    "garter_bin",
    "galoshes",
    "ex_ray",
    "dump",
    "dump_macros",
    "handle_holders",
];

/// `HOLE_LOG` value for the dev-run file sink: deps at `debug`, first-party at
/// `trace`.
pub fn dev_run_file_directives() -> String {
    let mut s = String::from("debug");
    for c in DEV_RUN_TRACE_CRATES {
        s.push(',');
        s.push_str(c);
        s.push_str("=trace");
    }
    s
}

/// `HOLE_LOG_STDERR` for the bridge / GUI terminal view — today's info level.
pub const DEV_RUN_STDERR_BRIDGE: &str = "hole_bridge=info";
pub const DEV_RUN_STDERR_GUI: &str = "hole=info";

/// The per-sink log env a dev child (bridge or GUI) gets: file=trace into the
/// run dir, stderr=`stderr_directive` to the terminal. Returned as (name, value)
/// pairs so the caller applies them with `Command::env`.
pub fn dev_run_child_env(run_dir: &std::path::Path, stderr_directive: &str) -> Vec<(&'static str, std::ffi::OsString)> {
    vec![
        ("HOLE_LOG_DIR", run_dir.as_os_str().to_owned()),
        ("HOLE_LOG", dev_run_file_directives().into()),
        ("HOLE_LOG_STDERR", stderr_directive.into()),
    ]
}

/// Filesystem-safe, sortable local timestamp for the dev-run subdir.
pub fn dev_run_subdir_name(now: chrono::NaiveDateTime) -> String {
    now.format("%Y-%m-%d_%H-%M-%S").to_string()
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod policy_tests;
