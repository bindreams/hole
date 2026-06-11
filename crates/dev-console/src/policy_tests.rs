use crate::policy::*;

// Elevation matrix (ports dev_tests.py:50-86) =========================================================================

#[skuld::test]
fn windows_requires_admin_regardless_of_euid() {
    assert_eq!(
        elevation_action(Os::Windows, None),
        ElevationAction::WindowsRequireAdmin
    );
}

#[skuld::test]
fn posix_root_is_refused() {
    assert_eq!(elevation_action(Os::Posix, Some(0)), ElevationAction::PosixErrorRoot);
}

#[skuld::test]
fn posix_user_proceeds() {
    assert_eq!(elevation_action(Os::Posix, Some(501)), ElevationAction::PosixOk);
}

// argv builders (ports dev_tests.py:87-110, incl. the exact preserve-env literal) =====================================

#[skuld::test]
fn grant_access_argv_posix() {
    let argv = grant_access_argv(Os::Posix, "/stage/hole");
    assert_eq!(
        argv,
        [
            "sudo",
            "--preserve-env=RUST_LOG,RUST_BACKTRACE,HOLE_BRIDGE_LOG",
            "/stage/hole",
            "bridge",
            "grant-access"
        ]
    );
}

#[skuld::test]
fn grant_access_argv_windows_has_no_sudo() {
    assert_eq!(
        grant_access_argv(Os::Windows, "C:\\stage\\hole.exe"),
        ["C:\\stage\\hole.exe", "bridge", "grant-access"]
    );
}

#[skuld::test]
fn bridge_argv_posix_includes_ready_notify() {
    let argv = bridge_argv(
        Os::Posix,
        "/stage/hole",
        "/tmp/hole-dev.sock",
        "/tmp/hole-dev/state",
        "127.0.0.1:5000/tok",
    );
    assert_eq!(
        argv,
        [
            "sudo",
            "--preserve-env=RUST_LOG,RUST_BACKTRACE,HOLE_BRIDGE_LOG",
            "/stage/hole",
            "bridge",
            "run",
            "--socket-path",
            "/tmp/hole-dev.sock",
            "--state-dir",
            "/tmp/hole-dev/state",
            "--ready-notify",
            "127.0.0.1:5000/tok"
        ]
    );
}

// Teardown policy (ports dev_tests.py:113-159 pins) ===================================================================

#[skuld::test]
fn posix_bridge_is_never_force_killed() {
    assert_eq!(
        grace_timeout_action(ChildRole::Bridge, Os::Posix),
        GraceTimeoutAction::WarnRecovery
    );
}

#[skuld::test]
fn windows_bridge_and_all_others_are_force_killed() {
    assert_eq!(
        grace_timeout_action(ChildRole::Bridge, Os::Windows),
        GraceTimeoutAction::HardKill
    );
    assert_eq!(
        grace_timeout_action(ChildRole::Vite, Os::Posix),
        GraceTimeoutAction::HardKill
    );
    assert_eq!(
        grace_timeout_action(ChildRole::Gui, Os::Windows),
        GraceTimeoutAction::HardKill
    );
}

// Exit codes (Delta 1 + dev.py clean-exit parity) =====================================================================

#[skuld::test]
fn child_failure_exits_one_clean_paths_exit_zero() {
    assert_eq!(supervision_exit_code(ExitCause::ChildFailed), 1);
    assert_eq!(supervision_exit_code(ExitCause::StartupFailed), 1);
    assert_eq!(supervision_exit_code(ExitCause::ChildExitedClean), 0);
    assert_eq!(supervision_exit_code(ExitCause::Interrupted), 0);
}

// More dev_tests.py pins ==============================================================================================

/// dev_tests.py:54 — euid is IGNORED on Windows (even euid 0).
#[skuld::test]
fn windows_ignores_posix_euid_values() {
    assert_eq!(
        elevation_action(Os::Windows, Some(0)),
        ElevationAction::WindowsRequireAdmin
    );
}

/// dev_tests.py:108-110 — the Windows bridge argv has no sudo prefix.
#[skuld::test]
fn bridge_argv_windows_has_no_sudo() {
    let argv = bridge_argv(
        Os::Windows,
        "C:\\stage\\hole.exe",
        "C:\\t\\hole-dev.sock",
        "C:\\t\\state",
        "127.0.0.1:5000/tok",
    );
    assert_eq!(
        argv,
        [
            "C:\\stage\\hole.exe",
            "bridge",
            "run",
            "--socket-path",
            "C:\\t\\hole-dev.sock",
            "--state-dir",
            "C:\\t\\state",
            "--ready-notify",
            "127.0.0.1:5000/tok"
        ]
    );
}

/// Label/color/width pins (dev_tests strips ANSI and asserts exact labels;
/// the width-aligned `[  vite]` is deliberate, dev.py:533).
#[skuld::test]
fn prefixes_are_colored_and_width_aligned() {
    assert_eq!(ChildRole::Bridge.prefix(), "\x1b[36m\x1b[1m[bridge]\x1b[0m ");
    assert_eq!(ChildRole::Gui.prefix(), "\x1b[35m\x1b[1m[client]\x1b[0m ");
    assert_eq!(ChildRole::Vite.prefix(), "\x1b[33m\x1b[1m[  vite]\x1b[0m ");
}

/// Fidelity item 12: the recovery warning carries dev.py's exact content.
#[skuld::test]
fn network_reset_warning_is_verbatim() {
    assert!(NETWORK_RESET_WARNING.contains(
        "The bridge did not exit within 10s and may still be running as root with routing changes in place."
    ));
    assert!(NETWORK_RESET_WARNING.contains("Run `sudo scripts/network-reset.py` to restore connectivity."));
}
