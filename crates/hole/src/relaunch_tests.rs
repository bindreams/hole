use super::*;

#[skuld::test]
fn armed_wait_returns_after_child_exits() {
    // Spawn a real, short-lived child and arm a wait on it; whether we arm
    // before or after it exits, `wait()` must return (a live handle blocks
    // until exit; an already-gone PID is a no-op). Waiting on an external
    // process's exit is the sanctioned timing exception.
    #[cfg(windows)]
    let mut child = std::process::Command::new("cmd").args(["/c", "exit"]).spawn().unwrap();
    #[cfg(unix)]
    let mut child = std::process::Command::new("true").spawn().unwrap();

    let pid = child.id();
    let armed = ArmedWait::arm(pid).unwrap();
    child.wait().unwrap();
    armed.wait();
}

// Successor handoff: a relaunch reproduces the predecessor's window state using
// signals every shipped build handles — an argv flag all versions accept, and an
// env var older versions ignore.

#[skuld::test]
fn showing_uses_an_argv_flag_every_build_accepts() {
    assert_eq!(super::successor_args(true), [crate::launch::SHOW_DASHBOARD]);
}

#[skuld::test]
fn suppressing_passes_no_argv() {
    // An older successor would reject an unknown flag at parse and never arm.
    assert!(super::successor_args(false).is_empty());
}

#[skuld::test]
fn suppressing_sets_the_env_var() {
    assert_eq!(super::successor_env(false), Some(crate::launch::NO_DASHBOARD_ENV));
}

#[skuld::test]
fn showing_sets_no_env_var() {
    assert!(super::successor_env(true).is_none());
}
