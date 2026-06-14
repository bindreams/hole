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
