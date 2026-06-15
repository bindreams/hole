use super::*;
use std::cell::RefCell;

#[derive(Default)]
struct Recorder {
    calls: RefCell<Vec<&'static str>>,
}

impl CutoverOs for Recorder {
    fn swap_images(&mut self) -> std::io::Result<()> {
        self.calls.borrow_mut().push("swap");
        Ok(())
    }
    fn stop_service_wait_stopped(&mut self) -> std::io::Result<()> {
        self.calls.borrow_mut().push("stop_wait_stopped");
        Ok(())
    }
    fn start_service_wait_running(&mut self) -> std::io::Result<()> {
        self.calls.borrow_mut().push("start_wait_running");
        Ok(())
    }
}

// The never-engage/disengage invariant is structural, not asserted at runtime:
// `CutoverOs` exposes no cover-mutating method, so `run_cutover` cannot touch a
// cover. Cover persistence is the bridge-shutdown disarm's job (`stop_with`).

#[cfg(target_os = "windows")]
#[skuld::test]
fn windows_sequence_is_stop_swap_start() {
    let mut os = Recorder::default();
    run_cutover(&mut os).unwrap();
    assert_eq!(
        *os.calls.borrow(),
        vec!["stop_wait_stopped", "swap", "start_wait_running"]
    );
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn macos_sequence_is_swap_then_sigterm_restart() {
    let mut os = Recorder::default();
    run_cutover(&mut os).unwrap();
    // macOS swaps both images FIRST (the running daemon keeps its old inode),
    // then SIGTERM-stops (graceful, runs pm.stop()) + waits exit, then starts.
    assert_eq!(
        *os.calls.borrow(),
        vec!["swap", "stop_wait_stopped", "start_wait_running"]
    );
}
