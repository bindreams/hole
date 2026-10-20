use super::*;
use std::cell::RefCell;

#[derive(Default)]
struct Recorder {
    calls: RefCell<Vec<&'static str>>,
    /// What the repair step finds; `None` is a repair that fails.
    #[cfg(target_os = "windows")]
    repair: Option<RepairStep>,
}

#[cfg(target_os = "windows")]
impl Recorder {
    fn repairing(step: Option<RepairStep>) -> Self {
        Self {
            repair: step,
            ..Self::default()
        }
    }
}

impl CutoverOs for Recorder {
    fn swap_images(&mut self) -> std::io::Result<()> {
        self.calls.borrow_mut().push("swap");
        Ok(())
    }
    fn stop_service_wait_stopped(&mut self) -> std::io::Result<()> {
        // The stop step is OS-asymmetric: Windows waits for a real STOPPED;
        // macOS SIGTERMs its own process (graceful, no self-wait).
        #[cfg(target_os = "windows")]
        self.calls.borrow_mut().push("stop_wait_stopped");
        #[cfg(target_os = "macos")]
        self.calls.borrow_mut().push("trigger_graceful_shutdown");
        Ok(())
    }
    #[cfg(target_os = "windows")]
    fn repair_start_type(&mut self) -> std::io::Result<RepairStep> {
        self.calls.borrow_mut().push("repair_start_type");
        self.repair.ok_or_else(|| std::io::Error::other("injected"))
    }
    #[cfg(target_os = "windows")]
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
fn windows_sequence_is_stop_swap_repair_start() {
    for step in [
        RepairStep::Nothing,
        RepairStep::ClearRecordOnly,
        RepairStep::ResetThenClear,
    ] {
        let mut os = Recorder::repairing(Some(step));
        assert_eq!(run_cutover(&mut os).unwrap(), CutoverOutcome::Started, "{step:?}");
        assert_eq!(
            *os.calls.borrow(),
            vec!["stop_wait_stopped", "swap", "repair_start_type", "start_wait_running"],
            "{step:?}"
        );
    }
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn a_service_an_administrator_disabled_is_not_started_and_the_cutover_succeeds() {
    let mut os = Recorder::repairing(Some(RepairStep::LeaveDisabled));
    let outcome = run_cutover(&mut os).expect("the update installed; only the start is skipped");
    assert_eq!(outcome, CutoverOutcome::LeftDisabled);
    // The images are swapped; the start is skipped because it would fail.
    assert_eq!(
        *os.calls.borrow(),
        vec!["stop_wait_stopped", "swap", "repair_start_type"]
    );
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn a_failed_repair_fails_the_cutover_before_the_start() {
    let mut os = Recorder::repairing(None);
    run_cutover(&mut os).expect_err("a failed repair is the cutover's failure");
    assert_eq!(
        *os.calls.borrow(),
        vec!["stop_wait_stopped", "swap", "repair_start_type"]
    );
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn macos_sequence_is_swap_then_graceful_shutdown() {
    let mut os = Recorder::default();
    assert_eq!(run_cutover(&mut os).unwrap(), CutoverOutcome::Started);
    // macOS swaps both images FIRST (the running daemon keeps its old inode),
    // then triggers its OWN graceful shutdown (SIGTERM rides pm.stop(), so the
    // marker-conditional disarm fires). It does NOT wait-for-exit or start: the
    // inline actor SIGTERMs its own process, so a self-wait + explicit start are
    // unreachable — launchd's KeepAlive=true respawns the now-swapped binary.
    assert_eq!(*os.calls.borrow(), vec!["swap", "trigger_graceful_shutdown"]);
}
