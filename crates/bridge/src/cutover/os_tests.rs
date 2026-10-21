use super::*;
use std::cell::RefCell;
use std::rc::Rc;

type Calls = Rc<RefCell<Vec<&'static str>>>;

#[derive(Default)]
struct Recorder {
    calls: Calls,
    /// What the repair step finds; `None` is a repair that fails.
    #[cfg(target_os = "windows")]
    repair: Option<RepairStep>,
    /// The step that fails, if any.
    #[cfg(target_os = "windows")]
    failing: Option<&'static str>,
}

#[cfg(target_os = "windows")]
impl Recorder {
    fn repairing(step: Option<RepairStep>) -> Self {
        Self {
            repair: step,
            ..Self::default()
        }
    }

    fn failing_at(step: &'static str) -> Self {
        Self {
            repair: Some(RepairStep::Nothing),
            failing: Some(step),
            ..Self::default()
        }
    }

    /// Logs `step`, and fails if it is the one scripted to.
    fn step(&self, step: &'static str) -> std::io::Result<()> {
        self.calls.borrow_mut().push(step);
        match self.failing == Some(step) {
            true => Err(std::io::Error::other("injected")),
            false => Ok(()),
        }
    }
}

/// The hold a cutover keeps on the service from before its stop to after its start.
#[cfg(target_os = "windows")]
struct RecordedHold {
    calls: Calls,
}

#[cfg(target_os = "windows")]
impl ServiceHold for RecordedHold {
    fn restore(&mut self) {
        self.calls.borrow_mut().push("restore");
    }
}

#[cfg(target_os = "windows")]
impl Drop for RecordedHold {
    fn drop(&mut self) {
        self.calls.borrow_mut().push("release");
    }
}

impl CutoverOs for Recorder {
    fn swap_images(&mut self) -> std::io::Result<()> {
        #[cfg(target_os = "windows")]
        return self.step("swap");
        #[cfg(not(target_os = "windows"))]
        {
            self.calls.borrow_mut().push("swap");
            Ok(())
        }
    }
    #[cfg(target_os = "windows")]
    fn hold_service(&mut self) -> std::io::Result<Box<dyn ServiceHold>> {
        self.step("hold")?;
        Ok(Box::new(RecordedHold {
            calls: self.calls.clone(),
        }))
    }
    fn stop_service_wait_stopped(&mut self) -> std::io::Result<()> {
        // The stop step is OS-asymmetric: Windows waits for a real STOPPED;
        // macOS SIGTERMs its own process (graceful, no self-wait).
        #[cfg(target_os = "windows")]
        return self.step("stop_wait_stopped");
        #[cfg(not(target_os = "windows"))]
        {
            #[cfg(target_os = "macos")]
            self.calls.borrow_mut().push("trigger_graceful_shutdown");
            Ok(())
        }
    }
    #[cfg(target_os = "windows")]
    fn repair_start_type(&mut self) -> std::io::Result<RepairStep> {
        self.calls.borrow_mut().push("repair_start_type");
        self.repair.ok_or_else(|| std::io::Error::other("injected"))
    }
    #[cfg(target_os = "windows")]
    fn start_service_wait_running(&mut self) -> std::io::Result<()> {
        self.step("start_wait_running")
    }
}

// The never-engage/disengage invariant is structural, not asserted at runtime:
// `CutoverOs` exposes no cover-mutating method, so `run_cutover` cannot touch a
// cover. Cover persistence is the bridge-shutdown disarm's job (`stop_with`).

/// The sequence of a cutover whose steps all succeed: the service is held and
/// hardened first, stopped, swapped, put back, repaired, started, and released
/// last, so no other change to the start type or the record interleaves.
#[cfg(target_os = "windows")]
const WHOLE: [&str; 7] = [
    "hold",
    "stop_wait_stopped",
    "swap",
    "restore",
    "repair_start_type",
    "start_wait_running",
    "release",
];

#[cfg(target_os = "windows")]
#[skuld::test]
fn windows_sequence_is_hold_stop_swap_restore_repair_start_release() {
    for step in [
        RepairStep::Nothing,
        RepairStep::ClearRecordOnly,
        RepairStep::ResetThenClear,
    ] {
        let mut os = Recorder::repairing(Some(step));
        assert_eq!(run_cutover(&mut os).unwrap(), CutoverOutcome::Started, "{step:?}");
        assert_eq!(*os.calls.borrow(), WHOLE, "{step:?}");
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
        [
            "hold",
            "stop_wait_stopped",
            "swap",
            "restore",
            "repair_start_type",
            "release"
        ]
    );
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn a_failed_repair_fails_the_cutover_before_the_start() {
    let mut os = Recorder::repairing(None);
    run_cutover(&mut os).expect_err("a failed repair is the cutover's failure");
    assert_eq!(
        *os.calls.borrow(),
        [
            "hold",
            "stop_wait_stopped",
            "swap",
            "restore",
            "repair_start_type",
            "release"
        ]
    );
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn a_service_that_cannot_be_held_is_not_stopped() {
    let mut os = Recorder::failing_at("hold");
    run_cutover(&mut os).expect_err("no hold, no cutover");
    assert_eq!(
        *os.calls.borrow(),
        ["hold"],
        "nothing was changed, so nothing is put back"
    );
}

/// A service held and then not stopped, or not swapped, is put back and let go
/// of, so a failed update leaves it as it was and not Disabled over a record.
#[cfg(target_os = "windows")]
#[skuld::test]
fn a_failed_stop_or_swap_puts_the_service_back_and_releases_it() {
    for (failing, ran) in [
        (
            "stop_wait_stopped",
            vec!["hold", "stop_wait_stopped", "restore", "release"],
        ),
        ("swap", vec!["hold", "stop_wait_stopped", "swap", "restore", "release"]),
    ] {
        let mut os = Recorder::failing_at(failing);
        run_cutover(&mut os).expect_err(failing);
        assert_eq!(*os.calls.borrow(), ran, "{failing}");
    }
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn a_failed_start_still_releases_the_hold() {
    let mut os = Recorder::failing_at("start_wait_running");
    run_cutover(&mut os).expect_err("the start failed");
    assert_eq!(*os.calls.borrow(), WHOLE);
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
    assert_eq!(*os.calls.borrow(), ["swap", "trigger_graceful_shutdown"]);
}
