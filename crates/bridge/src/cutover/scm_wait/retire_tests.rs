use std::cell::RefCell;
use std::collections::VecDeque;

use super::*;
use crate::cutover::scm_wait::call_error::{ScmCall, ScmCallError};
use crate::cutover::scm_wait::hold::{Look, ProcessFate};
use crate::cutover::scm_wait::Observed;

/// A look at a service whose process is held and alive.
fn running() -> Look {
    Look {
        observed: Observed::Running,
        fate: ProcessFate::Alive,
        held_alive: true,
        ever_held: true,
    }
}

/// A look at a stopped service with nothing held alive.
fn stopped() -> Look {
    Look {
        observed: Observed::Stopped,
        fate: ProcessFate::Unheld,
        held_alive: false,
        ever_held: true,
    }
}

type Log = RefCell<Vec<String>>;

/// A session that logs every call in order and answers from a script. A look
/// script that runs dry panics, so a loop that would spin fails instead of
/// hanging.
struct FakeSession<'a> {
    log: &'a Log,
    looks: VecDeque<Look>,
    start_type: StartType,
    /// `(call, n)`: the n-th (1-based) occurrence of `call` fails with a plain error.
    fail: Vec<(&'static str, usize)>,
    /// `(call, error)`: the first occurrence of `call` fails with `error`.
    fail_with: Vec<(&'static str, io::Error)>,
    /// The n-th (1-based) `observe` fails as a refused process open does.
    open_refused_at_look: Option<usize>,
    seen: Vec<String>,
}

impl<'a> FakeSession<'a> {
    fn new(log: &'a Log, looks: Vec<Look>) -> Self {
        Self {
            log,
            looks: looks.into(),
            start_type: StartType::Auto,
            fail: vec![],
            fail_with: vec![],
            open_refused_at_look: None,
            seen: vec![],
        }
    }

    /// A session of a service that was running and stops when sent a Stop.
    fn running_then_stopped(log: &'a Log) -> Self {
        Self::new(log, vec![running(), stopped(), stopped()])
    }

    fn with_start_type(mut self, start_type: StartType) -> Self {
        self.start_type = start_type;
        self
    }

    fn failing(mut self, call: &'static str) -> Self {
        self.fail.push((call, 1));
        self
    }

    fn failing_with(mut self, call: &'static str, error: io::Error) -> Self {
        self.fail_with.push((call, error));
        self
    }

    fn refusing_the_process_open_at_look(mut self, n: usize) -> Self {
        self.open_refused_at_look = Some(n);
        self
    }

    /// Logs `call`, then fails if this occurrence was scripted to.
    fn call(&mut self, call: impl Into<String>) -> io::Result<()> {
        let call = call.into();
        self.log.borrow_mut().push(call.clone());
        self.seen.push(call.clone());
        let occurrence = self.seen.iter().filter(|seen| **seen == call).count();
        if call == "observe" && self.open_refused_at_look == Some(occurrence) {
            return Err(ScmCallError {
                call: ScmCall::OpenProcess,
                code: 5,
            }
            .into_io());
        }
        if let Some(at) = self.fail_with.iter().position(|(name, _)| *name == call) {
            return Err(self.fail_with.remove(at).1);
        }
        if self.fail.iter().any(|(name, n)| *name == call && *n == occurrence) {
            return Err(io::Error::other(call));
        }
        Ok(())
    }
}

impl StopActor for FakeSession<'_> {
    fn observe(&mut self) -> io::Result<Look> {
        self.call("observe")?;
        Ok(self.looks.pop_front().expect("the look script ran dry"))
    }
    fn arm_leaving(&mut self, from: Observed) -> io::Result<()> {
        self.call(format!("arm_leaving({from:?})"))
    }
    fn control_stop(&mut self) -> io::Result<()> {
        self.call("control_stop")
    }
    fn await_callback(&mut self) -> io::Result<()> {
        self.call("await_callback")
    }
    fn await_held_exits(&mut self) -> io::Result<()> {
        self.call("await_held_exits")
    }
    fn hold_scanned(&mut self) -> io::Result<()> {
        self.call("hold_scanned")
    }
}

impl ServiceSession for FakeSession<'_> {
    fn start_type(&mut self) -> io::Result<StartType> {
        self.call("start_type")?;
        Ok(self.start_type)
    }
    fn set_start_type(&mut self, to: StartWrite) -> io::Result<()> {
        self.call(format!("set_start_type({to:?})"))
    }
    fn set_failure_actions(&mut self, actions: FailureActions) -> io::Result<()> {
        self.call(format!("set_failure_actions({actions:?})"))
    }
    fn delete(&mut self) -> io::Result<()> {
        self.call("delete")
    }
}

fn logged(log: &Log) -> Vec<String> {
    log.borrow().clone()
}

/// What the hardening writes, in order.
const HARDEN: [&str; 3] = ["start_type", "set_start_type(Disabled)", "set_failure_actions(None)"];
/// The settle loop over a service that is running and then stopped.
const STOP_AND_SETTLE: [&str; 6] = [
    "observe",
    "control_stop",
    "await_held_exits",
    "observe",
    "hold_scanned",
    "observe",
];
/// What a restore of an `Auto` service writes: the failure actions, then the start type last.
const RESTORE_AUTO: [&str; 2] = ["set_failure_actions(Restart)", "set_start_type(Auto)"];

fn scm_error(call: ScmCall, code: u32) -> io::Error {
    ScmCallError { call, code }.into_io()
}

// The order of a retirement ===========================================================================================

#[skuld::test]
fn deregistering_hardens_settles_then_deletes_and_nothing_follows_the_delete() {
    let log = Log::default();
    let mut session = FakeSession::running_then_stopped(&log);
    retire(&mut session, Disposition::Deregister).unwrap();
    let expected: Vec<&str> = HARDEN
        .iter()
        .chain(&STOP_AND_SETTLE)
        .copied()
        .chain(["delete"])
        .collect();
    assert_eq!(logged(&log), expected);
}

#[skuld::test]
fn stopping_only_restores_after_the_wait_settles_and_writes_the_start_type_last() {
    let log = Log::default();
    let mut session = FakeSession::running_then_stopped(&log);
    retire(&mut session, Disposition::StopOnly).unwrap();
    let expected: Vec<&str> = HARDEN
        .iter()
        .chain(&STOP_AND_SETTLE)
        .chain(&RESTORE_AUTO)
        .copied()
        .collect();
    assert_eq!(logged(&log), expected);
}

// A retirement that fails =============================================================================================

/// Every step before the delete that can fail: the failure comes back as the
/// step's own variant, the hardening is put back, and nothing is deleted.
#[skuld::test]
fn each_failure_before_the_delete_restores_and_returns_its_own_variant() {
    type Check = fn(&RetireError) -> bool;
    let cases: [(&str, FakeSession<'_>, Check); 5] = {
        let log: &'static Log = Box::leak(Box::default());
        [
            (
                "a Stop the service refuses while still running",
                FakeSession::new(log, vec![running(), running()]).failing("control_stop"),
                |e| matches!(e, RetireError::Stop(_)),
            ),
            (
                "a look that fails",
                FakeSession::new(log, vec![]).failing("observe"),
                |e| matches!(e, RetireError::Observe(_)),
            ),
            (
                "a scan that fails",
                FakeSession::new(log, vec![stopped()]).failing("hold_scanned"),
                |e| matches!(e, RetireError::Hold(_)),
            ),
            (
                "a wait on a process that fails",
                FakeSession::new(log, vec![running()]).failing("await_held_exits"),
                |e| matches!(e, RetireError::Exit(_)),
            ),
            (
                "an arm that fails",
                FakeSession::new(
                    log,
                    vec![Look {
                        observed: Observed::StopPending,
                        fate: ProcessFate::Unheld,
                        held_alive: false,
                        ever_held: false,
                    }],
                )
                .failing_with(
                    "arm_leaving(StopPending)",
                    scm_error(ScmCall::NotifyServiceStatusChange, 5),
                ),
                |e| matches!(e, RetireError::Stop(_)),
            ),
        ]
    };
    for (what, mut session, is_expected) in cases {
        session.log.borrow_mut().clear();
        let log = session.log;
        let error = retire(&mut session, Disposition::Deregister).expect_err(what);
        assert!(is_expected(&error), "{what}: {error}");
        let logged = logged(log);
        assert!(!logged.contains(&"delete".to_owned()), "{what}: {logged:?}");
        assert_eq!(logged[logged.len() - 2..], RESTORE_AUTO, "{what}: {logged:?}");
    }
}

#[skuld::test]
fn a_failed_delete_restores_and_is_the_delete_variant() {
    let log = Log::default();
    let mut session = FakeSession::new(&log, vec![stopped(), stopped()]).failing_with("delete", io::Error::other("no"));
    let error = retire(&mut session, Disposition::Deregister).expect_err("the delete failed");
    assert!(matches!(error, RetireError::Delete(_)), "{error}");
    let logged = logged(&log);
    assert_eq!(logged[logged.len() - 2..], RESTORE_AUTO, "{logged:?}");
    assert_eq!(logged[logged.len() - 3], "delete", "{logged:?}");
}

/// `DeleteService` says the service is already marked for deletion: someone
/// else's delete beat ours, which is what we wanted.
#[skuld::test]
fn a_delete_that_finds_the_service_already_marked_is_a_success_and_restores_nothing() {
    let log = Log::default();
    let mut session = FakeSession::new(&log, vec![stopped(), stopped()])
        .failing_with("delete", scm_error(ScmCall::DeleteService, 1072));
    retire(&mut session, Disposition::Deregister).unwrap();
    let logged = logged(&log);
    assert_eq!(logged.last().map(String::as_str), Some("delete"), "{logged:?}");
}

/// The SCM has no entry left at the delete: that is not "already done"; the
/// delete failed.
#[skuld::test]
fn a_delete_that_finds_no_service_is_a_failed_delete() {
    let log = Log::default();
    let mut session = FakeSession::new(&log, vec![stopped(), stopped()])
        .failing_with("delete", scm_error(ScmCall::DeleteService, 1060));
    let error = retire(&mut session, Disposition::Deregister).expect_err("no service to delete");
    assert!(matches!(error, RetireError::Delete(_)), "{error}");
}

#[skuld::test]
fn a_failed_stop_only_wait_restores_before_returning_the_error() {
    let log = Log::default();
    let mut session = FakeSession::new(&log, vec![running()]).failing("await_held_exits");
    let error = retire(&mut session, Disposition::StopOnly).expect_err("the wait failed");
    assert!(matches!(error, RetireError::Exit(_)), "{error}");
    assert_eq!(logged(&log).last().map(String::as_str), Some("set_start_type(Auto)"));
}

/// A refused open of the service's process (or of its token) is not the step
/// that happened to need it failing.
#[skuld::test]
fn a_refused_process_open_in_a_look_is_the_hold_variant() {
    let log = Log::default();
    let mut session = FakeSession::new(&log, vec![running()]).refusing_the_process_open_at_look(1);
    let error = retire(&mut session, Disposition::Deregister).expect_err("the open was refused");
    assert!(matches!(error, RetireError::Hold(_)), "{error}");
    assert!(error.to_string().contains("OpenProcess failed"), "{error}");
}

#[skuld::test]
fn a_refused_token_read_is_the_hold_variant_whichever_step_needed_the_process() {
    for call in [
        ScmCall::OpenProcess,
        ScmCall::OpenProcessToken,
        ScmCall::GetTokenInformation,
    ] {
        let refused = || ScmCallError { call, code: 5 }.into_io();
        for step in [RetireError::Observe, RetireError::Stop, RetireError::Exit] {
            let got = RetireError::of_step(step, refused());
            assert!(matches!(got, RetireError::Hold(_)), "{call:?}: {got}");
        }
    }
    assert!(!matches!(
        RetireError::of_step(RetireError::Stop, scm_error(ScmCall::ControlService, 5)),
        RetireError::Hold(_)
    ));
}

// The hardening =======================================================================================================

/// The start type is the first thing written: a failure there leaves nothing
/// changed, so there is nothing to put back.
#[skuld::test]
fn a_start_type_that_cannot_be_disabled_fails_the_retirement_and_restores_nothing() {
    let log = Log::default();
    let mut session = FakeSession::running_then_stopped(&log).failing("set_start_type(Disabled)");
    let error = retire(&mut session, Disposition::Deregister).expect_err("the start type write failed");
    assert!(matches!(error, RetireError::Harden(_)), "{error}");
    assert_eq!(logged(&log), ["start_type", "set_start_type(Disabled)"]);
}

#[skuld::test]
fn a_start_type_that_cannot_be_read_fails_the_retirement_before_anything_is_written() {
    let log = Log::default();
    let mut session = FakeSession::running_then_stopped(&log).failing("start_type");
    let error = retire(&mut session, Disposition::Deregister).expect_err("the start type read failed");
    assert!(matches!(error, RetireError::Harden(_)), "{error}");
    assert_eq!(logged(&log), ["start_type"]);
}

#[skuld::test]
fn failure_actions_that_cannot_be_written_do_not_stop_the_retirement() {
    let log = Log::default();
    let mut session = FakeSession::running_then_stopped(&log).failing("set_failure_actions(None)");
    retire(&mut session, Disposition::Deregister).unwrap();
    assert!(logged(&log).contains(&"delete".to_owned()));
}

/// Restoring is best effort, and the start type is last: the failure actions
/// failing must not leave the start type Disabled.
#[skuld::test]
fn a_restore_that_cannot_write_the_failure_actions_still_writes_the_start_type() {
    let log = Log::default();
    let mut session = FakeSession::running_then_stopped(&log).failing("set_failure_actions(Restart)");
    retire(&mut session, Disposition::StopOnly).unwrap();
    assert_eq!(logged(&log).last().map(String::as_str), Some("set_start_type(Auto)"));
}

#[skuld::test]
fn a_restore_that_cannot_write_the_start_type_is_not_a_failed_stop() {
    let log = Log::default();
    let mut session =
        FakeSession::running_then_stopped(&log).failing_with("set_start_type(Auto)", io::Error::other("no"));
    retire(&mut session, Disposition::StopOnly).unwrap();
}

/// What the retirement leaves for a service that was left Disabled is what the
/// product treats as working, not what an interrupted retirement leaves.
#[skuld::test]
fn the_start_type_put_back_is_the_one_observed_unless_it_was_disabled() {
    let table = [
        (StartType::Auto, StartWrite::Auto),
        (StartType::Demand, StartWrite::Demand),
        (StartType::Disabled, StartWrite::Auto),
        (StartType::Other, StartWrite::Auto),
    ];
    for (observed, restored) in table {
        assert_eq!(Hardening { observed }.restored(), restored, "{observed:?}");
    }
}

#[skuld::test]
fn a_service_found_disabled_is_restored_to_auto_and_one_found_on_demand_to_on_demand() {
    for (observed, written) in [
        (StartType::Disabled, "set_start_type(Auto)"),
        (StartType::Demand, "set_start_type(Demand)"),
    ] {
        let log = Log::default();
        let mut session = FakeSession::running_then_stopped(&log).with_start_type(observed);
        retire(&mut session, Disposition::StopOnly).unwrap();
        assert_eq!(logged(&log).last().map(String::as_str), Some(written), "{observed:?}");
    }
}

// A service marked for deletion =======================================================================================

/// `ERROR_SERVICE_MARKED_FOR_DELETE` from the start-type write: someone else's
/// delete came first.
fn marked_at_the_start_type_write() -> io::Error {
    scm_error(ScmCall::ChangeServiceConfig, 1072)
}

/// Nothing was disabled, so there is nothing to put back, and the delete is
/// not ours to issue: the stop wait runs and the retirement ends.
#[skuld::test]
fn a_start_type_write_answered_as_marked_goes_on_to_the_stop_wait() {
    for disposition in [Disposition::StopOnly, Disposition::Deregister] {
        let log = Log::default();
        let mut session = FakeSession::running_then_stopped(&log)
            .failing_with("set_start_type(Disabled)", marked_at_the_start_type_write());
        retire(&mut session, disposition).unwrap_or_else(|e| panic!("{disposition:?}: {e}"));
        let expected: Vec<&str> = ["start_type", "set_start_type(Disabled)"]
            .iter()
            .chain(&STOP_AND_SETTLE)
            .copied()
            .collect();
        assert_eq!(logged(&log), expected, "{disposition:?}");
    }
}

#[skuld::test]
fn a_start_type_read_answered_as_marked_goes_on_to_the_stop_wait() {
    for disposition in [Disposition::StopOnly, Disposition::Deregister] {
        let log = Log::default();
        let mut session = FakeSession::running_then_stopped(&log)
            .failing_with("start_type", scm_error(ScmCall::QueryServiceConfig, 1072));
        retire(&mut session, disposition).unwrap_or_else(|e| panic!("{disposition:?}: {e}"));
        let expected: Vec<&str> = ["start_type"].iter().chain(&STOP_AND_SETTLE).copied().collect();
        assert_eq!(logged(&log), expected, "{disposition:?}");
    }
}

/// Only the documented answer of a mark continues; a missing service and a
/// refusal are the retirement's failure, with nothing changed.
#[skuld::test]
fn a_start_type_write_that_fails_otherwise_is_the_retirements_failure() {
    for code in [1060, 5] {
        let log = Log::default();
        let mut session = FakeSession::running_then_stopped(&log).failing_with(
            "set_start_type(Disabled)",
            scm_error(ScmCall::ChangeServiceConfig, code),
        );
        let error = retire(&mut session, Disposition::Deregister).expect_err("the write failed");
        assert!(matches!(error, RetireError::Harden(_)), "{code}: {error}");
        assert_eq!(logged(&log), ["start_type", "set_start_type(Disabled)"], "{code}");
    }
}

/// The mark lands while the service is starting: the arm is refused, and the
/// loop waits on the process it holds instead of the SCM's notification.
#[skuld::test]
fn a_mark_at_the_first_arm_is_waited_out_on_the_held_process() {
    let pending = || Look {
        observed: Observed::StartPending,
        fate: ProcessFate::Alive,
        held_alive: true,
        ever_held: true,
    };
    for disposition in [Disposition::StopOnly, Disposition::Deregister] {
        let log = Log::default();
        let mut session = FakeSession::new(&log, vec![pending(), pending(), stopped(), stopped()])
            .failing_with("set_start_type(Disabled)", marked_at_the_start_type_write())
            .failing_with(
                "arm_leaving(StartPending)",
                scm_error(ScmCall::NotifyServiceStatusChange, 1072),
            );
        retire(&mut session, disposition).unwrap_or_else(|e| panic!("{disposition:?}: {e}"));
        let expected = [
            "start_type",
            "set_start_type(Disabled)",
            "observe",
            "arm_leaving(StartPending)",
            "hold_scanned",
            "observe",
            "await_held_exits",
            "observe",
            "hold_scanned",
            "observe",
        ];
        assert_eq!(logged(&log), expected, "{disposition:?}");
    }
}

/// A live state, nothing ever held and no arm possible: no event exists to
/// wait on, so the retirement fails with the refusal and never reports done.
#[skuld::test]
fn a_marked_service_with_nothing_to_wait_on_fails_and_is_never_ok() {
    let unheld_running = || Look {
        observed: Observed::Running,
        fate: ProcessFate::Unheld,
        held_alive: false,
        ever_held: false,
    };
    for disposition in [Disposition::StopOnly, Disposition::Deregister] {
        let log = Log::default();
        let mut session = FakeSession::new(&log, vec![unheld_running(), unheld_running()])
            .failing_with("set_start_type(Disabled)", marked_at_the_start_type_write())
            .failing_with(
                "arm_leaving(Running)",
                scm_error(ScmCall::NotifyServiceStatusChange, 1072),
            );
        let error = retire(&mut session, disposition).expect_err("nothing to wait on is never done");
        assert!(matches!(error, RetireError::Stop(_)), "{disposition:?}: {error}");
        assert!(error.to_string().contains("1072"), "{error}");
        let logged = logged(&log);
        assert!(!logged.contains(&"delete".to_owned()), "{logged:?}");
        assert!(
            !logged.iter().any(|call| call.starts_with("set_failure_actions")),
            "{logged:?}"
        );
    }
}

/// The open handle keeps the entry, so neither 1060 nor 1072 after the open
/// means the service is gone: each step's failure is that step's error.
#[skuld::test]
fn a_failure_after_the_open_is_never_read_as_gone() {
    type Check = fn(&RetireError) -> bool;
    for code in [1060, 1072] {
        let log: &'static Log = Box::leak(Box::default());
        let cases: [(&str, FakeSession<'_>, Check); 2] = [
            (
                "a look",
                FakeSession::new(log, vec![]).failing_with("observe", scm_error(ScmCall::QueryServiceStatusEx, code)),
                |e| matches!(e, RetireError::Observe(_)),
            ),
            (
                "a Stop while still running",
                FakeSession::new(log, vec![running(), running()])
                    .failing_with("control_stop", scm_error(ScmCall::ControlService, code)),
                |e| matches!(e, RetireError::Stop(_)),
            ),
        ];
        for (what, mut session, is_expected) in cases {
            let error = retire(&mut session, Disposition::Deregister).expect_err(what);
            assert!(is_expected(&error), "{what}, {code}: {error}");
        }
    }
    let log = Log::default();
    let mut session = FakeSession::running_then_stopped(&log)
        .failing_with("start_type", scm_error(ScmCall::QueryServiceConfig, 1060));
    let error = retire(&mut session, Disposition::Deregister).expect_err("1060 on the read");
    assert!(matches!(error, RetireError::Harden(_)), "{error}");
}

// What a failure means ================================================================================================

/// A step's error maps to the retirement's variant for that step, one by one.
#[skuld::test]
fn every_settle_error_is_the_retire_error_of_its_step() {
    let io = || io::Error::other("x");
    assert!(matches!(
        RetireError::from(SettleError::Observe(io())),
        RetireError::Observe(_)
    ));
    assert!(matches!(
        RetireError::from(SettleError::Arm(io())),
        RetireError::Stop(_)
    ));
    assert!(matches!(
        RetireError::from(SettleError::Stop(io())),
        RetireError::Stop(_)
    ));
    assert!(matches!(
        RetireError::from(SettleError::AwaitChange(io())),
        RetireError::Stop(_)
    ));
    assert!(matches!(
        RetireError::from(SettleError::Scan(io())),
        RetireError::Hold(_)
    ));
    assert!(matches!(
        RetireError::from(SettleError::AwaitExit(io())),
        RetireError::Exit(_)
    ));
}

/// The error a caller prints names the call and the code: the step wraps it and
/// hides neither.
#[skuld::test]
fn a_failed_step_reads_with_its_call_and_its_code() {
    let message = RetireError::Delete(scm_error(ScmCall::DeleteService, 5)).to_string();
    assert!(
        message.starts_with("the service could not be deleted: DeleteService failed"),
        "{message}"
    );
    assert!(message.contains('5'), "{message}");
    let message = RetireError::Harden(scm_error(ScmCall::ChangeServiceConfig, 5)).to_string();
    assert!(message.contains("ChangeServiceConfig failed"), "{message}");
}

// A process that outlives its removed entry ===========================================================================

/// What the survivors wait does, in order, with scripted answers. A script that
/// runs dry panics, so a loop that would spin fails instead of hanging.
struct FakeSurvivors<'a> {
    log: &'a Log,
    /// The answer of each `any_alive`, in order.
    alive: VecDeque<bool>,
    scan_fails: bool,
    await_fails: bool,
    alive_fails: bool,
}

impl<'a> FakeSurvivors<'a> {
    fn new(log: &'a Log, alive: Vec<bool>) -> Self {
        Self {
            log,
            alive: alive.into(),
            scan_fails: false,
            await_fails: false,
            alive_fails: false,
        }
    }
}

impl Survivors for FakeSurvivors<'_> {
    fn hold_scanned(&mut self) -> io::Result<()> {
        self.log.borrow_mut().push("hold_scanned".into());
        if self.scan_fails {
            return Err(io::Error::other("scan"));
        }
        Ok(())
    }
    fn any_alive(&mut self) -> io::Result<bool> {
        self.log.borrow_mut().push("any_alive".into());
        if self.alive_fails {
            return Err(io::Error::other("alive"));
        }
        Ok(self.alive.pop_front().expect("the alive script ran dry"))
    }
    fn await_exits(&mut self) -> io::Result<()> {
        self.log.borrow_mut().push("await_exits".into());
        if self.await_fails {
            return Err(io::Error::other("await"));
        }
        Ok(())
    }
}

#[skuld::test]
fn an_absent_service_with_no_process_is_not_retired() {
    let log = Log::default();
    let mut survivors = FakeSurvivors::new(&log, vec![false]);
    wait_out_survivors(&mut survivors).unwrap();
    assert_eq!(logged(&log), ["hold_scanned", "any_alive"]);
}

/// The wait ends only on a scan that leaves nothing alive: a process that
/// exits can have started another, which the next scan finds.
#[skuld::test]
fn a_process_that_outlives_its_entry_is_waited_on_until_a_scan_finds_none() {
    let log = Log::default();
    // The first scan holds the process, the second a descendant it started, the third nothing.
    let mut survivors = FakeSurvivors::new(&log, vec![true, true, false]);
    wait_out_survivors(&mut survivors).unwrap();
    assert_eq!(
        logged(&log),
        [
            "hold_scanned",
            "any_alive",
            "await_exits",
            "hold_scanned",
            "any_alive",
            "await_exits",
            "hold_scanned",
            "any_alive",
        ]
    );
}

#[skuld::test]
fn a_scan_failure_is_a_hold_error_and_a_wait_failure_an_exit_error() {
    let log = Log::default();
    let mut survivors = FakeSurvivors::new(&log, vec![]);
    survivors.scan_fails = true;
    let error = wait_out_survivors(&mut survivors).expect_err("the scan failed");
    assert!(matches!(error, RetireError::Hold(_)), "{error}");

    let mut survivors = FakeSurvivors::new(&log, vec![true]);
    survivors.await_fails = true;
    let error = wait_out_survivors(&mut survivors).expect_err("the wait failed");
    assert!(matches!(error, RetireError::Exit(_)), "{error}");

    let mut survivors = FakeSurvivors::new(&log, vec![]);
    survivors.alive_fails = true;
    let error = wait_out_survivors(&mut survivors).expect_err("the state read failed");
    assert!(matches!(error, RetireError::Exit(_)), "{error}");
}

#[skuld::test]
fn an_absent_opening_goes_to_the_survivors_and_never_to_retire() {
    let log = Log::default();
    let built = RefCell::new(0);
    let opened = retire_over(
        Opening::<FakeSession<'_>>::Absent,
        || {
            *built.borrow_mut() += 1;
            FakeSurvivors::new(&log, vec![true, false])
        },
        Disposition::Deregister,
    )
    .unwrap();
    assert!(!opened, "nothing was retired");
    assert_eq!(*built.borrow(), 1);
    assert_eq!(
        logged(&log),
        ["hold_scanned", "any_alive", "await_exits", "hold_scanned", "any_alive"]
    );
}

#[skuld::test]
fn an_opened_session_never_scans_for_survivors() {
    let log = Log::default();
    let session = FakeSession::running_then_stopped(&log);
    let opened = retire_over(
        Opening::Opened(session),
        || -> FakeSurvivors<'_> { panic!("an opened session has no entry to be gone from") },
        Disposition::Deregister,
    )
    .unwrap();
    assert!(opened, "the retirement ran");
    let expected: Vec<&str> = HARDEN
        .iter()
        .chain(&STOP_AND_SETTLE)
        .copied()
        .chain(["delete"])
        .collect();
    assert_eq!(logged(&log), expected);
}
