use std::cell::RefCell;
use std::collections::VecDeque;

use super::*;
use crate::cutover::scm_wait::call_error::{ScmCall, ScmCallError};
use crate::cutover::scm_wait::hold::{Look, ProcessFate};
use crate::cutover::scm_wait::scan::ScanFinding;
use crate::cutover::scm_wait::Observed;
use crate::disable_record::RecordState;

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
    /// Whether the record is there: `write_record` sets it, `clear_record` unsets it.
    record: RecordState,
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
            record: RecordState::Absent,
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

    fn with_record(mut self, record: RecordState) -> Self {
        self.record = record;
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
    fn hold_scanned(&mut self) -> io::Result<ScanFinding> {
        self.call("hold_scanned")?;
        Ok(ScanFinding::Nothing)
    }
}

impl StartConfig for FakeSession<'_> {
    fn start_type(&mut self) -> io::Result<StartType> {
        self.call("start_type")?;
        Ok(self.start_type)
    }
    fn set_start_type(&mut self, to: StartWrite) -> io::Result<()> {
        self.call(format!("set_start_type({to:?})"))
    }
    fn record_state(&mut self) -> RecordState {
        self.log.borrow_mut().push("record_state".into());
        self.record
    }
    fn clear_record(&mut self) -> io::Result<()> {
        self.call("clear_record")?;
        self.record = RecordState::Absent;
        Ok(())
    }
    fn write_record(&mut self) -> io::Result<()> {
        self.call("write_record")?;
        self.record = RecordState::Present;
        Ok(())
    }
    fn record_changer(&mut self) -> Option<Changer> {
        match self.record {
            RecordState::Absent => None,
            RecordState::Present => Some(Changer::NotRunning),
        }
    }
}

impl ServiceSession for FakeSession<'_> {
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

/// What the hardening of an `Auto` service with no record does, in order: the
/// record is written before the start type is disabled.
const HARDEN: [&str; 5] = [
    "start_type",
    "record_state",
    "write_record",
    "set_start_type(Disabled)",
    "set_failure_actions(None)",
];
/// The settle loop over a service that is running and then stopped.
const STOP_AND_SETTLE: [&str; 6] = [
    "observe",
    "control_stop",
    "await_held_exits",
    "observe",
    "hold_scanned",
    "observe",
];
/// What a restore of an `Auto` service we disabled does: the failure actions,
/// then the start type, then the record last.
const RESTORE_AUTO: [&str; 3] = ["set_failure_actions(Restart)", "set_start_type(Auto)", "clear_record"];

fn scm_error(call: ScmCall, code: u32) -> io::Error {
    ScmCallError { call, code }.into_io()
}

// The order of a retirement ===========================================================================================

#[skuld::test]
fn deregistering_hardens_settles_then_deletes_and_only_the_record_follows_the_delete() {
    let log = Log::default();
    let mut session = FakeSession::running_then_stopped(&log);
    retire(&mut session, Disposition::Deregister).unwrap();
    let expected: Vec<&str> = HARDEN
        .iter()
        .chain(&STOP_AND_SETTLE)
        .copied()
        .chain(["delete", "clear_record"])
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
        assert_eq!(
            logged[logged.len() - RESTORE_AUTO.len()..],
            RESTORE_AUTO,
            "{what}: {logged:?}"
        );
    }
}

#[skuld::test]
fn a_failed_delete_restores_and_is_the_delete_variant() {
    let log = Log::default();
    let mut session = FakeSession::new(&log, vec![stopped(), stopped()]).failing_with("delete", io::Error::other("no"));
    let error = retire(&mut session, Disposition::Deregister).expect_err("the delete failed");
    assert!(matches!(error, RetireError::Delete(_)), "{error}");
    let logged = logged(&log);
    assert_eq!(logged[logged.len() - RESTORE_AUTO.len()..], RESTORE_AUTO, "{logged:?}");
    assert_eq!(logged[logged.len() - RESTORE_AUTO.len() - 1], "delete", "{logged:?}");
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
    assert_eq!(logged[logged.len() - 2..], ["delete", "clear_record"], "{logged:?}");
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
    let logged = logged(&log);
    assert_eq!(logged[logged.len() - RESTORE_AUTO.len()..], RESTORE_AUTO, "{logged:?}");
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

/// The start type is the first service setting written: a failure there leaves
/// nothing changed but the record written before it, which is cleared.
#[skuld::test]
fn a_start_type_that_cannot_be_disabled_fails_the_retirement_and_clears_only_the_record_it_wrote() {
    let log = Log::default();
    let mut session = FakeSession::running_then_stopped(&log).failing("set_start_type(Disabled)");
    let error = retire(&mut session, Disposition::Deregister).expect_err("the start type write failed");
    assert!(matches!(error, RetireError::Harden(_)), "{error}");
    assert_eq!(
        logged(&log),
        [
            "start_type",
            "record_state",
            "write_record",
            "set_start_type(Disabled)",
            "clear_record"
        ]
    );
    assert_eq!(session.record, RecordState::Absent);
}

#[skuld::test]
fn a_start_type_that_cannot_be_read_fails_the_retirement_before_anything_is_written() {
    let log = Log::default();
    let mut session = FakeSession::running_then_stopped(&log).failing("start_type");
    let error = retire(&mut session, Disposition::Deregister).expect_err("the start type read failed");
    assert!(matches!(error, RetireError::Harden(_)), "{error}");
    assert_eq!(logged(&log), ["start_type"]);
    assert_eq!(session.record, RecordState::Absent);
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
    let logged = logged(&log);
    assert_eq!(
        logged[logged.len() - 2..],
        ["set_start_type(Auto)", "clear_record"],
        "{logged:?}"
    );
}

#[skuld::test]
fn a_restore_that_cannot_write_the_start_type_is_not_a_failed_stop() {
    let log = Log::default();
    let mut session =
        FakeSession::running_then_stopped(&log).failing_with("set_start_type(Auto)", io::Error::other("no"));
    retire(&mut session, Disposition::StopOnly).unwrap();
}

// The record ==========================================================================================================

fn position(logged: &[String], call: &str) -> usize {
    logged
        .iter()
        .position(|logged| logged == call)
        .unwrap_or_else(|| panic!("{call} was never called: {logged:?}"))
}

#[skuld::test]
fn the_record_is_written_before_the_start_type_is_disabled() {
    let log = Log::default();
    let mut session = FakeSession::running_then_stopped(&log);
    retire(&mut session, Disposition::StopOnly).unwrap();
    let logged = logged(&log);
    assert!(
        position(&logged, "write_record") < position(&logged, "set_start_type(Disabled)"),
        "{logged:?}"
    );
}

/// A failed write changes nothing: the start type is not touched, and the
/// failure is the record's own.
#[skuld::test]
fn a_failed_record_write_changes_nothing_and_is_a_record_error() {
    let log = Log::default();
    let mut session = FakeSession::running_then_stopped(&log).failing("write_record");
    let error = retire(&mut session, Disposition::Deregister).expect_err("the record write failed");
    assert!(matches!(error, RetireError::Record(_)), "{error}");
    assert_eq!(logged(&log), ["start_type", "record_state", "write_record"]);
}

/// The start type put back: the one observed, except that `Other` (a boot or
/// system start, which a service of its own process never has) becomes `Auto`,
/// and `Disabled` becomes `Auto` only when the disable is ours.
#[skuld::test]
fn restored_is_one_table_over_observed_and_ours() {
    let table = [
        (StartType::Auto, true, StartWrite::Auto),
        (StartType::Auto, false, StartWrite::Auto),
        (StartType::Demand, true, StartWrite::Demand),
        (StartType::Demand, false, StartWrite::Demand),
        (StartType::Disabled, true, StartWrite::Auto),
        (StartType::Disabled, false, StartWrite::Disabled),
        (StartType::Other, true, StartWrite::Auto),
        (StartType::Other, false, StartWrite::Auto),
    ];
    for (observed, ours, restored) in table {
        assert_eq!(
            Hardening { observed, ours }.restored(),
            restored,
            "{observed:?}, ours {ours}"
        );
    }
}

/// An administrator's Disable is not ours to undo: no record is written for it
/// or cleared, and what is put back is Disabled.
#[skuld::test]
fn a_disabled_service_without_a_record_is_not_ours_and_is_restored_disabled() {
    for disposition in [Disposition::StopOnly, Disposition::Deregister] {
        let log = Log::default();
        let mut session = FakeSession::running_then_stopped(&log).with_start_type(StartType::Disabled);
        retire(&mut session, disposition).unwrap_or_else(|e| panic!("{disposition:?}: {e}"));
        let logged = logged(&log);
        assert!(
            !logged.contains(&"write_record".to_owned()),
            "{disposition:?}: {logged:?}"
        );
        assert!(
            !logged.contains(&"clear_record".to_owned()),
            "{disposition:?}: {logged:?}"
        );
        if disposition == Disposition::StopOnly {
            assert_eq!(
                logged.last().map(String::as_str),
                Some("set_start_type(Disabled)"),
                "{logged:?}"
            );
        }
        assert_eq!(session.record, RecordState::Absent, "{disposition:?}");
    }
}

/// A Disabled service with a record is ours: put back as Automatic, and the
/// record, which already exists, is stamped again with this retirement's
/// identity (so a reader does not take the old, dead stamp for an interrupted
/// change while this one runs) and cleared at the end.
#[skuld::test]
fn a_disabled_service_with_a_record_is_restored_automatic_and_the_record_cleared() {
    let log = Log::default();
    let mut session = FakeSession::running_then_stopped(&log)
        .with_start_type(StartType::Disabled)
        .with_record(RecordState::Present);
    retire(&mut session, Disposition::StopOnly).unwrap();
    let logged = logged(&log);
    assert!(logged.contains(&"write_record".to_owned()), "{logged:?}");
    assert_eq!(logged[logged.len() - RESTORE_AUTO.len()..], RESTORE_AUTO, "{logged:?}");
    assert_eq!(session.record, RecordState::Absent);
}

#[skuld::test]
fn a_service_found_on_demand_is_restored_to_on_demand_and_its_record_cleared() {
    let log = Log::default();
    let mut session = FakeSession::running_then_stopped(&log).with_start_type(StartType::Demand);
    retire(&mut session, Disposition::StopOnly).unwrap();
    let logged = logged(&log);
    assert_eq!(
        logged[logged.len() - 3..],
        ["set_failure_actions(Restart)", "set_start_type(Demand)", "clear_record"],
        "{logged:?}"
    );
}

/// A record over a service that is not Disabled is stale: the retirement
/// stamps it with its own identity, restores the start type as observed and
/// sweeps it.
#[skuld::test]
fn a_stale_record_over_a_service_that_is_not_disabled_is_swept() {
    let log = Log::default();
    let mut session = FakeSession::running_then_stopped(&log).with_record(RecordState::Present);
    retire(&mut session, Disposition::StopOnly).unwrap();
    let logged = logged(&log);
    assert!(logged.contains(&"write_record".to_owned()), "{logged:?}");
    assert_eq!(logged[logged.len() - RESTORE_AUTO.len()..], RESTORE_AUTO, "{logged:?}");
    assert_eq!(session.record, RecordState::Absent);
}

/// The record goes only after the start type is written back: a record cleared
/// first, then a failure, would leave a Disabled service that looks like an
/// administrator's.
#[skuld::test]
fn the_record_is_cleared_after_the_start_type_is_written_back_and_not_before() {
    let log = Log::default();
    let mut session = FakeSession::running_then_stopped(&log);
    retire(&mut session, Disposition::StopOnly).unwrap();
    let logged = logged(&log);
    assert!(
        position(&logged, "set_start_type(Auto)") < position(&logged, "clear_record"),
        "{logged:?}"
    );
}

#[skuld::test]
fn a_failed_start_type_restore_leaves_the_record() {
    let log = Log::default();
    let mut session =
        FakeSession::running_then_stopped(&log).failing_with("set_start_type(Auto)", io::Error::other("no"));
    retire(&mut session, Disposition::StopOnly).unwrap();
    assert!(
        !logged(&log).contains(&"clear_record".to_owned()),
        "the service is still Disabled"
    );
    assert_eq!(session.record, RecordState::Present);
}

/// Clearing the record is the last step of an uninstall that has already
/// deleted the service: it warns when it fails.
#[skuld::test]
fn a_record_that_cannot_be_cleared_is_not_a_failed_retirement() {
    for disposition in [Disposition::StopOnly, Disposition::Deregister] {
        let log = Log::default();
        let mut session = FakeSession::running_then_stopped(&log).failing("clear_record");
        retire(&mut session, disposition).unwrap_or_else(|e| panic!("{disposition:?}: {e}"));
    }
}

/// The record is cleared after the delete, and also after a delete answering
/// that the service is already marked, which is a delete done.
#[skuld::test]
fn a_deregister_clears_the_record_after_the_delete_and_after_a_delete_answering_1072() {
    let log = Log::default();
    let mut session = FakeSession::running_then_stopped(&log);
    retire(&mut session, Disposition::Deregister).unwrap();
    let logged_ok = logged(&log);
    assert_eq!(
        logged_ok[logged_ok.len() - 2..],
        ["delete", "clear_record"],
        "{logged_ok:?}"
    );

    let log = Log::default();
    let mut session =
        FakeSession::running_then_stopped(&log).failing_with("delete", scm_error(ScmCall::DeleteService, 1072));
    retire(&mut session, Disposition::Deregister).unwrap();
    let logged_marked = logged(&log);
    assert_eq!(
        logged_marked[logged_marked.len() - 2..],
        ["delete", "clear_record"],
        "{logged_marked:?}"
    );
    assert_eq!(session.record, RecordState::Absent);
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
        // The record this call wrote is cleared at once: nothing was disabled.
        let expected: Vec<&str> = [
            "start_type",
            "record_state",
            "write_record",
            "set_start_type(Disabled)",
            "clear_record",
        ]
        .iter()
        .chain(&STOP_AND_SETTLE)
        .copied()
        .collect();
        assert_eq!(logged(&log), expected, "{disposition:?}");
        assert_eq!(session.record, RecordState::Absent, "{disposition:?}");
    }
}

/// A record written by an earlier, interrupted uninstall is not this call's to
/// clear: this call only stamped it again, so it is kept, and a record this
/// call made is cleared.
#[skuld::test]
fn a_marked_answer_clears_the_record_this_call_wrote_and_keeps_a_stale_one() {
    let log = Log::default();
    let mut session = FakeSession::running_then_stopped(&log)
        .with_record(RecordState::Present)
        .failing_with("set_start_type(Disabled)", marked_at_the_start_type_write());
    retire(&mut session, Disposition::Deregister).unwrap();
    let logged = logged(&log);
    assert!(logged.contains(&"write_record".to_owned()), "{logged:?}");
    assert!(!logged.contains(&"clear_record".to_owned()), "{logged:?}");
    assert_eq!(session.record, RecordState::Present);

    let log = Log::default();
    let mut session = FakeSession::running_then_stopped(&log)
        .failing_with("set_start_type(Disabled)", marked_at_the_start_type_write());
    retire(&mut session, Disposition::Deregister).unwrap();
    assert_eq!(
        session.record,
        RecordState::Absent,
        "the record this call wrote is gone"
    );
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
        assert_eq!(
            logged(&log),
            [
                "start_type",
                "record_state",
                "write_record",
                "set_start_type(Disabled)",
                "clear_record"
            ],
            "{code}"
        );
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
            "record_state",
            "write_record",
            "set_start_type(Disabled)",
            "clear_record",
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

/// What the survivors wait does, in order, with scripted answers. A script
/// that runs dry panics, so a loop that would spin fails instead of hanging.
struct FakeSurvivors<'a> {
    log: &'a Log,
    /// What each scan finds, in order.
    findings: VecDeque<ScanFinding>,
    scan_fails: bool,
    await_fails: bool,
}

impl<'a> FakeSurvivors<'a> {
    fn new(log: &'a Log, findings: Vec<ScanFinding>) -> Self {
        Self {
            log,
            findings: findings.into(),
            scan_fails: false,
            await_fails: false,
        }
    }
}

impl Survivors for FakeSurvivors<'_> {
    fn hold_scanned(&mut self) -> io::Result<ScanFinding> {
        self.log.borrow_mut().push("hold_scanned".into());
        if self.scan_fails {
            return Err(io::Error::other("scan"));
        }
        Ok(self.findings.pop_front().expect("the scan script ran dry"))
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
    let mut survivors = FakeSurvivors::new(&log, vec![ScanFinding::Nothing]);
    wait_out_survivors(&mut survivors).unwrap();
    assert_eq!(logged(&log), ["hold_scanned"]);
}

/// The wait ends only on a scan that finds nothing: a process that exits
/// can have started another, which the next scan finds.
#[skuld::test]
fn a_process_that_outlives_its_entry_is_waited_on_until_a_scan_finds_none() {
    let log = Log::default();
    // The first scan holds the process, the second a descendant it started, the third nothing.
    let mut survivors = FakeSurvivors::new(&log, vec![ScanFinding::Alive, ScanFinding::Alive, ScanFinding::Nothing]);
    wait_out_survivors(&mut survivors).unwrap();
    assert_eq!(
        logged(&log),
        [
            "hold_scanned",
            "await_exits",
            "hold_scanned",
            "await_exits",
            "hold_scanned"
        ]
    );
}

/// A scan that lost a listed process to its probe is not a scan that found
/// nothing: it is made again.
#[skuld::test]
fn a_scan_that_lost_a_listed_process_is_made_again() {
    let log = Log::default();
    let mut survivors = FakeSurvivors::new(&log, vec![ScanFinding::Vanished, ScanFinding::Nothing]);
    wait_out_survivors(&mut survivors).unwrap();
    assert_eq!(logged(&log), ["hold_scanned", "await_exits", "hold_scanned"]);
}

#[skuld::test]
fn a_scan_failure_is_a_hold_error_and_a_wait_failure_an_exit_error() {
    let log = Log::default();
    let mut survivors = FakeSurvivors::new(&log, vec![]);
    survivors.scan_fails = true;
    let error = wait_out_survivors(&mut survivors).expect_err("the scan failed");
    assert!(matches!(error, RetireError::Hold(_)), "{error}");

    let mut survivors = FakeSurvivors::new(&log, vec![ScanFinding::Alive]);
    survivors.await_fails = true;
    let error = wait_out_survivors(&mut survivors).expect_err("the wait failed");
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
            FakeSurvivors::new(&log, vec![ScanFinding::Alive, ScanFinding::Nothing])
        },
        Disposition::Deregister,
    )
    .unwrap();
    assert!(!opened, "nothing was retired");
    assert_eq!(*built.borrow(), 1);
    assert_eq!(logged(&log), ["hold_scanned", "await_exits", "hold_scanned"]);
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
        .chain(["delete", "clear_record"])
        .collect();
    assert_eq!(logged(&log), expected);
}

// Where a retirement can be cut short =================================================================================

/// What goes wrong at the n-th call (1-based) of a retirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// The call fails and changes nothing.
    Fails(usize),
    /// The call succeeds and the process dies right after it.
    Killed(usize),
    /// Someone else's delete marks the service just before the call: from then
    /// on the SCM answers a configuration write, an arm and a delete with
    /// `ERROR_SERVICE_MARKED_FOR_DELETE`.
    MarkedBefore(usize),
}

/// The process dying: unwinds without a panic message, and is caught by the
/// harness, so nothing after the call that carried it runs.
struct Killed;

/// A service and its record, as the SCM and the service's registry key hold them,
/// checked after every call.
struct Model {
    start: StartType,
    record: bool,
    marked: bool,
    stopped: bool,
    /// Disabled with no record when the retirement began: an administrator's.
    administrators: bool,
    calls: usize,
    fault: Option<Fault>,
}

impl Model {
    fn new(start: StartType, record: bool, fault: Option<Fault>) -> Self {
        Self {
            start,
            record,
            marked: false,
            stopped: false,
            administrators: start == StartType::Disabled && !record,
            calls: 0,
            fault,
        }
    }

    /// The invariants of the record, true after every call. A service marked
    /// for deletion is going away, so only a live one is held to them.
    fn check(&self) {
        if self.marked {
            return;
        }
        if self.administrators {
            assert!(
                self.start == StartType::Disabled && !self.record,
                "an administrator's disable was changed: start {:?}, record {}",
                self.start,
                self.record
            );
        } else {
            assert!(
                !(self.start == StartType::Disabled && !self.record),
                "a service this retirement disabled is Disabled with no record"
            );
        }
    }

    /// One call: counts it, applies the fault, runs `apply` and checks the
    /// invariants. `refused_when_marked` names the SCM call a mark makes the
    /// SCM answer 1072.
    fn step(&mut self, refused_when_marked: Option<ScmCall>, apply: impl FnOnce(&mut Self)) -> io::Result<()> {
        self.calls += 1;
        if self.fault == Some(Fault::MarkedBefore(self.calls)) {
            self.marked = true;
        }
        if self.fault == Some(Fault::Fails(self.calls)) {
            return Err(io::Error::other("injected"));
        }
        if let (true, Some(call)) = (self.marked, refused_when_marked) {
            return Err(scm_error(call, 1072));
        }
        apply(self);
        self.check();
        if self.fault == Some(Fault::Killed(self.calls)) {
            std::panic::resume_unwind(Box::new(Killed));
        }
        Ok(())
    }
}

impl StopActor for Model {
    fn observe(&mut self) -> io::Result<Look> {
        self.step(None, |_| {})?;
        Ok(if self.stopped { stopped() } else { running() })
    }
    fn arm_leaving(&mut self, _: Observed) -> io::Result<()> {
        self.step(Some(ScmCall::NotifyServiceStatusChange), |_| {})
    }
    fn control_stop(&mut self) -> io::Result<()> {
        self.step(None, |model| model.stopped = true)
    }
    fn await_callback(&mut self) -> io::Result<()> {
        self.step(None, |_| {})
    }
    fn await_held_exits(&mut self) -> io::Result<()> {
        self.step(None, |_| {})
    }
    fn hold_scanned(&mut self) -> io::Result<ScanFinding> {
        self.step(None, |_| {})?;
        Ok(ScanFinding::Nothing)
    }
}

impl StartConfig for Model {
    fn start_type(&mut self) -> io::Result<StartType> {
        self.step(None, |_| {})?;
        Ok(self.start)
    }
    fn set_start_type(&mut self, to: StartWrite) -> io::Result<()> {
        self.step(Some(ScmCall::ChangeServiceConfig), |model| {
            model.start = match to {
                StartWrite::Auto => StartType::Auto,
                StartWrite::Demand => StartType::Demand,
                StartWrite::Disabled => StartType::Disabled,
            }
        })
    }
    fn record_state(&mut self) -> RecordState {
        if self.record {
            RecordState::Present
        } else {
            RecordState::Absent
        }
    }
    fn clear_record(&mut self) -> io::Result<()> {
        self.step(None, |model| model.record = false)
    }
    fn write_record(&mut self) -> io::Result<()> {
        self.step(None, |model| model.record = true)
    }
    fn record_changer(&mut self) -> Option<Changer> {
        self.record.then_some(Changer::NotRunning)
    }
}

impl ServiceSession for Model {
    fn set_failure_actions(&mut self, _: FailureActions) -> io::Result<()> {
        self.step(Some(ScmCall::ChangeServiceConfig2), |_| {})
    }
    fn delete(&mut self) -> io::Result<()> {
        self.step(Some(ScmCall::DeleteService), |model| model.marked = true)
    }
}

const STARTS: [StartType; 4] = [
    StartType::Auto,
    StartType::Demand,
    StartType::Disabled,
    StartType::Other,
];

/// Runs a retirement over every starting point, every disposition and every
/// fault at every call the clean run makes, and fails with the scenario that
/// broke an invariant. The number of faults is the number of calls of the
/// clean run: nothing is sampled.
fn under_every_fault(only: impl Fn(StartType, bool) -> bool) {
    for start in STARTS {
        for record in [false, true] {
            if !only(start, record) {
                continue;
            }
            for disposition in [Disposition::StopOnly, Disposition::Deregister] {
                let mut clean = Model::new(start, record, None);
                retire(&mut clean, disposition).unwrap_or_else(|e| panic!("{start:?}/{record}/{disposition:?}: {e}"));
                for n in 1..=clean.calls {
                    for fault in [Fault::Fails(n), Fault::Killed(n), Fault::MarkedBefore(n)] {
                        let mut model = Model::new(start, record, Some(fault));
                        let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            let _ = retire(&mut model, disposition);
                        }));
                        let Err(payload) = ran else { continue };
                        if payload.is::<Killed>() {
                            continue;
                        }
                        let message = payload
                            .downcast_ref::<String>()
                            .cloned()
                            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                            .unwrap_or_else(|| "a panic with no message".into());
                        panic!("{start:?} with record {record}, {disposition:?}, {fault:?}: {message}");
                    }
                }
            }
        }
    }
}

/// The kill point: whatever call a retirement fails or dies at, and whether or
/// not someone else marks the service meanwhile, a live service this
/// retirement disabled has its record.
#[skuld::test]
fn at_no_point_is_a_service_we_disabled_left_without_a_record() {
    under_every_fault(|start, record| !(start == StartType::Disabled && !record));
}

/// An administrator's Disable stays exactly as it was, with no record made,
/// whatever call a retirement fails or dies at.
#[skuld::test]
fn a_service_an_administrator_disabled_is_never_touched_at_any_step() {
    under_every_fault(|start, record| start == StartType::Disabled && !record);
}

/// A retirement that completes leaves no record behind, whatever it began with.
#[skuld::test]
fn a_completed_retirement_leaves_no_record() {
    for start in STARTS {
        for record in [false, true] {
            for disposition in [Disposition::StopOnly, Disposition::Deregister] {
                let mut model = Model::new(start, record, None);
                retire(&mut model, disposition).unwrap();
                assert!(!model.record, "{start:?} with record {record}, {disposition:?}");
            }
        }
    }
}

// The survivors wait on a model host ==================================================================================

use crate::cutover::scm_wait::world_tests::{Act, StoppedService, When, World};

/// The removed-service wait over the processes the model host runs.
struct ModelSurvivors(StoppedService);

impl Survivors for ModelSurvivors {
    fn hold_scanned(&mut self) -> io::Result<ScanFinding> {
        let mut host = self.0.world.host();
        self.0.holds.hold_scanned(&mut host).map(|scanned| scanned.finding)
    }

    fn await_exits(&mut self) -> io::Result<()> {
        self.0.await_exits();
        Ok(())
    }
}

fn wait_out_on(world: &World) {
    wait_out_survivors(&mut ModelSurvivors(StoppedService::new(world))).unwrap();
    assert_eq!(
        world.alive(),
        Vec::<u32>::new(),
        "the wait returned with a process of the service alive"
    );
}

#[skuld::test]
fn survivors_started_after_the_snapshot_by_a_process_that_then_exits_are_waited_out() {
    let world = World::new(
        &[10],
        vec![
            (When::AfterOpen(10), Act::Spawn(11)),
            (When::AfterOpen(10), Act::Exit(10)),
        ],
    );
    wait_out_on(&world);
}

#[skuld::test]
fn survivors_started_by_a_process_that_vanished_before_its_probe_are_waited_out() {
    let world = World::new(
        &[10],
        vec![
            (When::AfterSnapshot(1), Act::Spawn(11)),
            (When::AfterSnapshot(1), Act::Vanish(10)),
        ],
    );
    wait_out_on(&world);
}

/// A listed id that no probe ever opens does not keep the wait scanning.
#[skuld::test]
fn an_id_the_listing_names_and_no_probe_opens_does_not_hold_the_survivors_wait_for_ever() {
    let world = World::new(&[10], vec![]).listing_an_id_that_never_opens(77);
    wait_out_on(&world);
}
