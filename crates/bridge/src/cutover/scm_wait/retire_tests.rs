use std::cell::RefCell;
use std::collections::VecDeque;

use super::*;
use crate::cutover::scm_wait::WantState;

type Log = RefCell<Vec<&'static str>>;

/// A session whose every call is logged in order and whose answers are
/// scripted: `waits` feed `wait_callback`, `observations` feed `observe`.
struct FakeSession<'a> {
    log: &'a Log,
    waits: VecDeque<Observed>,
    observations: VecDeque<Observed>,
    fail: Vec<&'static str>,
}

impl<'a> FakeSession<'a> {
    fn new(log: &'a Log, waits: Vec<Observed>, observations: Vec<Observed>) -> Self {
        Self {
            log,
            waits: waits.into(),
            observations: observations.into(),
            fail: vec![],
        }
    }

    fn failing(mut self, call: &'static str) -> Self {
        self.fail.push(call);
        self
    }

    /// Logs `call`, then fails if it was scripted to.
    fn call(&self, call: &'static str) -> io::Result<()> {
        self.log.borrow_mut().push(call);
        if self.fail.contains(&call) {
            Err(io::Error::other(call))
        } else {
            Ok(())
        }
    }
}

impl ScmActor for FakeSession<'_> {
    fn arm(&mut self, _want: WantState) -> io::Result<()> {
        self.call("arm")
    }
    fn control_stop(&mut self) -> io::Result<()> {
        self.call("control_stop")
    }
    fn start(&mut self) -> io::Result<()> {
        self.call("start")
    }
    fn wait_callback(&mut self) -> io::Result<Observed> {
        self.call("wait")?;
        Ok(self.waits.pop_front().expect("wait script ran dry"))
    }
}

impl ServiceSession for FakeSession<'_> {
    fn disable_restart(&mut self) -> io::Result<()> {
        self.call("disable_restart")
    }
    fn restore_restart(&mut self) -> io::Result<()> {
        self.call("restore_restart")
    }
    fn delete(&mut self) -> io::Result<()> {
        self.call("delete")
    }
    fn observe(&mut self) -> io::Result<Observed> {
        self.call("observe")?;
        Ok(self.observations.pop_front().expect("observation script ran dry"))
    }
}

const STOPS_FROM_RUNNING: [Observed; 3] = [Observed::Running, Observed::StopPending, Observed::Stopped];

#[skuld::test]
fn deregistering_disables_the_restart_stops_deletes_then_confirms() {
    let log = Log::default();
    let mut session = FakeSession::new(&log, STOPS_FROM_RUNNING.into(), vec![Observed::Stopped]);
    retire(&mut session, Disposition::Deregister).unwrap();
    assert_eq!(
        *log.borrow(),
        vec![
            "disable_restart",
            // the stop wait: Running earns the one Stop
            "arm",
            "wait",
            "control_stop",
            "arm",
            "wait",
            "arm",
            "wait",
            // then the delete, then the confirmation on the same session
            "delete",
            "observe",
        ]
    );
}

/// The #1099 slip: the SCM restarts the service between the stop and the
/// delete, so the delete marks a live service. The confirmation reads that and
/// stops it again, after the delete.
#[skuld::test]
fn a_restart_that_slipped_in_before_the_delete_is_stopped_after_it() {
    let log = Log::default();
    let waits = [STOPS_FROM_RUNNING.to_vec(), STOPS_FROM_RUNNING.to_vec()].concat();
    let mut session = FakeSession::new(&log, waits, vec![Observed::Running]);
    retire(&mut session, Disposition::Deregister).unwrap();
    let log = log.borrow();
    let delete = log.iter().position(|c| *c == "delete").unwrap();
    let last_control = log.iter().rposition(|c| *c == "control_stop").unwrap();
    assert!(delete < last_control, "{log:?}");
    assert_eq!(log.iter().filter(|c| **c == "control_stop").count(), 2);
    assert!(!log.contains(&"restore_restart"), "{log:?}");
}

#[skuld::test]
fn a_service_that_is_still_starting_after_the_delete_is_waited_out_then_stopped() {
    let log = Log::default();
    let waits = vec![
        // first stop
        Observed::Stopped,
        // drain: the restarted service goes START_PENDING -> RUNNING -> STOPPED
        Observed::StartPending,
        Observed::Running,
        Observed::StopPending,
        Observed::Stopped,
    ];
    let mut session = FakeSession::new(&log, waits, vec![Observed::StartPending]);
    retire(&mut session, Disposition::Deregister).unwrap();
    let log = log.borrow();
    assert_eq!(log.iter().filter(|c| **c == "control_stop").count(), 1);
}

#[skuld::test]
fn a_failed_stop_restores_the_restart_and_never_deletes() {
    let log = Log::default();
    let mut session = FakeSession::new(&log, vec![Observed::Running], vec![]).failing("control_stop");
    let err = retire(&mut session, Disposition::Deregister).expect_err("the stop failed");
    assert!(matches!(err, RetireError::Stop(_)), "{err}");
    let log = log.borrow();
    assert!(!log.contains(&"delete"), "{log:?}");
    assert_eq!(log.last(), Some(&"restore_restart"), "{log:?}");
}

#[skuld::test]
fn a_failed_delete_restores_the_restart() {
    let log = Log::default();
    let mut session = FakeSession::new(&log, vec![Observed::Stopped], vec![]).failing("delete");
    let err = retire(&mut session, Disposition::Deregister).expect_err("the delete failed");
    assert!(matches!(err, RetireError::Delete(_)), "{err}");
    assert_eq!(log.borrow().last(), Some(&"restore_restart"));
}

/// Past the delete the service is gone or going, so there is no hardening left
/// to put back.
#[skuld::test]
fn a_failed_confirmation_after_the_delete_restores_nothing() {
    let log = Log::default();
    let mut session = FakeSession::new(&log, vec![Observed::Stopped], vec![]).failing("observe");
    let err = retire(&mut session, Disposition::Deregister).expect_err("the confirmation failed");
    assert!(matches!(err, RetireError::Drain(_)), "{err}");
    assert!(!log.borrow().contains(&"restore_restart"));
}

#[skuld::test]
fn a_failed_second_stop_after_the_delete_is_reported_as_the_confirmation_failing() {
    let log = Log::default();
    let mut session = FakeSession::new(
        &log,
        vec![Observed::Stopped, Observed::Running],
        vec![Observed::Running],
    )
    .failing("control_stop");
    let err = retire(&mut session, Disposition::Deregister).expect_err("the second stop failed");
    assert!(matches!(err, RetireError::Drain(_)), "{err}");
}

#[skuld::test]
fn a_restart_that_cannot_be_disabled_does_not_stop_the_retirement() {
    let log = Log::default();
    let mut session =
        FakeSession::new(&log, vec![Observed::Stopped], vec![Observed::Stopped]).failing("disable_restart");
    retire(&mut session, Disposition::Deregister).unwrap();
    assert!(log.borrow().contains(&"delete"));
}

/// Nothing was changed, so a later failure has nothing to put back.
#[skuld::test]
fn a_restart_that_was_never_disabled_is_not_restored() {
    let log = Log::default();
    let mut session = FakeSession::new(&log, vec![Observed::Running], vec![])
        .failing("disable_restart")
        .failing("control_stop");
    retire(&mut session, Disposition::Deregister).expect_err("the stop failed");
    assert!(!log.borrow().contains(&"restore_restart"));
}

#[skuld::test]
fn stopping_only_leaves_the_service_registered_and_the_restart_back_on() {
    let log = Log::default();
    let mut session = FakeSession::new(&log, STOPS_FROM_RUNNING.into(), vec![]);
    retire(&mut session, Disposition::StopOnly).unwrap();
    let log = log.borrow();
    assert!(!log.contains(&"delete"), "{log:?}");
    assert_eq!(log.first(), Some(&"disable_restart"));
    assert_eq!(log.last(), Some(&"restore_restart"));
}

#[skuld::test]
fn a_restart_that_cannot_be_restored_after_a_good_stop_is_not_a_failed_stop() {
    let log = Log::default();
    let mut session = FakeSession::new(&log, vec![Observed::Stopped], vec![]).failing("restore_restart");
    retire(&mut session, Disposition::StopOnly).unwrap();
}

fn os_error(code: i32) -> io::Error {
    io::Error::from_raw_os_error(code)
}

fn scm_error(call: crate::cutover::scm_wait::call_error::ScmCall, code: u32) -> io::Error {
    crate::cutover::scm_wait::call_error::ScmCallError { call, code }.into_io()
}

#[skuld::test]
fn only_a_stop_that_failed_over_a_vanished_service_means_the_service_is_gone() {
    use crate::cutover::scm_wait::call_error::ScmCall;
    // ERROR_SERVICE_DOES_NOT_EXIST 1060, ERROR_SERVICE_MARKED_FOR_DELETE 1072,
    // ERROR_ACCESS_DENIED 5.
    assert!(RetireError::Stop(scm_error(ScmCall::OpenService, 1060)).means_service_is_gone());
    assert!(RetireError::Stop(scm_error(ScmCall::NotifyServiceStatusChange, 1072)).means_service_is_gone());
    assert!(RetireError::Stop(os_error(1060)).means_service_is_gone());
    assert!(!RetireError::Stop(scm_error(ScmCall::ControlService, 5)).means_service_is_gone());
    assert!(!RetireError::Stop(io::Error::other("plain")).means_service_is_gone());
    // A delete or a confirmation that fails over a missing service is not the
    // service already being gone: the delete is this session's own act.
    assert!(!RetireError::Delete(scm_error(ScmCall::OpenService, 1060)).means_service_is_gone());
    assert!(!RetireError::Drain(scm_error(ScmCall::OpenService, 1072)).means_service_is_gone());
}
