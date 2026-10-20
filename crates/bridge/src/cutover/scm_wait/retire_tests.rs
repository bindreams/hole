use std::cell::RefCell;
use std::collections::VecDeque;

use super::*;
use crate::cutover::scm_wait::call_error::{ScmCall, ScmCallError};
use crate::cutover::scm_wait::WantState;

/// A look at a live service whose process is still running, or at a stopped one.
fn look(observed: Observed) -> Look {
    Look {
        observed,
        fate: if observed.names_a_process() {
            ProcessFate::Alive
        } else {
            ProcessFate::Unheld
        },
        held_alive: false,
    }
}

/// A look at a service the SCM still reports in `observed` whose process has gone.
fn stale(observed: Observed) -> Look {
    Look {
        observed,
        fate: ProcessFate::Exited,
        held_alive: false,
    }
}

type Log = RefCell<Vec<&'static str>>;

/// A session whose every call is logged in order and whose answers are
/// scripted: `waits` feed `wait_callback` (each held process answers with the
/// next of `wait_fates`, `Alive` once they run out), `observations` feed `observe`.
struct FakeSession<'a> {
    log: &'a Log,
    waits: VecDeque<Observed>,
    wait_fates: VecDeque<ProcessFate>,
    observations: VecDeque<Look>,
    /// The `(call, n)` whose n-th (1-based) occurrence fails as an `OpenProcess`
    /// refusal does.
    process_open_refused_at: Option<(&'static str, usize)>,
    /// `(call, n)`: the n-th (1-based) occurrence of `call` fails.
    fail: Vec<(&'static str, usize)>,
    seen: Vec<&'static str>,
}

impl<'a> FakeSession<'a> {
    fn new(log: &'a Log, waits: Vec<Observed>, observations: Vec<Observed>) -> Self {
        Self {
            log,
            waits: waits.into(),
            wait_fates: VecDeque::new(),
            observations: observations.into_iter().map(look).collect(),
            process_open_refused_at: None,
            fail: vec![],
            seen: vec![],
        }
    }

    /// The observations are these exact looks.
    fn with_looks(mut self, looks: Vec<Look>) -> Self {
        self.observations = looks.into();
        self
    }

    /// The processes held on callbacks answer with these fates, in order.
    fn with_wait_fates(mut self, fates: Vec<ProcessFate>) -> Self {
        self.wait_fates = fates.into();
        self
    }

    /// The n-th (1-based) `call` ("hold" or "observe") fails as a refused
    /// process open does.
    fn refusing_the_process_open_at(mut self, call: &'static str, n: usize) -> Self {
        self.process_open_refused_at = Some((call, n));
        self
    }

    /// The first `call` fails.
    fn failing(self, call: &'static str) -> Self {
        self.failing_nth(call, 1)
    }

    /// The `n`-th (1-based) `call` fails.
    fn failing_nth(mut self, call: &'static str, n: usize) -> Self {
        self.fail.push((call, n));
        self
    }

    /// Logs `call`, then fails if this occurrence was scripted to.
    fn call(&mut self, call: &'static str) -> io::Result<()> {
        self.log.borrow_mut().push(call);
        self.seen.push(call);
        let occurrence = self.seen.iter().filter(|seen| **seen == call).count();
        if self.process_open_refused_at == Some((call, occurrence)) {
            Err(ScmCallError {
                call: ScmCall::OpenProcess,
                code: 5,
            }
            .into_io())
        } else if self.fail.contains(&(call, occurrence)) {
            Err(io::Error::other(call))
        } else {
            Ok(())
        }
    }
}

impl ScmActor for FakeSession<'_> {
    fn arm(&mut self, _want: WantState, _except: Option<Observed>) -> io::Result<()> {
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
    fn process_fate(&mut self) -> io::Result<ProcessFate> {
        unreachable!("the retirement reads a fate through `Holding`, never off the session")
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
    fn observe(&mut self) -> io::Result<Look> {
        self.call("observe")?;
        Ok(self.observations.pop_front().expect("observation script ran dry"))
    }
    fn hold_process(&mut self) -> io::Result<ProcessFate> {
        self.call("hold")?;
        Ok(self.wait_fates.pop_front().unwrap_or(ProcessFate::Alive))
    }
    fn await_exits(&mut self) -> io::Result<()> {
        self.call("await_exits")
    }
}

const STOPS_FROM_RUNNING: [Observed; 3] = [Observed::Running, Observed::StopPending, Observed::Stopped];

fn position(log: &[&str], call: &str) -> usize {
    log.iter()
        .position(|c| *c == call)
        .unwrap_or_else(|| panic!("{call} in {log:?}"))
}

fn count(log: &[&str], call: &str) -> usize {
    log.iter().filter(|c| **c == call).count()
}

#[skuld::test]
fn deregistering_holds_the_process_stops_deletes_then_waits_it_out() {
    let log = Log::default();
    // The first look finds it running; the look after the delete and the one
    // after the wait find it stopped.
    let mut session = FakeSession::new(
        &log,
        STOPS_FROM_RUNNING.into(),
        vec![Observed::Running, Observed::Stopped, Observed::Stopped],
    );
    retire(&mut session, Disposition::Deregister).unwrap();
    assert_eq!(
        *log.borrow(),
        vec![
            // the process is held before anything is changed
            "observe",
            "disable_restart",
            // the stop wait: Running earns the one Stop; a process-carrying callback is held
            "arm",
            "wait",
            "hold",
            "control_stop",
            "arm",
            "wait",
            "hold",
            "arm",
            "wait",
            // then the delete, the look at the same session, and the wait for the process
            "delete",
            "observe",
            "await_exits",
            // time spent waiting is time the SCM could have started another
            "observe",
        ]
    );
}

/// What the uninstall promises: it returns with no service process left. The
/// last thing it does is wait one out and look again.
#[skuld::test]
fn deregistering_returns_only_after_the_last_process_exit_is_awaited() {
    let log = Log::default();
    let mut session = FakeSession::new(
        &log,
        STOPS_FROM_RUNNING.into(),
        vec![Observed::Stopped, Observed::Stopped, Observed::Stopped],
    );
    retire(&mut session, Disposition::Deregister).unwrap();
    let log = log.borrow();
    assert_eq!(log[log.len() - 2..], ["await_exits", "observe"], "{log:?}");
    assert!(position(&log, "delete") < log.iter().rposition(|c| *c == "await_exits").unwrap());
}

/// The #1099 slip: the SCM restarts the service between the stop and the
/// delete, so the delete marks a live service. The drain stops it after the
/// delete and waits for its process to exit, with no notification armed: whether
/// one can be armed on a marked service has not been measured.
#[skuld::test]
fn a_restart_that_slipped_in_before_the_delete_is_stopped_and_awaited_without_an_arm() {
    let log = Log::default();
    let mut session = FakeSession::new(
        &log,
        STOPS_FROM_RUNNING.into(),
        vec![
            Observed::Stopped,
            Observed::Running,
            Observed::Stopped,
            Observed::Stopped,
        ],
    );
    retire(&mut session, Disposition::Deregister).unwrap();
    let log = log.borrow();
    let delete = position(&log, "delete");
    assert_eq!(count(&log, "control_stop"), 2, "{log:?}");
    assert!(log[delete..].contains(&"control_stop"), "{log:?}");
    assert!(!log[delete..].contains(&"arm"), "{log:?}");
    assert!(!log.contains(&"restore_restart"), "{log:?}");
    // The Stop is followed by the wait for the process, not by another look first.
    let stop_after = delete + log[delete..].iter().position(|c| *c == "control_stop").unwrap();
    assert_eq!(log[stop_after + 1], "await_exits", "{log:?}");
}

/// A process already on its way out is waited on, not signalled and not armed for.
#[skuld::test]
fn a_service_stopping_after_the_delete_is_awaited_without_a_stop_or_an_arm() {
    let log = Log::default();
    let mut session = FakeSession::new(
        &log,
        vec![Observed::Stopped],
        vec![
            Observed::Stopped,
            Observed::StopPending,
            Observed::Stopped,
            Observed::Stopped,
        ],
    );
    retire(&mut session, Disposition::Deregister).unwrap();
    let log = log.borrow();
    let after = &log[position(&log, "delete")..];
    assert!(!after.contains(&"arm"), "{log:?}");
    assert!(!after.contains(&"control_stop"), "{log:?}");
    assert_eq!(count(after, "await_exits"), 2, "{log:?}");
}

/// The one state with no wait that avoids a notification: nothing can be
/// signalled in START_PENDING and the process will not exit by itself, so the
/// stop wait takes it, and a failure to arm there is reported, not hidden.
#[skuld::test]
fn a_service_still_starting_after_the_delete_is_waited_out_then_stopped() {
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
    let mut session = FakeSession::new(
        &log,
        waits,
        vec![
            Observed::Stopped,
            Observed::StartPending,
            Observed::Stopped,
            Observed::Stopped,
        ],
    );
    retire(&mut session, Disposition::Deregister).unwrap();
    let log = log.borrow();
    assert_eq!(count(&log, "control_stop"), 1, "{log:?}");
}

#[skuld::test]
fn a_service_still_starting_after_the_delete_that_cannot_be_armed_is_a_reported_failure() {
    let log = Log::default();
    // The first arm is the stop before the delete; the second is the drain's.
    let mut session = FakeSession::new(
        &log,
        vec![Observed::Stopped],
        vec![Observed::Stopped, Observed::StartPending],
    )
    .failing_nth("arm", 2);
    let err = retire(&mut session, Disposition::Deregister).expect_err("the drain's arm was refused");
    assert!(matches!(err, RetireError::Drain(_)), "{err}");
}

#[skuld::test]
fn a_failed_stop_restores_the_restart_and_never_deletes() {
    let log = Log::default();
    // Still RUNNING when looked at again after the refusal.
    let mut session = FakeSession::new(
        &log,
        vec![Observed::Running, Observed::Running],
        vec![Observed::Running],
    )
    .failing("control_stop");
    let err = retire(&mut session, Disposition::Deregister).expect_err("the stop failed");
    assert!(matches!(err, RetireError::Stop(_)), "{err}");
    let log = log.borrow();
    assert!(!log.contains(&"delete"), "{log:?}");
    assert_eq!(log.last(), Some(&"restore_restart"), "{log:?}");
}

#[skuld::test]
fn a_failed_delete_restores_the_restart() {
    let log = Log::default();
    let mut session = FakeSession::new(&log, vec![Observed::Stopped], vec![Observed::Stopped]).failing("delete");
    let err = retire(&mut session, Disposition::Deregister).expect_err("the delete failed");
    assert!(matches!(err, RetireError::Delete(_)), "{err}");
    assert_eq!(log.borrow().last(), Some(&"restore_restart"));
}

/// Past the delete the service is gone or going, so there is no hardening left
/// to put back.
#[skuld::test]
fn a_failed_look_after_the_delete_restores_nothing() {
    let log = Log::default();
    // The first "observe" is the look before anything changes; the second, after the delete, fails.
    let mut session =
        FakeSession::new(&log, vec![Observed::Stopped], vec![Observed::Stopped]).failing_nth("observe", 2);
    let err = retire(&mut session, Disposition::Deregister).expect_err("the look failed");
    assert!(matches!(err, RetireError::Drain(_)), "{err}");
    assert!(!log.borrow().contains(&"restore_restart"));
}

/// F6, after the delete: a Stop refused to a service that has since stopped is
/// not a failure.
#[skuld::test]
fn a_refused_stop_after_the_delete_on_a_service_that_has_since_stopped_is_not_a_failure() {
    let log = Log::default();
    let mut session = FakeSession::new(
        &log,
        vec![Observed::Stopped],
        vec![
            Observed::Stopped,
            Observed::Running,
            Observed::Stopped,
            Observed::Stopped,
        ],
    )
    .failing("control_stop");
    retire(&mut session, Disposition::Deregister).unwrap();
}

#[skuld::test]
fn a_refused_stop_after_the_delete_on_a_service_still_running_is_the_drains_failure() {
    let log = Log::default();
    let mut session = FakeSession::new(
        &log,
        vec![Observed::Stopped],
        vec![Observed::Stopped, Observed::Running, Observed::Running],
    )
    .failing("control_stop");
    let err = retire(&mut session, Disposition::Deregister).expect_err("still running");
    assert!(matches!(err, RetireError::Drain(_)), "{err}");
    assert_eq!(
        err.to_string(),
        "the deleted service could not be confirmed stopped: control_stop"
    );
}

/// The process outlives the STOPPED the SCM reports, so the process is awaited
/// BEFORE the restart is put back: a process that fails on its way out must not
/// be restarted by the hardening this session is restoring.
#[skuld::test]
fn stopping_only_waits_the_process_out_then_puts_the_restart_back() {
    let log = Log::default();
    let mut session = FakeSession::new(&log, STOPS_FROM_RUNNING.into(), vec![Observed::Running]);
    retire(&mut session, Disposition::StopOnly).unwrap();
    let log = log.borrow();
    assert!(!log.contains(&"delete"), "{log:?}");
    assert_eq!(log[0], "observe");
    assert_eq!(log[1], "disable_restart");
    assert_eq!(log[log.len() - 2..], ["await_exits", "restore_restart"], "{log:?}");
}

#[skuld::test]
fn a_failed_wait_for_the_process_in_a_stop_only_still_puts_the_restart_back() {
    let log = Log::default();
    let mut session = FakeSession::new(&log, vec![Observed::Stopped], vec![Observed::Stopped]).failing("await_exits");
    let err = retire(&mut session, Disposition::StopOnly).expect_err("the wait failed");
    assert!(matches!(err, RetireError::Exit(_)), "{err}");
    assert_eq!(log.borrow().last(), Some(&"restore_restart"));
}

#[skuld::test]
fn a_failed_wait_for_the_process_after_the_delete_is_reported_by_its_step() {
    let log = Log::default();
    let mut session = FakeSession::new(
        &log,
        vec![Observed::Stopped],
        vec![Observed::Stopped, Observed::Stopped],
    )
    .failing("await_exits");
    let err = retire(&mut session, Disposition::Deregister).expect_err("the wait failed");
    assert!(matches!(err, RetireError::Exit(_)), "{err}");
    assert!(!log.borrow().contains(&"restore_restart"));
}

/// Waiting for a process out is time in which the SCM could have started
/// another; the look after it is what finds that.
#[skuld::test]
fn a_service_started_again_while_its_process_was_awaited_is_drained_again() {
    let log = Log::default();
    let mut session = FakeSession::new(
        &log,
        vec![Observed::Stopped],
        vec![
            Observed::Stopped,
            Observed::Stopped,
            // after the wait: running again
            Observed::Running,
            Observed::Stopped,
            Observed::Stopped,
        ],
    );
    retire(&mut session, Disposition::Deregister).unwrap();
    let log = log.borrow();
    assert_eq!(count(&log, "control_stop"), 1, "{log:?}");
    assert_eq!(count(&log, "await_exits"), 3, "{log:?}");
}

#[skuld::test]
fn a_restart_that_cannot_be_disabled_does_not_stop_the_retirement() {
    let log = Log::default();
    let mut session = FakeSession::new(
        &log,
        vec![Observed::Stopped],
        vec![Observed::Stopped, Observed::Stopped, Observed::Stopped],
    )
    .failing("disable_restart");
    retire(&mut session, Disposition::Deregister).unwrap();
    assert!(log.borrow().contains(&"delete"));
}

/// Nothing was changed, so a later failure has nothing to put back.
#[skuld::test]
fn a_restart_that_was_never_disabled_is_not_restored() {
    let log = Log::default();
    let mut session = FakeSession::new(
        &log,
        vec![Observed::Running, Observed::Running],
        vec![Observed::Running],
    )
    .failing("disable_restart")
    .failing("control_stop");
    retire(&mut session, Disposition::Deregister).expect_err("the stop failed");
    assert!(!log.borrow().contains(&"restore_restart"));
}

#[skuld::test]
fn a_restart_that_cannot_be_restored_after_a_good_stop_is_not_a_failed_stop() {
    let log = Log::default();
    let mut session =
        FakeSession::new(&log, vec![Observed::Stopped], vec![Observed::Stopped]).failing("restore_restart");
    retire(&mut session, Disposition::StopOnly).unwrap();
}

#[skuld::test]
fn a_look_that_fails_before_anything_changes_changes_nothing() {
    let log = Log::default();
    let mut session = FakeSession::new(&log, vec![], vec![]).failing("observe");
    let err = retire(&mut session, Disposition::Deregister).expect_err("the first look failed");
    assert!(matches!(err, RetireError::Observe(_)), "{err}");
    assert_eq!(*log.borrow(), vec!["observe"]);
}

/// A process held on a callback is held for every state that has one, and for
/// no other: the callback that says STOPPED has no process to name.
#[skuld::test]
fn every_callback_naming_a_process_holds_it_and_a_stopped_one_does_not() {
    let log = Log::default();
    let waits = vec![
        Observed::StartPending,
        Observed::Running,
        Observed::StopPending,
        Observed::Stopped,
    ];
    let mut session = FakeSession::new(&log, waits, vec![Observed::Running]);
    retire(&mut session, Disposition::StopOnly).unwrap();
    let log = log.borrow();
    assert_eq!(count(&log, "hold"), 3, "{log:?}");
    let last_wait = log.iter().rposition(|c| *c == "wait").unwrap();
    assert_ne!(log[last_wait + 1], "hold", "{log:?}");
}

fn os_error(code: i32) -> io::Error {
    io::Error::from_raw_os_error(code)
}

fn scm_error(call: ScmCall, code: u32) -> io::Error {
    ScmCallError { call, code }.into_io()
}

#[skuld::test]
fn only_a_failure_over_a_vanished_service_before_the_delete_means_the_service_is_gone() {
    // ERROR_SERVICE_DOES_NOT_EXIST 1060, ERROR_SERVICE_MARKED_FOR_DELETE 1072,
    // ERROR_ACCESS_DENIED 5.
    assert!(RetireError::Stop(scm_error(ScmCall::OpenService, 1060)).means_service_is_gone());
    assert!(RetireError::Stop(scm_error(ScmCall::NotifyServiceStatusChange, 1072)).means_service_is_gone());
    assert!(RetireError::Stop(os_error(1060)).means_service_is_gone());
    assert!(!RetireError::Stop(scm_error(ScmCall::ControlService, 5)).means_service_is_gone());
    assert!(!RetireError::Stop(io::Error::other("plain")).means_service_is_gone());
    // The first look is a step of the stop: the service going away under it is
    // the service already being gone.
    assert!(RetireError::Observe(scm_error(ScmCall::QueryServiceStatusEx, 1060)).means_service_is_gone());
    assert!(!RetireError::Observe(scm_error(ScmCall::QueryServiceStatusEx, 5)).means_service_is_gone());
    // A delete, a drain or a wait that fails over a missing service is not the
    // service already being gone: each is this session's own act.
    assert!(!RetireError::Delete(scm_error(ScmCall::DeleteService, 1060)).means_service_is_gone());
    assert!(!RetireError::Drain(scm_error(ScmCall::QueryServiceStatusEx, 1072)).means_service_is_gone());
    assert!(!RetireError::Exit(scm_error(ScmCall::WaitForSingleObject, 1060)).means_service_is_gone());
}

/// The error a caller prints must name the call and the code (F1): the
/// retirement's step wraps it, and neither hides it.
#[skuld::test]
fn a_failed_step_reads_with_its_call_and_its_code() {
    let message = RetireError::Delete(scm_error(ScmCall::DeleteService, 5)).to_string();
    assert!(
        message.starts_with("the service could not be deleted: DeleteService failed"),
        "{message}"
    );
    assert!(message.contains('5'), "{message}");
}

/// The SCM can keep reporting a live state for a process that has gone. The
/// drain acts on the process, not the status: it waits the held processes out,
/// looks once more, and is done, with no Stop, no arm and no re-query loop.
#[skuld::test]
fn a_status_that_lags_the_process_exit_is_drained_without_polling() {
    for lagging in [Observed::StartPending, Observed::Running, Observed::StopPending] {
        let log = Log::default();
        let mut session = FakeSession::new(&log, vec![Observed::Stopped], vec![Observed::Stopped]).with_looks(vec![
            look(Observed::Stopped),
            stale(lagging),
            stale(lagging),
        ]);
        retire(&mut session, Disposition::Deregister).unwrap_or_else(|e| panic!("{lagging:?}: {e}"));
        let log = log.borrow();
        let after = &log[position(&log, "delete")..];
        assert_eq!(
            after,
            ["delete", "observe", "await_exits", "observe"],
            "{lagging:?}: {log:?}"
        );
    }
}

/// The bridge dies as the drain's Stop is sent: the Stop fails and the status
/// still says RUNNING. The process has exited, so the failure is explained.
#[skuld::test]
fn a_refused_stop_after_the_delete_on_a_status_that_lags_the_process_exit_is_not_a_failure() {
    let log = Log::default();
    let mut session = FakeSession::new(&log, vec![Observed::Stopped], vec![Observed::Stopped])
        .with_looks(vec![
            look(Observed::Stopped),
            look(Observed::Running),
            stale(Observed::Running),
            stale(Observed::Running),
        ])
        .failing("control_stop");
    retire(&mut session, Disposition::Deregister).unwrap();
    let log = log.borrow();
    assert_eq!(count(&log, "control_stop"), 1, "{log:?}");
}

/// With a live process the refusal stands: the process is there to have taken it.
#[skuld::test]
fn a_refused_stop_after_the_delete_on_a_live_process_is_still_the_drains_failure() {
    let log = Log::default();
    let mut session = FakeSession::new(&log, vec![Observed::Stopped], vec![Observed::Stopped])
        .with_looks(vec![
            look(Observed::Stopped),
            look(Observed::Running),
            look(Observed::Running),
        ])
        .failing("control_stop");
    let err = retire(&mut session, Disposition::Deregister).expect_err("still running");
    assert!(matches!(err, RetireError::Drain(_)), "{err}");
}

/// A live state with no process held leaves no process exit to wait on. The
/// only event left is the SCM's own, so the drain takes the stop wait rather
/// than looking again in a loop.
#[skuld::test]
fn a_live_state_with_no_process_held_after_the_delete_waits_on_the_scm_not_on_a_loop() {
    let log = Log::default();
    let mut session = FakeSession::new(
        &log,
        // the first stop, then the drain's stop wait
        vec![Observed::Stopped, Observed::Stopped],
        vec![],
    )
    .with_looks(vec![
        look(Observed::Stopped),
        Look {
            observed: Observed::StopPending,
            fate: ProcessFate::Unheld,
            held_alive: false,
        },
        look(Observed::Stopped),
        look(Observed::Stopped),
    ]);
    retire(&mut session, Disposition::Deregister).unwrap();
    let log = log.borrow();
    let after = &log[position(&log, "delete")..];
    assert_eq!(count(after, "arm"), 1, "{log:?}");
    assert_eq!(count(after, "observe"), 3, "{log:?}");
}

/// A refused open of the service's process is not the service failing to stop
/// (or to be read, or to drain): it names its own step, and the call and code.
#[skuld::test]
fn a_refused_process_open_in_the_stop_wait_is_its_own_failure_not_the_stop() {
    let log = Log::default();
    let mut session = FakeSession::new(&log, vec![Observed::Running], vec![Observed::Running])
        .refusing_the_process_open_at("hold", 1);
    let err = retire(&mut session, Disposition::Deregister).expect_err("the open was refused");
    assert!(matches!(err, RetireError::Hold(_)), "{err}");
    let message = err.to_string();
    assert!(message.contains("OpenProcess failed"), "{message}");
    assert!(!err.means_service_is_gone());
    assert!(!log.borrow().contains(&"delete"), "{:?}", log.borrow());
}

#[skuld::test]
fn a_refused_process_open_on_the_first_look_is_its_own_failure_not_a_failed_read() {
    let log = Log::default();
    let mut session = FakeSession::new(&log, vec![], vec![]).refusing_the_process_open_at("observe", 1);
    let err = retire(&mut session, Disposition::Deregister).expect_err("the open was refused");
    assert!(matches!(err, RetireError::Hold(_)), "{err}");
    assert_eq!(*log.borrow(), vec!["observe"]);
}

#[skuld::test]
fn a_refused_process_open_in_the_drain_is_its_own_failure_not_a_failed_confirmation() {
    let log = Log::default();
    let mut session = FakeSession::new(
        &log,
        vec![Observed::Stopped],
        vec![Observed::Stopped, Observed::Stopped],
    )
    .refusing_the_process_open_at("observe", 2);
    let err = retire(&mut session, Disposition::Deregister).expect_err("the open was refused");
    assert!(matches!(err, RetireError::Hold(_)), "{err}");
}

/// Only the open of the process has its own step: any other SCM call failing
/// in a step is that step's failure.
#[skuld::test]
fn other_scm_failures_stay_with_their_step() {
    let log = Log::default();
    let mut session = FakeSession::new(&log, vec![Observed::Stopped], vec![Observed::Stopped]).failing("delete");
    let err = retire(&mut session, Disposition::Deregister).expect_err("the delete failed");
    assert!(matches!(err, RetireError::Delete(_)), "{err}");
    assert!(!matches!(
        RetireError::of_step(RetireError::Stop, scm_error(ScmCall::ControlService, 5)),
        RetireError::Hold(_)
    ));
}

/// The stop wait reads each callback's process through the session: a
/// callback over a process that has already exited earns no Stop.
#[skuld::test]
fn a_callback_over_a_process_that_has_exited_ends_the_stop_wait_with_no_stop() {
    let log = Log::default();
    let mut session = FakeSession::new(
        &log,
        vec![Observed::Running],
        vec![Observed::Running, Observed::Stopped, Observed::Stopped],
    )
    .with_wait_fates(vec![ProcessFate::Exited]);
    retire(&mut session, Disposition::Deregister).unwrap();
    let log = log.borrow();
    assert!(!log.contains(&"control_stop"), "{log:?}");
    assert_eq!(count(&log, "hold"), 1, "{log:?}");
}
