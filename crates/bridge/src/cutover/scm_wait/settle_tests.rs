use std::collections::VecDeque;

use super::*;
use crate::cutover::scm_wait::call_error::{service_gone, ScmCall, ScmCallError, ServiceGone};

// The look table ======================================================================================================

fn look(observed: Observed, fate: ProcessFate, held_alive: bool) -> Look {
    Look {
        observed,
        fate,
        held_alive,
        // A live hold was held.
        ever_held: held_alive,
    }
}

/// A look after every process held so far has exited.
fn look_after_holds_exited(observed: Observed, fate: ProcessFate) -> Look {
    Look {
        observed,
        fate,
        held_alive: false,
        ever_held: true,
    }
}

/// STOPPED, nothing held alive.
fn stopped() -> Look {
    look(Observed::Stopped, ProcessFate::Unheld, false)
}

/// STOPPED, but a process held earlier has not exited.
fn stopped_over_a_live_hold() -> Look {
    look(Observed::Stopped, ProcessFate::Unheld, true)
}

/// RUNNING over a held, live process.
fn running() -> Look {
    look(Observed::Running, ProcessFate::Alive, true)
}

/// RUNNING over a process no hold could be made on (no service SID).
fn running_unheld() -> Look {
    look(Observed::Running, ProcessFate::Unheld, false)
}

/// RUNNING whose process has exited while the status still says so.
fn running_over_an_exited_process() -> Look {
    look(Observed::Running, ProcessFate::Exited, false)
}

fn pending(observed: Observed) -> Look {
    look(observed, ProcessFate::Unheld, false)
}

/// Every (state, fate, held_alive) the step is decided on, written out from the
/// contract: only a RUNNING status over a process that has not exited takes a
/// Stop; STOPPED is final only with nothing held alive; every other state is
/// left by the SCM's own transition, whatever the fate (an id read in a pending
/// state may name another process), and a live hold does not turn a pending
/// state into a wait on the hold.
#[skuld::test]
fn the_step_for_every_state_fate_and_hold() {
    use ProcessFate::{Alive, Exited, Unheld};
    use SettleStep::{AwaitChange, AwaitHeldExit, Quiescent, SendStop};
    // The waits to leave RUNNING, START_PENDING and STOP_PENDING.
    let (leave_running, leave_starting, leave_stopping) = (
        AwaitChange(Observed::Running),
        AwaitChange(Observed::StartPending),
        AwaitChange(Observed::StopPending),
    );
    let table = [
        (Observed::Running, Unheld, false, SendStop),
        (Observed::Running, Unheld, true, SendStop),
        (Observed::Running, Alive, false, SendStop),
        (Observed::Running, Alive, true, SendStop),
        (Observed::Running, Exited, false, leave_running),
        (Observed::Running, Exited, true, leave_running),
        (Observed::StartPending, Unheld, false, leave_starting),
        (Observed::StartPending, Unheld, true, leave_starting),
        (Observed::StartPending, Alive, false, leave_starting),
        (Observed::StartPending, Alive, true, leave_starting),
        (Observed::StartPending, Exited, false, leave_starting),
        (Observed::StartPending, Exited, true, leave_starting),
        (Observed::StopPending, Unheld, false, leave_stopping),
        (Observed::StopPending, Unheld, true, leave_stopping),
        (Observed::StopPending, Alive, false, leave_stopping),
        (Observed::StopPending, Alive, true, leave_stopping),
        (Observed::StopPending, Exited, false, leave_stopping),
        (Observed::StopPending, Exited, true, leave_stopping),
        (Observed::Stopped, Unheld, false, Quiescent),
        (Observed::Stopped, Unheld, true, AwaitHeldExit),
        (Observed::Stopped, Alive, false, Quiescent),
        (Observed::Stopped, Alive, true, AwaitHeldExit),
        (Observed::Stopped, Exited, false, Quiescent),
        (Observed::Stopped, Exited, true, AwaitHeldExit),
    ];
    for (observed, fate, held_alive, want) in table {
        let got = look(observed, fate, held_alive).settle_step();
        assert_eq!(got, want, "{observed:?} {fate:?} held_alive={held_alive}");
    }
}

#[skuld::test]
fn only_a_stopped_service_with_nothing_alive_ends_the_wait_and_only_running_takes_a_stop() {
    use SettleStep::{AwaitChange, AwaitHeldExit, Quiescent, SendStop};
    let table = [
        (Quiescent, true, false),
        (SendStop, false, true),
        (AwaitHeldExit, false, false),
        (AwaitChange(Observed::Running), false, false),
        (AwaitChange(Observed::StartPending), false, false),
        (AwaitChange(Observed::StopPending), false, false),
        (AwaitChange(Observed::Stopped), false, false),
    ];
    for (step, ends, takes_a_stop) in table {
        assert_eq!(step.ends_the_wait(), ends, "{step:?}");
        assert_eq!(step.is_a_stop_the_service_takes(), takes_a_stop, "{step:?}");
    }
}

#[skuld::test]
fn what_follows_an_accepted_stop_is_told_by_the_process_fate() {
    assert_eq!(ProcessFate::Alive.wait_after_stop(), StopWait::HeldProcess);
    assert_eq!(ProcessFate::Unheld.wait_after_stop(), StopWait::StatusChange);
    assert_eq!(ProcessFate::Exited.wait_after_stop(), StopWait::StatusChange);
}

// The loop on a recording actor =======================================================================================

fn marked() -> io::Error {
    ScmCallError {
        call: ScmCall::NotifyServiceStatusChange,
        code: 1072,
    }
    .into_io()
}

/// An actor that records every call in order and answers from a script. A script
/// that runs dry panics, so a loop that would spin fails instead of hanging.
#[derive(Default)]
struct Recording {
    log: Vec<String>,
    looks: VecDeque<Look>,
    /// One entry per `arm_leaving` call; `None` is success. Success once it runs dry.
    arms: VecDeque<Option<io::Error>>,
    /// One entry per `control_stop` call; `None` is acceptance. Acceptance once it runs dry.
    stops: VecDeque<Option<io::Error>>,
    /// The error the next call of this wait fails with, once.
    await_callback_error: Option<io::Error>,
    await_exit_error: Option<io::Error>,
    scan_error: Option<io::Error>,
    /// What each scan finds, in order. Nothing once it runs dry.
    findings: VecDeque<ScanFinding>,
}

impl Recording {
    fn new(looks: Vec<Look>) -> Self {
        Self {
            looks: looks.into(),
            ..Default::default()
        }
    }

    fn arm_fails_with(mut self, errors: Vec<Option<io::Error>>) -> Self {
        self.arms = errors.into();
        self
    }

    fn stop_fails_with(mut self, errors: Vec<Option<io::Error>>) -> Self {
        self.stops = errors.into();
        self
    }

    fn await_callback_fails_with(mut self, error: io::Error) -> Self {
        self.await_callback_error = Some(error);
        self
    }

    fn await_exit_fails_with(mut self, error: io::Error) -> Self {
        self.await_exit_error = Some(error);
        self
    }

    fn scan_fails_with(mut self, error: io::Error) -> Self {
        self.scan_error = Some(error);
        self
    }

    fn scans_find(mut self, findings: Vec<ScanFinding>) -> Self {
        self.findings = findings.into();
        self
    }

    fn log(&self) -> Vec<&str> {
        self.log.iter().map(String::as_str).collect()
    }

    fn count(&self, entry: &str) -> usize {
        self.log.iter().filter(|logged| *logged == entry).count()
    }
}

impl StopActor for Recording {
    fn observe(&mut self) -> io::Result<Look> {
        self.log.push("observe".into());
        Ok(self.looks.pop_front().expect("the look script ran dry"))
    }

    fn arm_leaving(&mut self, from: Observed) -> io::Result<()> {
        self.log.push(format!("arm_leaving({from:?})"));
        self.arms.pop_front().flatten().map_or(Ok(()), Err)
    }

    fn control_stop(&mut self) -> io::Result<()> {
        self.log.push("control_stop".into());
        self.stops.pop_front().flatten().map_or(Ok(()), Err)
    }

    fn await_callback(&mut self) -> io::Result<()> {
        self.log.push("await_callback".into());
        self.await_callback_error.take().map_or(Ok(()), Err)
    }

    fn await_held_exits(&mut self) -> io::Result<()> {
        self.log.push("await_held_exits".into());
        self.await_exit_error.take().map_or(Ok(()), Err)
    }

    fn hold_scanned(&mut self) -> io::Result<ScanFinding> {
        self.log.push("hold_scanned".into());
        self.scan_error
            .take()
            .map_or(Ok(self.findings.pop_front().unwrap_or(ScanFinding::Nothing)), Err)
    }
}

#[skuld::test]
fn a_stopped_service_is_settled_only_after_the_scan_finds_nothing() {
    let mut actor = Recording::new(vec![stopped(), stopped()]);
    settle_stopped(&mut actor).unwrap();
    assert_eq!(actor.log(), ["observe", "hold_scanned", "observe"]);
}

/// STOPPED from the first look: something stopped the service a moment before,
/// and its process may be alive. The scan finds it; the loop waits it out and
/// scans again.
#[skuld::test]
fn a_process_the_scan_finds_after_stopped_is_waited_out() {
    let mut actor = Recording::new(vec![stopped(), stopped_over_a_live_hold(), stopped(), stopped()]);
    settle_stopped(&mut actor).unwrap();
    assert_eq!(
        actor.log(),
        [
            "observe",
            "hold_scanned",
            "observe",
            "await_held_exits",
            "observe",
            "hold_scanned",
            "observe",
        ]
    );
}

#[skuld::test]
fn a_stopped_service_with_a_live_hold_is_waited_on_and_looked_at_again() {
    let mut actor = Recording::new(vec![stopped_over_a_live_hold(), stopped(), stopped()]);
    settle_stopped(&mut actor).unwrap();
    assert_eq!(
        actor.log(),
        ["observe", "await_held_exits", "observe", "hold_scanned", "observe"]
    );
}

/// A held process takes the Stop and is waited on by its handle: a handle keeps
/// its id from being reused, so no arm is needed.
#[skuld::test]
fn a_stop_to_a_held_process_waits_on_the_process_and_arms_nothing() {
    let mut actor = Recording::new(vec![running(), stopped(), stopped()]);
    settle_stopped(&mut actor).unwrap();
    assert_eq!(
        actor.log(),
        [
            "observe",
            "control_stop",
            "await_held_exits",
            "observe",
            "hold_scanned",
            "observe",
        ]
    );
}

/// With no process to wait on the SCM's reaction to the Stop is the only event.
/// It is armed leaving RUNNING BEFORE the Stop, so the Stop's effect is an entry
/// into a state the arm names, whether the service stays down or is restarted at
/// once.
#[skuld::test]
fn a_stop_to_an_unheld_process_arms_before_it_is_sent() {
    let mut actor = Recording::new(vec![running_unheld(), stopped(), stopped()]);
    settle_stopped(&mut actor).unwrap();
    assert_eq!(
        actor.log(),
        [
            "observe",
            "arm_leaving(Running)",
            "control_stop",
            "await_callback",
            "observe",
            "hold_scanned",
            "observe",
        ]
    );
}

/// The service the Stop reached is restarted at once and the next look finds it
/// RUNNING again: it is a new RUNNING observation, stopped again.
#[skuld::test]
fn a_service_restarted_after_the_stop_is_stopped_again() {
    let mut actor = Recording::new(vec![running_unheld(), running_unheld(), stopped(), stopped()]);
    settle_stopped(&mut actor).unwrap();
    assert_eq!(actor.count("control_stop"), 2);
    assert_eq!(actor.count("arm_leaving(Running)"), 2);
    assert_eq!(actor.count("await_callback"), 2);
}

/// The stop is refused and the service is still RUNNING over a process: the
/// refusal is the answer, and nothing waits for a service that takes no Stop.
#[skuld::test]
fn a_stop_refused_by_a_service_that_stays_running_is_an_error() {
    for first in [running(), running_unheld()] {
        let mut actor = Recording::new(vec![first, first]).stop_fails_with(vec![Some(io::Error::other("refused"))]);
        let error = settle_stopped(&mut actor).unwrap_err();
        assert!(
            matches!(&error, SettleError::Stop(e) if e.to_string() == "refused"),
            "{first:?}: {error:?}"
        );
        assert_eq!(actor.count("control_stop"), 1, "{first:?}");
        assert_eq!(actor.count("await_held_exits"), 0, "{first:?}");
        assert_eq!(actor.count("await_callback"), 0, "{first:?}");
        // The look that decided it is a query, not a re-arm.
        let log = actor.log();
        assert_eq!(*log.last().unwrap(), "observe", "{first:?}");
    }
}

/// A Stop sent on a RUNNING look can find the service already on its way out.
#[skuld::test]
fn a_stop_refused_by_a_service_that_has_left_running_is_not_an_error() {
    // Already STOPPED: scan and settle.
    let mut actor = Recording::new(vec![running(), stopped(), stopped()])
        .stop_fails_with(vec![Some(io::Error::other("not active"))]);
    settle_stopped(&mut actor).unwrap();
    assert_eq!(actor.count("control_stop"), 1);

    // Already STOP_PENDING: the SCM's own transition is waited for.
    let mut actor = Recording::new(vec![
        running_unheld(),
        pending(Observed::StopPending),
        pending(Observed::StopPending),
        stopped(),
        stopped(),
    ])
    .stop_fails_with(vec![Some(io::Error::other("cannot accept"))]);
    settle_stopped(&mut actor).unwrap();
    assert_eq!(actor.count("control_stop"), 1);
    assert_eq!(actor.count("await_callback"), 1);
}

/// A look taken after the arm that is no longer the wait the arm was for means
/// the arm's mask does not cover where the service is: it is dropped, not slept on.
#[skuld::test]
fn an_arm_is_not_slept_on_when_the_look_after_it_asks_for_something_else() {
    // STOP_PENDING, then the service is already STOPPED once the arm is in.
    let mut actor = Recording::new(vec![pending(Observed::StopPending), stopped(), stopped()]);
    settle_stopped(&mut actor).unwrap();
    assert_eq!(
        actor.log(),
        [
            "observe",
            "arm_leaving(StopPending)",
            "observe",
            "hold_scanned",
            "observe"
        ]
    );
}

/// RUNNING over a process that has exited, the SCM not yet caught up: a restart
/// completes between the look and the arm. The arm excludes RUNNING, so it never
/// fires for the new instance; the look after it finds the new one and stops it.
#[skuld::test]
fn a_restart_that_completed_between_the_look_and_the_arm_is_stopped_not_slept_on() {
    let mut actor = Recording::new(vec![running_over_an_exited_process(), running(), stopped(), stopped()]);
    settle_stopped(&mut actor).unwrap();
    assert_eq!(
        actor.log(),
        [
            "observe",
            "arm_leaving(Running)",
            "observe",
            "control_stop",
            "await_held_exits",
            "observe",
            "hold_scanned",
            "observe",
        ]
    );
}

/// The same look after the arm: the arm is for exactly this wait, and the loop sleeps once.
#[skuld::test]
fn an_arm_followed_by_the_same_look_is_slept_on_once() {
    for state in [Observed::StartPending, Observed::StopPending] {
        let mut actor = Recording::new(vec![pending(state), pending(state), stopped(), stopped()]);
        settle_stopped(&mut actor).unwrap();
        assert_eq!(
            actor.log(),
            [
                "observe".to_string(),
                format!("arm_leaving({state:?})"),
                "observe".to_string(),
                "await_callback".to_string(),
                "observe".to_string(),
                "hold_scanned".to_string(),
                "observe".to_string(),
            ],
            "{state:?}"
        );
    }
}

/// The SCM catching up on an exit it can already see is waited on by its
/// notification, once.
#[skuld::test]
fn the_scm_catching_up_on_an_exit_is_waited_on_by_its_notification() {
    let mut actor = Recording::new(vec![
        running_over_an_exited_process(),
        running_over_an_exited_process(),
        stopped(),
        stopped(),
    ]);
    settle_stopped(&mut actor).unwrap();
    assert_eq!(actor.count("await_callback"), 1);
}

/// An arm on a service marked for deletion is refused and the handle must be
/// closed. The service still queries and takes a Stop, so the loop waits on the
/// processes it holds instead.
#[skuld::test]
fn a_service_marked_for_deletion_is_waited_out_on_its_processes() {
    let mut actor = Recording::new(vec![
        pending(Observed::StopPending),
        look(Observed::StopPending, ProcessFate::Alive, true),
        stopped(),
        stopped(),
    ])
    .arm_fails_with(vec![Some(marked())]);
    settle_stopped(&mut actor).unwrap();
    assert_eq!(
        actor.log(),
        [
            "observe",
            "arm_leaving(StopPending)",
            "hold_scanned",
            "observe",
            "await_held_exits",
            "observe",
            "hold_scanned",
            "observe",
        ]
    );
}

/// Once the SCM has refused an arm, no later wait tries one.
#[skuld::test]
fn no_arm_is_made_after_the_scm_refused_one() {
    let held = look(Observed::StopPending, ProcessFate::Alive, true);
    let mut actor = Recording::new(vec![
        pending(Observed::StartPending),
        held,
        pending(Observed::StopPending),
        held,
        stopped(),
        stopped(),
    ])
    .arm_fails_with(vec![Some(marked())]);
    settle_stopped(&mut actor).unwrap();
    assert_eq!(actor.count("arm_leaving(StartPending)"), 1);
    assert_eq!(actor.count("arm_leaving(StopPending)"), 0);
    assert_eq!(actor.count("await_callback"), 0);
    assert_eq!(actor.count("await_held_exits"), 2);
}

/// Marked, the held process has exited and the scan finds nothing alive, but
/// the SCM still reports STOP_PENDING: no process is left, and no arm can be
/// made to learn more from the SCM, so the wait is over.
#[skuld::test]
fn a_marked_service_whose_held_processes_have_exited_is_settled_though_the_scm_lags() {
    for lagging in [Observed::StopPending, Observed::StartPending] {
        let mut actor = Recording::new(vec![
            look(lagging, ProcessFate::Alive, true),
            look_after_holds_exited(lagging, ProcessFate::Exited),
        ])
        .arm_fails_with(vec![Some(marked())]);
        settle_stopped(&mut actor).unwrap();
        assert_eq!(
            actor.log(),
            [
                "observe",
                format!("arm_leaving({lagging:?})").as_str(),
                "hold_scanned",
                "observe"
            ],
            "{lagging:?}"
        );
    }
}

/// The same for RUNNING over an exited process: the Stop is not sent, no arm is
/// possible, and the scan decides.
#[skuld::test]
fn a_marked_running_service_over_an_exited_process_is_settled_when_the_scan_finds_nothing() {
    let mut actor = Recording::new(vec![
        look_after_holds_exited(Observed::Running, ProcessFate::Exited),
        look_after_holds_exited(Observed::Running, ProcessFate::Exited),
    ])
    .arm_fails_with(vec![Some(marked())]);
    settle_stopped(&mut actor).unwrap();
    assert_eq!(actor.count("control_stop"), 0);
    assert_eq!(
        actor.log(),
        ["observe", "arm_leaving(Running)", "hold_scanned", "observe"]
    );
}

/// Marked, RUNNING over an id no process has: nothing was ever held, but the
/// look itself shows the service's process gone, and a scan that finds nothing
/// says nothing else carries the token.
#[skuld::test]
fn a_marked_running_service_over_an_id_no_process_has_is_settled_when_the_scan_finds_nothing() {
    let mut actor = Recording::new(vec![running_over_an_exited_process(), running_over_an_exited_process()])
        .arm_fails_with(vec![Some(marked())]);
    settle_stopped(&mut actor).unwrap();
    assert_eq!(actor.count("control_stop"), 0);
    assert_eq!(
        actor.log(),
        ["observe", "arm_leaving(Running)", "hold_scanned", "observe"]
    );
}

/// Marked, and the scan lost a listed process: the look shows nothing alive,
/// but only a scan that finds nothing settles, so the scan is made again.
#[skuld::test]
fn a_marked_service_is_scanned_again_after_a_scan_that_lost_a_process() {
    let gone = look_after_holds_exited(Observed::StopPending, ProcessFate::Exited);
    let mut actor = Recording::new(vec![pending(Observed::StopPending), gone, gone])
        .arm_fails_with(vec![Some(marked())])
        .scans_find(vec![ScanFinding::Vanished, ScanFinding::Nothing]);
    settle_stopped(&mut actor).unwrap();
    assert_eq!(
        actor.log(),
        [
            "observe",
            "arm_leaving(StopPending)",
            "hold_scanned",
            "observe",
            "hold_scanned",
            "observe"
        ]
    );
}

/// STOPPED with nothing held alive is final only on a scan that found nothing:
/// one that lost a listed process, or found one that has exited since, is made
/// again, and the wait does not end on the look after it.
#[skuld::test]
fn a_stopped_service_is_scanned_again_until_a_scan_finds_nothing() {
    let mut actor = Recording::new(vec![stopped(), stopped(), stopped(), stopped()]).scans_find(vec![
        ScanFinding::Vanished,
        ScanFinding::Alive,
        ScanFinding::Nothing,
    ]);
    settle_stopped(&mut actor).unwrap();
    assert_eq!(actor.count("hold_scanned"), 3);
    assert_eq!(actor.log().last(), Some(&"observe"));
}

/// A live state with no process to wait on and no arm: the only event left is
/// the SCM's, which cannot be asked for. The refusal that says why is the result.
#[skuld::test]
fn a_marked_service_with_no_process_to_wait_on_fails_with_the_refusal() {
    let mut actor = Recording::new(vec![pending(Observed::StopPending), pending(Observed::StopPending)])
        .arm_fails_with(vec![Some(marked())]);
    let error = settle_stopped(&mut actor).unwrap_err();
    let SettleError::Arm(refusal) = &error else {
        panic!("the arm's refusal is the result: {error:?}")
    };
    assert_eq!(service_gone(refusal), Some(ServiceGone::MarkedForDeletion));
    assert_eq!(actor.count("await_callback"), 0);
    assert_eq!(actor.count("await_held_exits"), 0);
}

/// Marked, RUNNING over a process no hold could name: the Stop goes without an
/// arm, and what follows is the scan's, not a sleep.
#[skuld::test]
fn a_stop_to_a_marked_unheld_service_is_sent_without_an_arm() {
    let mut actor = Recording::new(vec![running_unheld(), stopped(), stopped()]).arm_fails_with(vec![Some(marked())]);
    settle_stopped(&mut actor).unwrap();
    assert_eq!(
        actor.log(),
        [
            "observe",
            "arm_leaving(Running)",
            "control_stop",
            "hold_scanned",
            "observe",
            "hold_scanned",
            "observe",
        ]
    );
    assert_eq!(actor.count("await_callback"), 0);
}

#[skuld::test]
fn an_arm_that_fails_for_any_other_reason_ends_the_wait_before_the_stop() {
    for code in [1060, 5, 1061] {
        let mut actor =
            Recording::new(vec![running_unheld()]).arm_fails_with(vec![Some(io::Error::from_raw_os_error(code))]);
        let error = settle_stopped(&mut actor).unwrap_err();
        assert!(
            matches!(&error, SettleError::Arm(e) if e.raw_os_error() == Some(code)),
            "{code}: {error:?}"
        );
        assert_eq!(actor.count("control_stop"), 0, "{code}");
    }
}

#[skuld::test]
fn a_query_that_fails_ends_the_wait() {
    struct Failing;
    impl StopActor for Failing {
        fn observe(&mut self) -> io::Result<Look> {
            Err(io::Error::other("query failed"))
        }
        fn arm_leaving(&mut self, _: Observed) -> io::Result<()> {
            unreachable!()
        }
        fn control_stop(&mut self) -> io::Result<()> {
            unreachable!()
        }
        fn await_callback(&mut self) -> io::Result<()> {
            unreachable!()
        }
        fn await_held_exits(&mut self) -> io::Result<()> {
            unreachable!()
        }
        fn hold_scanned(&mut self) -> io::Result<ScanFinding> {
            unreachable!()
        }
    }
    let error = settle_stopped(&mut Failing).unwrap_err();
    assert!(
        matches!(&error, SettleError::Observe(e) if e.to_string() == "query failed"),
        "{error:?}"
    );
}

/// Each act that can fail names itself in the error, so the retirement's
/// policy per step does not have to guess it from the text.
#[skuld::test]
fn each_failing_act_is_its_own_error_variant() {
    let failure = || io::Error::other("failed");
    // The scan after STOPPED.
    let error = settle_stopped(&mut Recording::new(vec![stopped()]).scan_fails_with(failure())).unwrap_err();
    assert!(matches!(error, SettleError::Scan(_)), "{error:?}");
    // The wait on a held process after an accepted Stop.
    let error = settle_stopped(&mut Recording::new(vec![running()]).await_exit_fails_with(failure())).unwrap_err();
    assert!(matches!(error, SettleError::AwaitExit(_)), "{error:?}");
    // The sleep on the SCM's notification.
    let looks = vec![pending(Observed::StopPending), pending(Observed::StopPending)];
    let error = settle_stopped(&mut Recording::new(looks).await_callback_fails_with(failure())).unwrap_err();
    assert!(matches!(error, SettleError::AwaitChange(_)), "{error:?}");
    // A look after the first.
    struct FailsOnTheSecondLook(u8);
    impl StopActor for FailsOnTheSecondLook {
        fn observe(&mut self) -> io::Result<Look> {
            self.0 += 1;
            if self.0 == 1 {
                Ok(stopped())
            } else {
                Err(io::Error::other("failed"))
            }
        }
        fn arm_leaving(&mut self, _: Observed) -> io::Result<()> {
            unreachable!()
        }
        fn control_stop(&mut self) -> io::Result<()> {
            unreachable!()
        }
        fn await_callback(&mut self) -> io::Result<()> {
            unreachable!()
        }
        fn await_held_exits(&mut self) -> io::Result<()> {
            unreachable!()
        }
        fn hold_scanned(&mut self) -> io::Result<ScanFinding> {
            Ok(ScanFinding::Nothing)
        }
    }
    let error = settle_stopped(&mut FailsOnTheSecondLook(0)).unwrap_err();
    assert!(matches!(error, SettleError::Observe(_)), "{error:?}");
}

/// The cutover reads the failure as the one the SCM or the OS gave.
#[skuld::test]
fn a_settle_error_gives_back_the_error_it_carries() {
    for error in [
        SettleError::Observe(io::Error::from_raw_os_error(5)),
        SettleError::Arm(io::Error::from_raw_os_error(5)),
        SettleError::Stop(io::Error::from_raw_os_error(5)),
        SettleError::AwaitChange(io::Error::from_raw_os_error(5)),
        SettleError::Scan(io::Error::from_raw_os_error(5)),
        SettleError::AwaitExit(io::Error::from_raw_os_error(5)),
    ] {
        assert_eq!(error.into_io().raw_os_error(), Some(5));
    }
}

// The loop on a model host ============================================================================================

use crate::cutover::scm_wait::world_tests::{Act, StoppedService, When, World};

/// The stop wait over a STOPPED service whose processes the model host runs.
struct ModelStop(StoppedService);

impl StopActor for ModelStop {
    fn observe(&mut self) -> io::Result<Look> {
        self.0.look()
    }

    fn arm_leaving(&mut self, _: Observed) -> io::Result<()> {
        unreachable!("a STOPPED service is not armed on")
    }

    fn control_stop(&mut self) -> io::Result<()> {
        unreachable!("a STOPPED service takes no Stop")
    }

    fn await_callback(&mut self) -> io::Result<()> {
        unreachable!("a STOPPED service is not armed on")
    }

    fn await_held_exits(&mut self) -> io::Result<()> {
        self.0.await_exits();
        Ok(())
    }

    fn hold_scanned(&mut self) -> io::Result<ScanFinding> {
        let mut host = self.0.world.host();
        self.0.holds.hold_scanned(&mut host).map(|scanned| scanned.finding)
    }
}

fn settle_on(world: &World) {
    settle_stopped(&mut ModelStop(StoppedService::new(world))).unwrap();
    assert_eq!(
        world.alive(),
        Vec::<u32>::new(),
        "the wait returned with a process of the service alive"
    );
}

/// A process the scan holds starts a child after the snapshot and exits before
/// the look: the look finds nothing alive among the holds, but the child runs.
#[skuld::test]
fn a_child_started_after_the_snapshot_by_a_process_that_then_exits_is_waited_out() {
    let world = World::new(
        &[10],
        vec![
            (When::AfterOpen(10), Act::Spawn(11)),
            (When::AfterOpen(10), Act::Exit(10)),
        ],
    );
    settle_on(&world);
}

/// A process in the snapshot starts a child and vanishes before it is probed:
/// the child is not in the snapshot and nothing was held.
#[skuld::test]
fn a_child_started_by_a_process_that_vanished_before_its_probe_is_waited_out() {
    let world = World::new(
        &[10],
        vec![
            (When::AfterSnapshot(1), Act::Spawn(11)),
            (When::AfterSnapshot(1), Act::Vanish(10)),
        ],
    );
    settle_on(&world);
}

/// The same, again and again: each child starts one and exits.
#[skuld::test]
fn a_chain_of_children_each_exiting_before_the_next_look_is_waited_out() {
    let world = World::new(
        &[10],
        vec![
            (When::AfterOpen(10), Act::Spawn(11)),
            (When::AfterOpen(10), Act::Exit(10)),
            (When::AfterOpen(11), Act::Spawn(12)),
            (When::AfterOpen(11), Act::Vanish(11)),
        ],
    );
    settle_on(&world);
}
