use super::*;
use std::cell::RefCell;

/// Records the granular SCM steps in call order and replays a scripted `Observed`
/// for each `wait_callback`. The script asserts the pure ordering of
/// `stop_via_notify` / `start_via_notify` without touching the real SCM.
struct FakeScm<'a> {
    log: &'a RefCell<Vec<&'static str>>,
    /// `Observed`s the next `wait_callback` calls return, front to back.
    waits: std::collections::VecDeque<Observed>,
    /// Total `arm` calls, so the two-phase-arm re-arm behavior is checkable.
    arms: usize,
    /// When set, `arm` / `control_stop` log the call and then fail with it.
    arm_error: Option<&'static str>,
    /// What `control_stop` fails with, for its first `control_errors_left` calls.
    control_error: Option<&'static str>,
    control_errors_left: usize,
}

impl<'a> FakeScm<'a> {
    fn new(log: &'a RefCell<Vec<&'static str>>, waits: std::collections::VecDeque<Observed>) -> Self {
        Self {
            log,
            waits,
            arms: 0,
            arm_error: None,
            control_error: None,
            control_errors_left: 0,
        }
    }

    /// `control_stop` fails with `error` on its first `times` calls.
    fn failing_control(mut self, error: &'static str, times: usize) -> Self {
        self.control_error = Some(error);
        self.control_errors_left = times;
        self
    }

    /// A scripted actor with no call log, for the terminal-state assertions.
    fn scripted(waits: Vec<Observed>) -> ScriptedScm {
        ScriptedScm {
            waits: waits.into(),
            arms: 0,
        }
    }
}

impl ScmActor for FakeScm<'_> {
    fn arm(&mut self, want: WantState, except: Option<Observed>) -> std::io::Result<()> {
        self.arms += 1;
        self.log.borrow_mut().push(arm_label(want, except));
        self.arm_error.map_or(Ok(()), |e| Err(std::io::Error::other(e)))
    }
    fn control_stop(&mut self) -> std::io::Result<()> {
        self.log.borrow_mut().push("control_stop");
        if self.control_errors_left > 0 {
            self.control_errors_left -= 1;
            return Err(std::io::Error::other(self.control_error.expect("a scripted error")));
        }
        Ok(())
    }
    fn start(&mut self) -> std::io::Result<()> {
        self.log.borrow_mut().push("start");
        Ok(())
    }
    fn wait_callback(&mut self) -> std::io::Result<Observed> {
        self.log.borrow_mut().push("wait");
        let state = self.waits.pop_front().expect("script ran dry");
        self.log.borrow_mut().push(match state {
            Observed::Stopped => "got_stopped",
            Observed::Running => "got_running",
            Observed::StartPending => "got_start_pending",
            Observed::StopPending => "got_stop_pending",
        });
        Ok(state)
    }
}

/// The log entry for an arm: which wait, and which state it leaves out.
fn arm_label(want: WantState, except: Option<Observed>) -> &'static str {
    match (want, except) {
        (WantState::Stopped, None) => "arm_stopped",
        (WantState::Stopped, Some(Observed::Running)) => "arm_stopped_except_running",
        (WantState::Stopped, Some(Observed::Stopped)) => "arm_stopped_except_stopped",
        (WantState::Stopped, Some(Observed::StartPending)) => "arm_stopped_except_start_pending",
        (WantState::Stopped, Some(Observed::StopPending)) => "arm_stopped_except_stop_pending",
        (WantState::Running, None) => "arm_running",
        (WantState::Running, Some(Observed::Running)) => "arm_running_except_running",
        (WantState::Running, Some(Observed::Stopped)) => "arm_running_except_stopped",
        (WantState::Running, Some(Observed::StartPending)) => "arm_running_except_start_pending",
        (WantState::Running, Some(Observed::StopPending)) => "arm_running_except_stop_pending",
    }
}

/// A minimal scripted actor (no call log) that counts `arm`s — for the
/// terminal-state and re-arm-count assertions.
struct ScriptedScm {
    waits: std::collections::VecDeque<Observed>,
    arms: usize,
}

impl ScriptedScm {
    fn arm_count(&self) -> usize {
        self.arms
    }
}

impl ScmActor for ScriptedScm {
    fn arm(&mut self, _want: WantState, _except: Option<Observed>) -> std::io::Result<()> {
        self.arms += 1;
        Ok(())
    }
    fn control_stop(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn start(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn wait_callback(&mut self) -> std::io::Result<Observed> {
        Ok(self.waits.pop_front().expect("script ran dry"))
    }
}

/// A stop wait that finds the service already stopped sends nothing.
#[skuld::test]
fn stop_of_a_stopped_service_sends_no_control() {
    let log: RefCell<Vec<&'static str>> = RefCell::new(vec![]);
    let mut fake = FakeScm::new(&log, [Observed::Stopped].into());
    stop_via_notify(&mut fake).unwrap();
    assert_eq!(*log.borrow(), vec!["arm_stopped", "wait", "got_stopped"]);
}

/// The first thing the wait does is observe; a RUNNING observation is what
/// earns the Stop, and the wait then re-arms for the result.
#[skuld::test]
fn stop_of_a_running_service_sends_one_control_after_observing_running() {
    let log: RefCell<Vec<&'static str>> = RefCell::new(vec![]);
    let mut fake = FakeScm::new(
        &log,
        [Observed::Running, Observed::StopPending, Observed::Stopped].into(),
    );
    stop_via_notify(&mut fake).unwrap();
    assert_eq!(
        *log.borrow(),
        vec![
            "arm_stopped",
            "wait",
            "got_running",
            "control_stop",
            // RUNNING would report again at once; the wait is for what the Stop causes.
            "arm_stopped_except_running",
            "wait",
            "got_stop_pending",
            "arm_stopped_except_stop_pending",
            "wait",
            "got_stopped",
        ]
    );
}

/// The #1099 window: a service the SCM just restarted is START_PENDING, where
/// the SCM refuses a Stop. The wait observes first and sends nothing until the
/// service is RUNNING.
#[skuld::test]
fn stop_of_a_start_pending_service_waits_for_running_before_sending_the_control() {
    let log: RefCell<Vec<&'static str>> = RefCell::new(vec![]);
    let mut fake = FakeScm::new(
        &log,
        [
            Observed::StartPending,
            Observed::Running,
            Observed::StopPending,
            Observed::Stopped,
        ]
        .into(),
    );
    stop_via_notify(&mut fake).unwrap();
    assert_eq!(
        *log.borrow(),
        vec![
            "arm_stopped",
            "wait",
            "got_start_pending",
            "arm_stopped_except_start_pending",
            "wait",
            "got_running",
            "control_stop",
            "arm_stopped_except_running",
            "wait",
            "got_stop_pending",
            "arm_stopped_except_stop_pending",
            "wait",
            "got_stopped",
        ]
    );
}

/// A service that fails its start (START_PENDING straight to STOPPED) is
/// stopped; there is nothing to send.
#[skuld::test]
fn stop_of_a_service_that_fails_to_start_is_done_without_a_control() {
    let log: RefCell<Vec<&'static str>> = RefCell::new(vec![]);
    let mut fake = FakeScm::new(&log, [Observed::StartPending, Observed::Stopped].into());
    stop_via_notify(&mut fake).unwrap();
    assert!(!log.borrow().contains(&"control_stop"));
}

/// A service the SCM restarts while the wait is in flight (RUNNING, then back
/// through START_PENDING to RUNNING) is sent a Stop each time it is RUNNING,
/// and never while it is START_PENDING.
#[skuld::test]
fn stop_of_a_service_that_restarts_mid_wait_sends_a_control_per_running_observation() {
    let log: RefCell<Vec<&'static str>> = RefCell::new(vec![]);
    let mut fake = FakeScm::new(
        &log,
        [
            Observed::Running,
            Observed::StartPending,
            Observed::Running,
            Observed::StopPending,
            Observed::Stopped,
        ]
        .into(),
    );
    stop_via_notify(&mut fake).unwrap();
    let log = log.borrow();
    assert_eq!(log.iter().filter(|c| **c == "control_stop").count(), 2);
    assert_eq!(log.last(), Some(&"got_stopped"));
}

/// Every script the SCM can deliver: any run of non-terminal and RUNNING
/// observations, then STOPPED. A control may go out only straight after a
/// RUNNING observation, and every RUNNING observation gets one.
#[skuld::test]
fn a_stop_control_is_sent_exactly_when_running_is_observed() {
    const NON_TERMINAL: [Observed; 3] = [Observed::Running, Observed::StartPending, Observed::StopPending];
    let mut scripts: Vec<Vec<Observed>> = vec![vec![]];
    let mut frontier = scripts.clone();
    for _ in 0..4 {
        frontier = frontier
            .iter()
            .flat_map(|prefix| {
                NON_TERMINAL.iter().map(move |o| {
                    let mut next = prefix.clone();
                    next.push(*o);
                    next
                })
            })
            .collect();
        scripts.extend(frontier.iter().cloned());
    }
    assert_eq!(scripts.len(), 1 + 3 + 9 + 27 + 81);
    for prefix in scripts {
        let mut script = prefix.clone();
        script.push(Observed::Stopped);
        let log: RefCell<Vec<&'static str>> = RefCell::new(vec![]);
        let mut fake = FakeScm::new(&log, script.clone().into());
        stop_via_notify(&mut fake).unwrap();
        let log = log.borrow();
        let controls = log.iter().filter(|c| **c == "control_stop").count();
        let running = prefix.iter().filter(|o| **o == Observed::Running).count();
        assert_eq!(controls, running, "script {script:?}: {log:?}");
        for (i, call) in log.iter().enumerate() {
            if *call == "control_stop" {
                assert_eq!(log[i - 1], "got_running", "script {script:?}: {log:?}");
            }
            // Every re-arm leaves out the state the wait just acted on, so no
            // unchanged state is reported back at once.
            if i > 0 && call.starts_with("arm_stopped_except_") {
                let acted_on = match log[i - 1] {
                    "control_stop" => "running",
                    got => got
                        .strip_prefix("got_")
                        .expect("a re-arm follows an observation or a Stop"),
                };
                assert_eq!(
                    call.strip_prefix("arm_stopped_except_"),
                    Some(acted_on),
                    "script {script:?}: {log:?}"
                );
            }
            if *call == "arm_stopped" {
                assert_eq!(
                    i, 0,
                    "only the first arm asks for every state: script {script:?}: {log:?}"
                );
            }
        }
    }
}

#[skuld::test]
fn stop_surfaces_a_control_error_and_goes_no_further() {
    let log: RefCell<Vec<&'static str>> = RefCell::new(vec![]);
    // Still RUNNING when looked at again: the Stop was refused by a service
    // that can take it, which is a failure.
    let mut fake = FakeScm::new(&log, [Observed::Running, Observed::Running].into()).failing_control("refused", 2);
    let err = stop_via_notify(&mut fake).expect_err("the control failed");
    assert_eq!(err.to_string(), "refused");
    assert_eq!(
        *log.borrow(),
        vec![
            "arm_stopped",
            "wait",
            "got_running",
            "control_stop",
            "arm_stopped",
            "wait",
            "got_running"
        ]
    );
}

/// A Stop sent on a RUNNING observation the service has since left (it stopped,
/// or began stopping, on its own) can be refused with any code the SCM or the
/// dying process answers with. The failure is read against a fresh look at the
/// service: not RUNNING any more means there was nothing to refuse.
#[skuld::test]
fn a_refused_stop_on_a_service_that_has_since_stopped_is_not_a_failure() {
    let log: RefCell<Vec<&'static str>> = RefCell::new(vec![]);
    let mut fake = FakeScm::new(&log, [Observed::Running, Observed::Stopped].into()).failing_control("broken pipe", 1);
    stop_via_notify(&mut fake).unwrap();
    assert_eq!(
        *log.borrow(),
        vec![
            "arm_stopped",
            "wait",
            "got_running",
            "control_stop",
            // the fresh look is a full arm: RUNNING included
            "arm_stopped",
            "wait",
            "got_stopped",
        ]
    );
}

#[skuld::test]
fn a_refused_stop_on_a_service_that_is_stopping_waits_for_it() {
    let log: RefCell<Vec<&'static str>> = RefCell::new(vec![]);
    let mut fake = FakeScm::new(
        &log,
        [Observed::Running, Observed::StopPending, Observed::Stopped].into(),
    )
    .failing_control("broken pipe", 1);
    stop_via_notify(&mut fake).unwrap();
    assert_eq!(
        *log.borrow(),
        vec![
            "arm_stopped",
            "wait",
            "got_running",
            "control_stop",
            "arm_stopped",
            "wait",
            "got_stop_pending",
            "arm_stopped_except_stop_pending",
            "wait",
            "got_stopped",
        ]
    );
}

/// A pending state an arm reports is reported again at once by an arm that
/// still asks for it, so the re-arm leaves it out: the wait is then for a
/// change, not a busy loop of SCM calls for as long as the state lasts.
#[skuld::test]
fn a_re_arm_after_an_observed_state_leaves_that_state_out() {
    for (pending, label) in [
        (Observed::StartPending, "arm_stopped_except_start_pending"),
        (Observed::StopPending, "arm_stopped_except_stop_pending"),
    ] {
        let log: RefCell<Vec<&'static str>> = RefCell::new(vec![]);
        let mut fake = FakeScm::new(&log, [pending, Observed::Stopped].into());
        stop_via_notify(&mut fake).unwrap();
        assert_eq!(log.borrow()[3], label, "{pending:?}: {:?}", log.borrow());
    }
}

#[skuld::test]
fn the_stop_wait_arms_every_state_at_first_and_the_start_wait_the_states_it_acts_on() {
    use Observed::*;
    // The first arm reports the current state at once (see `Observed::for_stop_wait`),
    // so it must cover every state the policy has an answer for.
    assert_eq!(
        states_to_arm(WantState::Stopped, false, None),
        vec![Stopped, StartPending, StopPending, Running]
    );
    // Before `start()` a STOPPED would read as a failed start.
    assert_eq!(
        states_to_arm(WantState::Running, false, None),
        vec![StartPending, Running]
    );
    assert_eq!(
        states_to_arm(WantState::Running, true, None),
        vec![Stopped, StartPending, Running]
    );
}

#[skuld::test]
fn an_excepted_state_is_the_only_one_left_out() {
    use Observed::*;
    assert_eq!(
        states_to_arm(WantState::Stopped, false, Some(StartPending)),
        vec![Stopped, StopPending, Running]
    );
    assert_eq!(
        states_to_arm(WantState::Stopped, true, Some(Running)),
        vec![Stopped, StartPending, StopPending]
    );
    assert_eq!(
        states_to_arm(WantState::Running, true, Some(StartPending)),
        vec![Stopped, Running]
    );
    // A state the wait does not arm for is not there to leave out.
    assert_eq!(
        states_to_arm(WantState::Running, true, Some(StopPending)),
        vec![Stopped, StartPending, Running]
    );
}

/// No wait is ever armed for nothing: whichever state was just observed, at
/// least one other remains to be told about.
#[skuld::test]
fn no_arm_is_left_with_no_state_to_report() {
    use Observed::*;
    for want in [WantState::Stopped, WantState::Running] {
        for started in [false, true] {
            for except in [
                None,
                Some(Stopped),
                Some(Running),
                Some(StartPending),
                Some(StopPending),
            ] {
                assert!(
                    !states_to_arm(want, started, except).is_empty(),
                    "{want:?} {started} {except:?}"
                );
            }
        }
    }
}

#[skuld::test]
fn stop_surfaces_an_arm_error_before_waiting() {
    let log: RefCell<Vec<&'static str>> = RefCell::new(vec![]);
    let mut fake = FakeScm::new(&log, [Observed::Stopped].into());
    fake.arm_error = Some("no arm");
    let err = stop_via_notify(&mut fake).expect_err("the arm failed");
    assert_eq!(err.to_string(), "no arm");
    assert_eq!(*log.borrow(), vec!["arm_stopped"]);
}

#[skuld::test]
fn each_state_has_the_stop_policy_its_cause_gives_it() {
    // Written from the SCM's contract, not from the code: a Stop is accepted
    // in RUNNING only.
    let table = [
        (Observed::Stopped, StopStep::Finished),
        (Observed::Running, StopStep::SendStop),
        (Observed::StartPending, StopStep::KeepWaiting),
        (Observed::StopPending, StopStep::KeepWaiting),
    ];
    for (observed, step) in table {
        assert_eq!(observed.for_stop_wait(), step, "{observed:?}");
    }
}

/// Written from what the SCM does with a service marked for deletion, not from
/// the code: a Stop is accepted in RUNNING only, a process in STOP_PENDING is
/// already leaving, and a START_PENDING one cannot be stopped until it runs.
#[skuld::test]
fn each_state_has_the_drain_policy_its_cause_gives_it() {
    let table = [
        (Observed::Stopped, DrainStep::Finished),
        (Observed::Running, DrainStep::StopThenAwaitExit),
        (Observed::StopPending, DrainStep::AwaitExit),
        (Observed::StartPending, DrainStep::AwaitRunning),
    ];
    for (observed, step) in table {
        assert_eq!(observed.for_drain_step(), step, "{observed:?}");
    }
}

/// A STOPPED service has no process to report; every other state has one.
#[skuld::test]
fn only_a_stopped_service_has_no_process() {
    assert!(!Observed::Stopped.names_a_process());
    for observed in [Observed::StartPending, Observed::Running, Observed::StopPending] {
        assert!(observed.names_a_process(), "{observed:?}");
    }
}

#[skuld::test]
fn each_state_has_the_start_policy_its_cause_gives_it() {
    let table = [
        (Observed::Running, StartStep::Finished),
        (Observed::Stopped, StartStep::Failed),
        (Observed::StartPending, StartStep::KeepWaiting),
        (Observed::StopPending, StartStep::KeepWaiting),
    ];
    for (observed, step) in table {
        assert_eq!(observed.for_start_wait(), step, "{observed:?}");
    }
}

#[skuld::test]
fn start_via_notify_arms_running_before_start_then_gates_on_running() {
    let log: RefCell<Vec<&'static str>> = RefCell::new(vec![]);
    let mut fake = FakeScm::new(&log, [Observed::Running].into());
    start_via_notify(&mut fake).unwrap();
    // The critical ordering: arm RUNNING strictly BEFORE start, else a RUNNING
    // reached before the arm fires only on the NEXT entry — a hang.
    assert_eq!(*log.borrow(), vec!["arm_running", "start", "wait", "got_running"]);
}

#[skuld::test]
fn start_re_arms_after_a_non_terminal_callback() {
    let log: RefCell<Vec<&'static str>> = RefCell::new(vec![]);
    // A StartPending/StopPending intermediate fires while waiting for
    // RUNNING, then RUNNING; the non-terminal callback must trigger a re-arm.
    let mut fake = FakeScm::new(&log, [Observed::StartPending, Observed::Running].into());
    start_via_notify(&mut fake).unwrap();
    assert_eq!(
        *log.borrow(),
        vec![
            "arm_running",
            "start",
            "wait",
            "got_start_pending",
            "arm_running_except_start_pending", // re-arm: still waiting for RUNNING
            "wait",
            "got_running",
        ]
    );
}

#[skuld::test]
fn start_via_notify_errs_when_service_stops_instead_of_running() {
    let mut fake = FakeScm::scripted(vec![Observed::StartPending, Observed::Stopped]);
    assert!(start_via_notify(&mut fake).is_err());
}

#[skuld::test]
fn start_via_notify_ok_when_service_runs() {
    let mut fake = FakeScm::scripted(vec![Observed::StartPending, Observed::Running]);
    assert!(start_via_notify(&mut fake).is_ok());
}

#[skuld::test]
fn start_via_notify_rearms_on_pending_not_errs() {
    // A StartPending/StopPending intermediate must RE-ARM, not fail.
    let mut fake = FakeScm::scripted(vec![Observed::StartPending, Observed::StopPending, Observed::Running]);
    assert!(start_via_notify(&mut fake).is_ok());
    assert_eq!(fake.arm_count(), 3); // initial + 2 re-arms
}
