use super::*;
use std::cell::RefCell;

/// Records the granular SCM steps in call order and replays a scripted `Observed`
/// for each `wait_callback`. The script asserts the pure ordering of
/// `start_via_notify` without touching the real SCM.
struct FakeScm<'a> {
    log: &'a RefCell<Vec<&'static str>>,
    /// `Observed`s the next `wait_callback` calls return, front to back.
    waits: std::collections::VecDeque<Observed>,
}

impl<'a> FakeScm<'a> {
    fn new(log: &'a RefCell<Vec<&'static str>>, waits: std::collections::VecDeque<Observed>) -> Self {
        Self { log, waits }
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
        self.log.borrow_mut().push(arm_label(want, except));
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
    fn start(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn wait_callback(&mut self) -> std::io::Result<Observed> {
        Ok(self.waits.pop_front().expect("script ran dry"))
    }
}

#[skuld::test]
fn the_stop_wait_arms_every_state_at_first_and_the_start_wait_the_states_it_acts_on() {
    use Observed::*;
    // The first arm reports the current state at once, so it must cover every
    // state a wait has an answer for.
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

/// A STOPPED service has no process to report; every other state has one.
#[skuld::test]
fn only_a_stopped_service_has_no_process() {
    assert!(!Observed::Stopped.names_a_process());
    for observed in [Observed::StartPending, Observed::Running, Observed::StopPending] {
        assert!(observed.names_a_process(), "{observed:?}");
    }
}

/// Microsoft's `QueryServiceStatusEx` remarks: the id "is valid provided that
/// the state of the service is one of SERVICE_RUNNING, SERVICE_PAUSE_PENDING,
/// SERVICE_PAUSED, or SERVICE_CONTINUE_PENDING", "may not be valid" in
/// START_PENDING and STOP_PENDING, and "is never valid" in STOPPED. Written from
/// that text, not from the code.
#[skuld::test]
fn each_state_has_the_pid_validity_microsoft_documents() {
    assert_eq!(Observed::Running.reported_pid(), ReportedPid::Valid);
    assert_eq!(Observed::StartPending.reported_pid(), ReportedPid::MayBeInvalid);
    assert_eq!(Observed::StopPending.reported_pid(), ReportedPid::MayBeInvalid);
    assert_eq!(Observed::Stopped.reported_pid(), ReportedPid::Never);
}

/// An id no process has is the service's exit only where the id is valid.
#[skuld::test]
fn a_gone_id_is_an_exit_only_where_the_id_is_valid() {
    assert!(ReportedPid::Valid.gone_id_is_an_exit());
    assert!(!ReportedPid::MayBeInvalid.gone_id_is_an_exit());
    assert!(!ReportedPid::Never.gone_id_is_an_exit());
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
