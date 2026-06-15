use super::*;
use std::cell::RefCell;

/// Records the granular SCM steps in call order and replays a scripted state for
/// each `wait_callback`. The script asserts the pure ordering of
/// `restart_via_notify` without touching the real SCM.
struct FakeScm<'a> {
    log: &'a RefCell<Vec<&'static str>>,
    /// States the next `wait_callback` calls return, front to back.
    waits: std::collections::VecDeque<WantState>,
}

impl ScmActor for FakeScm<'_> {
    fn arm(&mut self, want: WantState) -> std::io::Result<()> {
        self.log.borrow_mut().push(match want {
            WantState::Stopped => "arm_stopped",
            WantState::Running => "arm_running",
        });
        Ok(())
    }
    fn control_stop(&mut self) -> std::io::Result<()> {
        self.log.borrow_mut().push("control_stop");
        Ok(())
    }
    fn start(&mut self) -> std::io::Result<()> {
        self.log.borrow_mut().push("start");
        Ok(())
    }
    fn wait_callback(&mut self) -> std::io::Result<WantState> {
        self.log.borrow_mut().push("wait");
        let state = self.waits.pop_front().expect("script ran dry");
        self.log.borrow_mut().push(match state {
            WantState::Stopped => "got_stopped",
            WantState::Running => "got_running",
        });
        Ok(state)
    }
}

#[skuld::test]
fn restart_sequence_arms_running_before_start_and_gates_on_running() {
    let log: RefCell<Vec<&'static str>> = RefCell::new(vec![]);
    let mut fake = FakeScm {
        log: &log,
        // Script: arm STOPPED then stop yields STOPPED; arm RUNNING then start
        // yields RUNNING.
        waits: [WantState::Stopped, WantState::Running].into(),
    };
    restart_via_notify(&mut fake).unwrap();
    assert_eq!(
        *log.borrow(),
        vec![
            "arm_stopped",
            "control_stop",
            "wait",
            "got_stopped",
            "arm_running",
            "start",
            "wait",
            "got_running",
        ]
    );
}

#[skuld::test]
fn restart_re_arms_after_a_non_terminal_callback() {
    let log: RefCell<Vec<&'static str>> = RefCell::new(vec![]);
    let mut fake = FakeScm {
        log: &log,
        // A spurious RUNNING fires while waiting for STOPPED, then STOPPED; a
        // spurious STOPPED fires while waiting for RUNNING, then RUNNING. Each
        // non-terminal callback must trigger a re-arm.
        waits: [
            WantState::Running,
            WantState::Stopped,
            WantState::Stopped,
            WantState::Running,
        ]
        .into(),
    };
    restart_via_notify(&mut fake).unwrap();
    assert_eq!(
        *log.borrow(),
        vec![
            "arm_stopped",
            "control_stop",
            "wait",
            "got_running",
            "arm_stopped", // re-arm: still waiting for STOPPED
            "wait",
            "got_stopped",
            "arm_running",
            "start",
            "wait",
            "got_stopped",
            "arm_running", // re-arm: still waiting for RUNNING
            "wait",
            "got_running",
        ]
    );
}
