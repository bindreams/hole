use super::*;

use windows::Win32::System::Services::SERVICE_RUNNING;

#[skuld::test]
fn a_null_notification_buffer_is_a_contract_breach() {
    // SAFETY: a null buffer is rejected before any read.
    assert_eq!(unsafe { deliver(std::ptr::null()) }, Err(ContractBreach::NullBuffer));
}

#[skuld::test]
fn a_notification_without_a_context_is_a_contract_breach() {
    let buffer = SERVICE_NOTIFY_2W::default();
    // SAFETY: `buffer` is a valid, readable notify buffer.
    assert_eq!(unsafe { deliver(&buffer) }, Err(ContractBreach::NullContext));
}

#[skuld::test]
fn delivery_stores_the_state_and_settles_the_record() {
    let registration = NotifyRecord::registered();
    let record = registration.get();
    // SAFETY: nothing registered the record with the SCM, so nothing else
    // touches the buffer.
    unsafe { (*record.notify.get()).ServiceStatus.dwCurrentState = SERVICE_RUNNING };
    assert!(!record.is_settled());
    // SAFETY: the buffer is the record's own, bound to its status slot.
    assert_eq!(unsafe { deliver(record.buffer()) }, Ok(()));
    assert!(record.is_settled());
    assert_eq!(record.status.current_state.load(Ordering::Acquire), SERVICE_RUNNING.0);
}

// The SCM's own numbers (winsvc.h): states 1..=4 and notify bits 0x1..=0x8.
// Literals, so a wrong constant in the code cannot make these agree with it.
#[skuld::test]
fn each_state_has_its_notify_bit() {
    assert_eq!(notify_bit(Observed::Stopped).0, 0x1);
    assert_eq!(notify_bit(Observed::StartPending).0, 0x2);
    assert_eq!(notify_bit(Observed::StopPending).0, 0x4);
    assert_eq!(notify_bit(Observed::Running).0, 0x8);
}

#[skuld::test]
fn a_mask_is_the_union_of_its_states_bits() {
    assert_eq!(states_to_mask(&[]).0, 0);
    assert_eq!(states_to_mask(&[Observed::Stopped, Observed::Running]).0, 0x1 | 0x8);
    assert_eq!(
        states_to_mask(&states_to_arm(WantState::Stopped, false, None)).0,
        0x1 | 0x2 | 0x4 | 0x8
    );
    assert_eq!(
        states_to_mask(&states_to_arm(WantState::Stopped, false, Some(Observed::StartPending))).0,
        0x1 | 0x4 | 0x8
    );
}

#[skuld::test]
fn each_scm_state_a_mask_arms_for_maps_to_its_observation() {
    assert_eq!(observed_from_state(1), Some(Observed::Stopped));
    assert_eq!(observed_from_state(2), Some(Observed::StartPending));
    assert_eq!(observed_from_state(3), Some(Observed::StopPending));
    assert_eq!(observed_from_state(4), Some(Observed::Running));
}

#[skuld::test]
fn the_pause_states_are_not_an_observation() {
    // CONTINUE_PENDING, PAUSE_PENDING, PAUSED.
    for state in [5, 6, 7] {
        assert_eq!(observed_from_state(state), None);
    }
}

// A real SCM, read-only ===============================================================================================
//
// The Windows Event Log service runs on every host and any authenticated user may
// query it, so these tests need no elevation and no fixture. Its handle carries
// `SERVICE_QUERY_STATUS` only; nothing here can stop or start it.

use std::cell::Cell;
use std::collections::VecDeque;
use std::rc::Rc;

use windows::Win32::Foundation::ERROR_SERVICE_NOTIFY_CLIENT_LAGGING;
use windows::Win32::System::Services::SERVICE_QUERY_STATUS;

use crate::cutover::scm_wait::hold::Look;
use crate::cutover::scm_wait::settle::StopActor;

const ALWAYS_RUNNING_SERVICE: &str = "EventLog";

/// Counts the opens of notification handles and plays back scripted outcomes.
#[derive(Default)]
struct Script {
    opens: Rc<Cell<usize>>,
    open_failures: VecDeque<io::Error>,
    notify_failures: VecDeque<NonZeroU32>,
}

impl Hooks for Script {
    fn intercept_notify(&mut self, _record: usize) -> Option<NonZeroU32> {
        self.notify_failures.pop_front()
    }

    fn fail_open(&mut self) -> Option<io::Error> {
        self.opens.set(self.opens.get() + 1);
        self.open_failures.pop_front()
    }
}

fn actor_on_the_event_log<H: Hooks>(hooks: H) -> SystemScmActor<H> {
    SystemScmActor::open_with_access(ALWAYS_RUNNING_SERVICE, SERVICE_QUERY_STATUS, hooks)
        .unwrap_or_else(|e| panic!("open {ALWAYS_RUNNING_SERVICE}, which every Windows host runs: {e}"))
}

#[skuld::test]
fn observing_reads_the_state_and_holds_no_process() {
    let mut actor = actor_on_the_event_log(NoHooks);
    assert_eq!(
        actor.observe().unwrap(),
        Look {
            observed: Observed::Running,
            fate: ProcessFate::Unheld,
            held_alive: false,
            ever_held: false,
        }
    );
}

#[skuld::test]
fn arming_to_leave_a_state_the_service_is_not_in_fires_at_once_on_every_arm() {
    let mut actor = actor_on_the_event_log(NoHooks);
    actor.arm_leaving(Observed::Stopped).unwrap();
    actor.await_callback().unwrap();
    actor.arm_leaving(Observed::Stopped).unwrap();
    actor.await_callback().unwrap();
}

#[skuld::test]
fn every_arm_opens_handles_of_its_own() {
    let script = Script::default();
    let opens = Rc::clone(&script.opens);
    let mut actor = actor_on_the_event_log(script);
    assert_eq!(opens.get(), 0, "opening the actor is not an arm");
    actor.arm_leaving(Observed::Stopped).unwrap();
    assert_eq!(opens.get(), 1);
    actor.arm_leaving(Observed::Stopped).unwrap();
    assert_eq!(opens.get(), 2);
}

#[skuld::test]
fn a_lagging_client_arms_again_on_fresh_handles() {
    let mut script = Script::default();
    script
        .notify_failures
        .push_back(NonZeroU32::new(ERROR_SERVICE_NOTIFY_CLIENT_LAGGING.0).unwrap());
    let opens = Rc::clone(&script.opens);
    let mut actor = actor_on_the_event_log(script);
    actor.arm_leaving(Observed::Stopped).unwrap();
    assert_eq!(opens.get(), 2, "the retry is an arm of its own, on handles of its own");
    actor.await_callback().unwrap();
}

#[skuld::test]
fn a_failed_open_fails_that_arm_and_leaves_the_actor_usable() {
    let mut script = Script::default();
    script
        .open_failures
        .push_back(io::Error::other("injected open failure"));
    let mut actor = actor_on_the_event_log(script);
    let error = actor.arm_leaving(Observed::Stopped).expect_err("the open fails");
    assert!(error.to_string().contains("injected open failure"), "{error}");
    let error = actor.await_callback().expect_err("nothing is armed");
    assert!(error.to_string().contains("without a successful arm"), "{error}");
    assert_eq!(actor.observe().unwrap().observed, Observed::Running);
    actor.arm_leaving(Observed::Stopped).unwrap();
    actor.await_callback().unwrap();
}

#[skuld::test]
fn scanning_for_the_service_token_holds_nothing() {
    let mut actor = actor_on_the_event_log(NoHooks);
    actor.hold_scanned().unwrap();
    let look = actor.observe().unwrap();
    assert!(!look.held_alive && !look.ever_held, "{look:?}");
}
