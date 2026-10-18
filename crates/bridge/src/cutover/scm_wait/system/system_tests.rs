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
