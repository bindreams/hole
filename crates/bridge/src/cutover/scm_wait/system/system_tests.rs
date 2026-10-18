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
    let record = NotifyRecord::new();
    record.bind_context();
    // SAFETY: the record is unregistered, so nothing else touches the buffer.
    unsafe { (*record.notify.get()).ServiceStatus.dwCurrentState = SERVICE_RUNNING };
    assert!(!record.is_settled());
    // SAFETY: the buffer is the record's own, bound to its status slot.
    assert_eq!(unsafe { deliver(record.buffer()) }, Ok(()));
    assert!(record.is_settled());
    assert_eq!(record.status.current_state.load(Ordering::Acquire), SERVICE_RUNNING.0);
}

/// An invalid handle is what a double close looks like, and `ScHandle::drop`
/// reports exactly this failure.
#[skuld::test]
fn closing_a_handle_that_is_not_live_fails() {
    let mut handle = std::mem::ManuallyDrop::new(ScHandle(SC_HANDLE(std::ptr::null_mut())));
    assert!(handle.close().is_err());
}
