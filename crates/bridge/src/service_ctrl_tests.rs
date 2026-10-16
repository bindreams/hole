use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

// Control codes and result codes from winsvc.h / winerror.h, written out so the
// expectations do not come from the code under test.
const STOP: u32 = 0x1;
const PAUSE: u32 = 0x2;
const INTERROGATE: u32 = 0x4;
const SHUTDOWN: u32 = 0x5;
const PRESHUTDOWN: u32 = 0xF;
const NO_ERROR: u32 = 0;
const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;

#[skuld::test]
fn raw_control_codes_map_to_their_variants() {
    assert_eq!(Control::from_raw(STOP), Control::Stop);
    assert_eq!(Control::from_raw(SHUTDOWN), Control::Shutdown);
    assert_eq!(Control::from_raw(INTERROGATE), Control::Interrogate);
}

#[skuld::test]
fn every_other_control_code_is_unsupported_and_keeps_its_code() {
    // Preshutdown is not accepted by the service, so Hole has no policy for it.
    for raw in [PAUSE, PRESHUTDOWN, 0, 3, 6, 128, 255, u32::MAX] {
        assert_eq!(Control::from_raw(raw), Control::Unsupported(raw));
    }
}

#[skuld::test]
fn result_codes_are_the_win32_values() {
    assert_eq!(ControlResult::Handled.to_raw(), NO_ERROR);
    assert_eq!(ControlResult::NotImplemented.to_raw(), ERROR_CALL_NOT_IMPLEMENTED);
}

#[skuld::test]
fn stop_and_shutdown_request_the_stop_and_nothing_else_does() {
    let requested = |control: Control| {
        let mut ran = false;
        let result = control.handle(|| ran = true);
        (ran, result)
    };
    assert_eq!(requested(Control::Stop), (true, ControlResult::Handled));
    assert_eq!(requested(Control::Shutdown), (true, ControlResult::Handled));
    assert_eq!(requested(Control::Interrogate), (false, ControlResult::Handled));
    assert_eq!(
        requested(Control::Unsupported(PAUSE)),
        (false, ControlResult::NotImplemented)
    );
}

/// Counts its own drops, so a test can tell whether the handler's captured
/// state was freed.
struct DropCounter(Arc<AtomicUsize>);

impl Drop for DropCounter {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// The defect this module exists for: `windows-service` frees the handler on
/// the first Stop, Shutdown or Preshutdown while the SCM still holds the
/// pointer, so any later control reads freed memory. Drives the registered
/// entry point the way the SCM does, with the context it was handed.
#[skuld::test]
fn handler_survives_every_control_the_scm_can_send_after_a_stop() {
    let drops = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let counter = DropCounter(Arc::clone(&drops));
    let seen_in_handler = Arc::clone(&seen);
    let (entry, context) = own(move |control| {
        let _owned = &counter;
        seen_in_handler.lock().unwrap().push(control);
        ControlResult::Handled
    });

    let deliver = |raw: u32| {
        // SAFETY: `entry` and `context` come from `own`, which is what the
        // SCM is handed; the event arguments are unused by the entry point.
        unsafe { entry(raw, 0, std::ptr::null_mut(), context.cast_mut()) }
    };
    for raw in [STOP, INTERROGATE, STOP, SHUTDOWN, PRESHUTDOWN, INTERROGATE] {
        assert_eq!(deliver(raw), NO_ERROR, "control {raw:#x}");
    }

    assert_eq!(
        drops.load(Ordering::SeqCst),
        0,
        "the handler was freed while registered"
    );
    assert_eq!(
        *seen.lock().unwrap(),
        [
            Control::Stop,
            Control::Interrogate,
            Control::Stop,
            Control::Shutdown,
            Control::Unsupported(PRESHUTDOWN),
            Control::Interrogate,
        ]
    );
}

#[skuld::test]
fn entry_point_returns_the_handlers_result_code() {
    let (entry, context) = own(|control| match control {
        Control::Interrogate => ControlResult::Handled,
        _ => ControlResult::NotImplemented,
    });
    let deliver = |raw: u32| unsafe { entry(raw, 0, std::ptr::null_mut(), context.cast_mut()) };
    assert_eq!(deliver(INTERROGATE), NO_ERROR);
    assert_eq!(deliver(PAUSE), ERROR_CALL_NOT_IMPLEMENTED);
}
