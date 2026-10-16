//! The Windows service control handler, owned by Hole for the life of the
//! process.
//!
//! `windows-service` 0.8's `register` hands the handler to the SCM as a raw
//! pointer and frees it on the first Stop, Shutdown or Preshutdown, though the
//! SCM keeps the pointer and can deliver another control (an Interrogate, or a
//! second Stop) afterwards. Here the handler is leaked at registration
//! ([`own`]) and never freed, so every control reaches live memory.
//!
//! The control decoding, the per-control policy and the entry point are
//! platform-neutral, so they test on any host. Registration and status reports
//! are Windows-only (`scm`).

use std::ffi::c_void;

#[cfg(windows)]
mod scm;
#[cfg(windows)]
pub use scm::{register, StatusHandle};

// Control codes and result codes (winsvc.h, winerror.h). `scm` asserts at
// compile time that they match the `windows` crate's constants.
const CONTROL_STOP: u32 = 0x1;
const CONTROL_INTERROGATE: u32 = 0x4;
const CONTROL_SHUTDOWN: u32 = 0x5;
const NO_ERROR: u32 = 0;
const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;

/// A service control the SCM delivered. Only the controls Hole has a policy
/// for are named; the rest keep their code in [`Control::Unsupported`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    Stop,
    Shutdown,
    Interrogate,
    Unsupported(u32),
}

impl Control {
    pub fn from_raw(raw: u32) -> Self {
        match raw {
            CONTROL_STOP => Control::Stop,
            CONTROL_SHUTDOWN => Control::Shutdown,
            CONTROL_INTERROGATE => Control::Interrogate,
            other => Control::Unsupported(other),
        }
    }

    /// The policy for this control: `stop` runs for a Stop or Shutdown, the one
    /// match on the variants.
    ///
    /// `stop` may run more than once, since the SCM can deliver a Stop after a
    /// Shutdown or the reverse; it must tolerate that.
    pub fn handle(self, stop: impl FnOnce()) -> ControlResult {
        match self {
            Control::Stop => {
                stop();
                ControlResult::Handled
            }
            Control::Shutdown => {
                stop();
                ControlResult::Handled
            }
            // The SCM answers an Interrogate from the last status reported.
            Control::Interrogate => ControlResult::Handled,
            Control::Unsupported(_) => ControlResult::NotImplemented,
        }
    }
}

/// What a handler answers the SCM for one control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlResult {
    Handled,
    NotImplemented,
}

impl ControlResult {
    pub const fn to_raw(self) -> u32 {
        match self {
            ControlResult::Handled => NO_ERROR,
            ControlResult::NotImplemented => ERROR_CALL_NOT_IMPLEMENTED,
        }
    }
}

/// The `LPHANDLER_FUNCTION_EX` signature the SCM calls.
type RawHandler = unsafe extern "system" fn(u32, u32, *mut c_void, *mut c_void) -> u32;

/// A handler leaked for the rest of the process, with the entry point that
/// calls it. The two fields are private and only [`own`] fills them, so an
/// entry point cannot be paired with another handler's context; `scm`
/// registers them together.
#[cfg_attr(not(any(windows, test)), allow(dead_code))] // read by `scm` and by `deliver`
pub struct OwnedHandler {
    entry: RawHandler,
    context: *const c_void,
}

impl OwnedHandler {
    /// Deliver `raw` the way the SCM does, through the registered entry point.
    #[cfg(test)]
    fn deliver(&self, raw: u32) -> u32 {
        // SAFETY: `entry` and `context` were paired by `own`; the event
        // arguments are unused by the entry point.
        unsafe { (self.entry)(raw, 0, std::ptr::null_mut(), self.context.cast_mut()) }
    }
}

/// Hand `handler` to the process for the rest of its life. It is never
/// dropped, so no control can reach freed memory.
///
/// `Fn + Sync`: the entry point only ever holds a shared reference to it.
pub fn own<F: Fn(Control) -> ControlResult + Send + Sync + 'static>(handler: F) -> OwnedHandler {
    let context: &'static F = Box::leak(Box::new(handler));
    OwnedHandler {
        entry: entry_point::<F>,
        context: std::ptr::from_ref(context).cast(),
    }
}

/// The entry point the SCM calls for every control. The event type and data
/// carry nothing for the controls Hole handles.
///
/// A panic in the handler aborts the process, as it would unwinding into the
/// SCM's frames: handlers catch their own (see `service_stop`).
unsafe extern "system" fn entry_point<F: Fn(Control) -> ControlResult>(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    context: *mut c_void,
) -> u32 {
    // SAFETY: `context` is the `&'static F` leaked by `own` for this very
    // `F`; it is never freed or mutably borrowed.
    let handler = unsafe { &*context.cast_const().cast::<F>() };
    handler(Control::from_raw(control)).to_raw()
}

#[cfg(test)]
#[path = "service_ctrl_tests.rs"]
mod service_ctrl_tests;
