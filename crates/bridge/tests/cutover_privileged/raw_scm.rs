//! `NotifyServiceStatusChangeW` and service-state reads with no production code
//! between the test and the SCM, so a probe measures the SCM and not the
//! policy built on it. Every arm opens its own SCM and service handles.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use windows::core::{HRESULT, PCWSTR};
use windows::Win32::System::Services::{
    CloseServiceHandle, NotifyServiceStatusChangeW, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_NOTIFY, SERVICE_NOTIFY_2W, SERVICE_NOTIFY_RUNNING,
    SERVICE_NOTIFY_START_PENDING, SERVICE_NOTIFY_STATUS_CHANGE, SERVICE_NOTIFY_STOPPED, SERVICE_NOTIFY_STOP_PENDING,
    SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS,
};
use windows::Win32::System::Threading::SleepEx;

pub const STOPPED: SERVICE_NOTIFY = SERVICE_NOTIFY_STOPPED;
pub const START_PENDING: SERVICE_NOTIFY = SERVICE_NOTIFY_START_PENDING;
pub const STOP_PENDING: SERVICE_NOTIFY = SERVICE_NOTIFY_STOP_PENDING;
pub const RUNNING: SERVICE_NOTIFY = SERVICE_NOTIFY_RUNNING;
/// Every state the probes arm for.
pub const ANY_STATE: SERVICE_NOTIFY = SERVICE_NOTIFY(STOPPED.0 | START_PENDING.0 | STOP_PENDING.0 | RUNNING.0);

/// `ANY_STATE` without `state`.
pub fn any_state_but(state: SERVICE_NOTIFY) -> SERVICE_NOTIFY {
    SERVICE_NOTIFY(ANY_STATE.0 & !state.0)
}

/// The notify flag of a `dwCurrentState` value (STOPPED 1, START_PENDING 2,
/// STOP_PENDING 3, RUNNING 4).
pub fn flag_of_state(current_state: u32) -> SERVICE_NOTIFY {
    match current_state {
        1 => STOPPED,
        2 => START_PENDING,
        3 => STOP_PENDING,
        4 => RUNNING,
        other => panic!("the probes do not handle service state {other}"),
    }
}

pub fn flag_name(flag: u32) -> &'static str {
    match SERVICE_NOTIFY(flag) {
        STOPPED => "STOPPED",
        START_PENDING => "START_PENDING",
        STOP_PENDING => "STOP_PENDING",
        RUNNING => "RUNNING",
        _ => "another state or several",
    }
}

/// The name of a `dwCurrentState` value.
pub fn state_name(current_state: u32) -> &'static str {
    flag_name(flag_of_state(current_state).0)
}

struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: the handle is a live one returned by the SCM open calls.
        // Closing a service handle cancels its outstanding notification.
        let _ = unsafe { CloseServiceHandle(self.0) };
    }
}

/// What a callback was told. Written by the SCM's APC, read after `fired`.
#[derive(Default)]
struct Delivery {
    fired: AtomicBool,
    status: AtomicU32,
    triggered: AtomicU32,
    state: AtomicU32,
    win32_exit_code: AtomicU32,
    service_exit_code: AtomicU32,
    process_id: AtomicU32,
}

/// What one callback reported.
#[derive(Debug, Clone, Copy)]
pub struct Report {
    /// `dwNotificationStatus`: 0 on success.
    pub status: u32,
    /// `dwNotificationTriggered`: the flag of the state that fired it.
    pub triggered: u32,
    /// `ServiceStatus.dwCurrentState`.
    pub state: u32,
    pub win32_exit_code: u32,
    pub service_exit_code: u32,
    /// `ServiceStatus.dwProcessId`.
    pub process_id: u32,
}

impl Report {
    pub fn describe(&self) -> String {
        format!(
            "notification status {}, triggered {} ({:#x}), state {}, process id {}, win32 exit code {}, service exit code {}",
            self.status,
            flag_name(self.triggered),
            self.triggered,
            state_name(self.state),
            self.process_id,
            self.win32_exit_code,
            self.service_exit_code
        )
    }
}

/// Runs as an APC on the thread that waits in [`Armed::wait`].
unsafe extern "system" fn callback(parameter: *const c_void) {
    // SAFETY: the SCM passes back the `SERVICE_NOTIFY_2W` armed below, and its
    // `pContext` is a leaked `Delivery`.
    let notify = unsafe { &*(parameter as *const SERVICE_NOTIFY_2W) };
    // SAFETY: as above.
    let delivery = unsafe { &*(notify.pContext as *const Delivery) };
    delivery.status.store(notify.dwNotificationStatus, Ordering::Relaxed);
    delivery
        .triggered
        .store(notify.dwNotificationTriggered, Ordering::Relaxed);
    delivery
        .state
        .store(notify.ServiceStatus.dwCurrentState.0, Ordering::Relaxed);
    delivery
        .win32_exit_code
        .store(notify.ServiceStatus.dwWin32ExitCode, Ordering::Relaxed);
    delivery
        .service_exit_code
        .store(notify.ServiceStatus.dwServiceSpecificExitCode, Ordering::Relaxed);
    delivery
        .process_id
        .store(notify.ServiceStatus.dwProcessId, Ordering::Relaxed);
    delivery.fired.store(true, Ordering::Release);
}

/// One arm on its own fresh handles. Dropping it closes them, which cancels
/// the notification if it is still outstanding.
pub struct Armed {
    delivery: &'static Delivery,
    _service: ScHandle,
    _scm: ScHandle,
}

impl Armed {
    /// Opens fresh handles to `service_name` and arms for the states in `mask`.
    /// Panics if the SCM refuses: a probe has nothing to measure then.
    pub fn arm(service_name: &str, mask: SERVICE_NOTIFY) -> Self {
        let name: Vec<u16> = service_name.encode_utf16().chain(std::iter::once(0)).collect();
        // Leaked on purpose: an APC queued before the handle closes can still
        // run at any later alertable wait, and must find live memory.
        let delivery: &'static Delivery = Box::leak(Box::default());
        let notify: &'static SERVICE_NOTIFY_2W = Box::leak(Box::new(SERVICE_NOTIFY_2W {
            dwVersion: SERVICE_NOTIFY_STATUS_CHANGE,
            pfnNotifyCallback: Some(callback),
            pContext: (delivery as *const Delivery).cast_mut().cast(),
            ..Default::default()
        }));
        // SAFETY: plain FFI calls; `name` is NUL-terminated and outlives them.
        let scm = ScHandle(
            unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
                .expect("open the SCM to arm on"),
        );
        // SAFETY: as above.
        let service = ScHandle(
            unsafe { OpenServiceW(scm.0, PCWSTR(name.as_ptr()), SERVICE_QUERY_STATUS) }
                .unwrap_or_else(|e| panic!("open {service_name} to arm on: {e}")),
        );
        // SAFETY: `service` is live; `notify` is leaked and so outlives it.
        let rc = unsafe { NotifyServiceStatusChangeW(service.0, mask, notify) };
        assert_eq!(
            rc,
            0,
            "NotifyServiceStatusChangeW({mask:?}) on {service_name} failed: {}",
            HRESULT::from_win32(rc).message()
        );
        Armed {
            delivery,
            _service: service,
            _scm: scm,
        }
    }

    /// Returns once the callback has run. Unbounded: the callback is the SCM's
    /// event, and a premise that is false hangs here until the nextest
    /// `terminate-after` names the test.
    pub fn wait(&self) -> Report {
        while !self.delivery.fired.load(Ordering::Acquire) {
            // The APC runs inside this alertable wait; an unrelated APC just
            // re-enters it.
            // SAFETY: plain FFI call.
            unsafe { SleepEx(u32::MAX, true) };
        }
        let d = self.delivery;
        Report {
            status: d.status.load(Ordering::Relaxed),
            triggered: d.triggered.load(Ordering::Relaxed),
            state: d.state.load(Ordering::Relaxed),
            win32_exit_code: d.win32_exit_code.load(Ordering::Relaxed),
            service_exit_code: d.service_exit_code.load(Ordering::Relaxed),
            process_id: d.process_id.load(Ordering::Relaxed),
        }
    }
}

/// `QueryServiceStatusEx` of `service_name` on a fresh handle.
pub fn query(service_name: &str) -> SERVICE_STATUS_PROCESS {
    let name: Vec<u16> = service_name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: plain FFI calls; `name` is NUL-terminated and outlives them.
    let scm = ScHandle(
        unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }.expect("open the SCM to query"),
    );
    // SAFETY: as above.
    let service = ScHandle(
        unsafe { OpenServiceW(scm.0, PCWSTR(name.as_ptr()), SERVICE_QUERY_STATUS) }
            .unwrap_or_else(|e| panic!("open {service_name} to query: {e}")),
    );
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0u32;
    // SAFETY: the buffer is the `SERVICE_STATUS_PROCESS` `status` is.
    unsafe {
        let buffer = std::slice::from_raw_parts_mut(
            std::ptr::from_mut(&mut status).cast::<u8>(),
            std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
        );
        QueryServiceStatusEx(service.0, SC_STATUS_PROCESS_INFO, Some(buffer), &mut needed)
    }
    .unwrap_or_else(|e| panic!("query {service_name}: {e}"));
    status
}
