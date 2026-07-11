//! Event-driven SCM stop/start waits via `NotifyServiceStatusChangeW` — a real
//! kernel rendezvous (an APC delivered on the actual state transition, awaited
//! in `SleepEx(INFINITE, TRUE)`), replacing the windows.rs sleep-poll. The
//! orchestration is a pure state machine over a `ScmActor`; the real impl drives
//! the raw `windows`-crate SCM FFI behind it.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WantState {
    Stopped,
    Running,
}

/// The service state a `wait_callback` observed. Distinct from `WantState`: a
/// callback can report a state that is neither what the caller wants nor its
/// opposite. `Running`/`Stopped` are terminal; `Pending` is any intermediate
/// (`StartPending`/`StopPending`) and re-arms. `start_via_notify` treats a
/// terminal `Stopped` as a FAILED start (the swapped-in bridge stopped instead
/// of reaching Running), so it returns `Err` rather than blocking forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observed {
    Running,
    Stopped,
    Pending,
}

/// The granular SCM operations the restart sequence needs, isolated so the
/// ordering can be unit-tested with a fake.
pub trait ScmActor {
    /// Register a status-change notification for `want`. `NotifyServiceStatusChangeW`
    /// is single-shot, so the sequence re-arms after every callback.
    fn arm(&mut self, want: WantState) -> std::io::Result<()>;
    fn control_stop(&mut self) -> std::io::Result<()>;
    fn start(&mut self) -> std::io::Result<()>;
    /// Block in an alertable wait until the armed notification fires; return the
    /// service's observed state from the callback buffer.
    fn wait_callback(&mut self) -> std::io::Result<Observed>;
}

/// Stop the service, gated strictly on a real STOPPED callback from
/// `NotifyServiceStatusChangeW`; re-arms after a non-terminal (pending) callback.
/// The cutover's `stop_service_wait_stopped` and `platform::os::stop` use this.
pub fn stop_via_notify<A: ScmActor>(a: &mut A) -> std::io::Result<()> {
    a.arm(WantState::Stopped)?;
    a.control_stop()?;
    loop {
        match a.wait_callback()? {
            Observed::Stopped => return Ok(()),
            // Running/Pending are non-terminal for a stop wait — re-arm and wait.
            Observed::Running | Observed::Pending => a.arm(WantState::Stopped)?,
        }
    }
}

/// Start the service, gated strictly on a real RUNNING callback; re-arms after a
/// non-terminal callback. Critical ordering: arm RUNNING BEFORE issuing start,
/// else the service can reach RUNNING before the arm and the notification only
/// fires on the NEXT entry into RUNNING — a hang. The cutover's
/// `start_service_wait_running` uses this.
pub fn start_via_notify<A: ScmActor>(a: &mut A) -> std::io::Result<()> {
    a.arm(WantState::Running)?;
    a.start()?;
    loop {
        match a.wait_callback()? {
            Observed::Running => return Ok(()),
            // A terminal Stopped means the service stopped instead of reaching
            // Running — a failed start. Give up (the cutover child then clears
            // the marker + exits; Part A's restart re-drives a transient failure).
            Observed::Stopped => {
                return Err(std::io::Error::other(
                    "service stopped before reaching Running (failed start)",
                ))
            }
            Observed::Pending => a.arm(WantState::Running)?,
        }
    }
}

#[cfg(target_os = "windows")]
mod system {
    //! Real `windows`-crate SCM impl. Raw FFI is sanctioned here (the #165
    //! isolation contract): the alertable `SleepEx(INFINITE, TRUE)` wait is a
    //! kernel rendezvous for an SCM-delivered APC, not a timeout-poll.
    #![allow(clippy::disallowed_methods)]

    use std::ffi::c_void;
    use std::io;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    use windows::core::{HRESULT, PCWSTR};
    use windows::Win32::Foundation::{ERROR_SERVICE_NOTIFY_CLIENT_LAGGING, ERROR_SERVICE_NOT_ACTIVE};
    use windows::Win32::System::Services::{
        CloseServiceHandle, ControlService, NotifyServiceStatusChangeW, OpenSCManagerW, OpenServiceW, StartServiceW,
        SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP, SERVICE_NOTIFY, SERVICE_NOTIFY_2W, SERVICE_NOTIFY_RUNNING,
        SERVICE_NOTIFY_START_PENDING, SERVICE_NOTIFY_STATUS_CHANGE, SERVICE_NOTIFY_STOPPED,
        SERVICE_NOTIFY_STOP_PENDING, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_STATUS,
        SERVICE_STOP, SERVICE_STOPPED,
    };
    use windows::Win32::System::Threading::SleepEx;

    use super::{Observed, WantState};

    /// Receives the callback-reported current state across the `SleepEx` wait.
    /// Heap-pinned (its address is handed to the SCM as `pContext`). Atomics:
    /// the APC writes these from the kernel's callback context, so the awaiting
    /// loop must not treat them as loop-invariant.
    struct LastStatus {
        current_state: AtomicU32,
        fired: AtomicBool,
    }

    /// `NotifyServiceStatusChangeW` delivers the new status via an APC into this
    /// callback. The SCM hands back the `SERVICE_NOTIFY_2W` buffer as
    /// `pparameter`; we read its `pContext` (our `*mut LastStatus`) and copy out
    /// the current state. Runs on the thread that issued the alertable wait.
    unsafe extern "system" fn notify_callback(pparameter: *const c_void) {
        let buf = pparameter as *const SERVICE_NOTIFY_2W;
        if buf.is_null() {
            return;
        }
        // SAFETY: the SCM passes back the exact buffer registered in `arm`,
        // whose `pContext` is the live `*mut LastStatus` pinned for the wait.
        let slot = unsafe { (*buf).pContext as *mut LastStatus };
        if slot.is_null() {
            return;
        }
        let state = unsafe { (*buf).ServiceStatus.dwCurrentState.0 };
        unsafe {
            (*slot).current_state.store(state, Ordering::Release);
            (*slot).fired.store(true, Ordering::Release);
        }
    }

    /// The `NotifyServiceStatusChangeW` mask for `want`, given whether `start()`
    /// has already been issued (`started`).
    ///
    /// For a start wait the STOPPED bit is included ONLY after `start()`: the
    /// service is `Stopped` at the initial arm (the cutover ran
    /// `stop_service_wait_stopped` first), and `NotifyServiceStatusChangeW`
    /// immediate-fires on the current state — so arming STOPPED before `start()`
    /// would misclassify that pre-start `Stopped` as a failed start. After
    /// `start()` the service has entered `StartPending`, so a later
    /// `StartPending -> Stopped` (or an already-`Stopped` immediate-fire) delivers
    /// a real `Stopped` callback that terminates the wait with `Err`.
    fn want_to_mask(want: WantState, started: bool) -> SERVICE_NOTIFY {
        match want {
            WantState::Stopped => SERVICE_NOTIFY_STOPPED | SERVICE_NOTIFY_STOP_PENDING,
            WantState::Running if started => {
                SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_STOPPED | SERVICE_NOTIFY_START_PENDING
            }
            WantState::Running => SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_START_PENDING,
        }
    }

    /// Owns the SCM + service handles and the notify buffer. The `LastStatus`
    /// slot and the `SERVICE_NOTIFY_2W` buffer are heap-pinned (`Box`) so their
    /// addresses stay stable across `arm` → `SleepEx` → callback.
    pub struct SystemScmActor {
        scm: SC_HANDLE,
        service: SC_HANDLE,
        service_name: Vec<u16>,
        status: Box<LastStatus>,
        notify: Box<SERVICE_NOTIFY_2W>,
        /// The state most recently awaited (for the debug trace).
        awaiting: WantState,
        /// Whether `start()` has been issued. Gates the two-phase arm: the STOPPED
        /// notify bit is added only after start (see `want_to_mask`).
        started: bool,
    }

    impl SystemScmActor {
        /// Open the SCM + service handles with query/stop/start access.
        pub fn open(service_name: &str) -> io::Result<Self> {
            let name: Vec<u16> = service_name.encode_utf16().chain(std::iter::once(0)).collect();
            let scm = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
                .map_err(io::Error::other)?;
            let service = match unsafe {
                OpenServiceW(
                    scm,
                    PCWSTR(name.as_ptr()),
                    SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_START,
                )
            } {
                Ok(s) => s,
                Err(e) => {
                    let _ = unsafe { CloseServiceHandle(scm) };
                    return Err(io::Error::other(e));
                }
            };
            Ok(Self {
                scm,
                service,
                service_name: name,
                status: Box::new(LastStatus {
                    current_state: AtomicU32::new(0),
                    fired: AtomicBool::new(false),
                }),
                notify: Box::new(SERVICE_NOTIFY_2W::default()),
                awaiting: WantState::Stopped,
                started: false,
            })
        }

        /// Close + reopen both handles. Used on
        /// `ERROR_SERVICE_NOTIFY_CLIENT_LAGGING`, which the SCM raises when the
        /// client missed a notification: the handle's notify queue must be
        /// dropped and re-established.
        fn reopen(&mut self) -> io::Result<()> {
            unsafe {
                let _ = CloseServiceHandle(self.service);
                let _ = CloseServiceHandle(self.scm);
            }
            self.scm = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
                .map_err(io::Error::other)?;
            self.service = unsafe {
                OpenServiceW(
                    self.scm,
                    PCWSTR(self.service_name.as_ptr()),
                    SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_START,
                )
            }
            .map_err(io::Error::other)?;
            Ok(())
        }
    }

    impl Drop for SystemScmActor {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseServiceHandle(self.service);
                let _ = CloseServiceHandle(self.scm);
            }
        }
    }

    impl super::ScmActor for SystemScmActor {
        fn arm(&mut self, want: WantState) -> io::Result<()> {
            self.awaiting = want;
            self.status.fired.store(false, Ordering::Release);
            *self.notify = SERVICE_NOTIFY_2W {
                dwVersion: SERVICE_NOTIFY_STATUS_CHANGE,
                pfnNotifyCallback: Some(notify_callback),
                pContext: (&mut *self.status as *mut LastStatus) as *mut c_void,
                ..Default::default()
            };
            let mask = want_to_mask(want, self.started);
            loop {
                let rc = unsafe { NotifyServiceStatusChangeW(self.service, mask, &*self.notify) };
                if rc == 0 {
                    return Ok(());
                }
                if rc == ERROR_SERVICE_NOTIFY_CLIENT_LAGGING.0 {
                    self.reopen()?;
                    continue; // re-arm against the fresh handle
                }
                return Err(io::Error::from_raw_os_error(rc as i32));
            }
        }

        fn control_stop(&mut self) -> io::Result<()> {
            let mut status = SERVICE_STATUS::default();
            match unsafe { ControlService(self.service, SERVICE_CONTROL_STOP, &mut status) } {
                Ok(()) => Ok(()),
                // The service stopped between the caller's early-return query and
                // this control. The STOPPED arm has already queued the
                // notification, so the wait still completes — benign.
                Err(e) if e.code() == HRESULT::from_win32(ERROR_SERVICE_NOT_ACTIVE.0) => Ok(()),
                Err(e) => Err(io::Error::other(e)),
            }
        }

        fn start(&mut self) -> io::Result<()> {
            let r = unsafe { StartServiceW(self.service, None) }.map_err(io::Error::other);
            // Mark started even if StartServiceW errored: the two-phase arm keys on
            // "start was attempted", and the caller propagates the error anyway.
            self.started = true;
            r
        }

        fn wait_callback(&mut self) -> io::Result<Observed> {
            // Alertable wait: blocks until the SCM delivers the notify APC, which
            // runs `notify_callback` and sets `status.fired`. A spurious early
            // wake (an unrelated APC) re-enters the wait.
            while !self.status.fired.load(Ordering::Acquire) {
                unsafe { SleepEx(u32::MAX, true) };
            }
            let state = self.status.current_state.load(Ordering::Acquire);
            // Trace here, NOT in `notify_callback`: that runs in an APC where any
            // allocation/lock (which `tracing` may take) is a hazard.
            tracing::debug!(scm_current_state = state, awaiting = ?self.awaiting, "SCM status callback fired");
            // Map the raw SCM state to an observation. RUNNING/STOPPED are terminal;
            // everything else (START_PENDING/STOP_PENDING/…) is Pending → re-arm.
            Ok(if state == SERVICE_RUNNING.0 {
                Observed::Running
            } else if state == SERVICE_STOPPED.0 {
                Observed::Stopped
            } else {
                Observed::Pending
            })
        }
    }
}

#[cfg(target_os = "windows")]
pub use system::SystemScmActor;

#[cfg(test)]
#[path = "scm_wait_tests.rs"]
mod scm_wait_tests;
