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
///
/// A RUNNING observation re-issues the control rather than merely re-arming.
/// The SCM refuses `ControlService(STOP)` with
/// `ERROR_SERVICE_CANNOT_ACCEPT_CTRL` whenever the service is STOPPED,
/// STOP_PENDING or START_PENDING, and the impl treats that refusal as benign
/// because a stop wait is armed for all three of STOPPED, STOP_PENDING and
/// RUNNING. The first two resolve themselves. START_PENDING resolves to
/// RUNNING — a service that never took the stop — so that observation is the
/// signal to send it again, now that the service can accept it. Re-arming
/// alone would wait forever for a STOPPED nothing asked for.
pub fn stop_via_notify<A: ScmActor>(a: &mut A) -> std::io::Result<()> {
    a.arm(WantState::Stopped)?;
    a.control_stop()?;
    loop {
        match a.wait_callback()? {
            Observed::Stopped => return Ok(()),
            Observed::Running => {
                a.control_stop()?;
                a.arm(WantState::Stopped)?;
            }
            // Pending is non-terminal for a stop wait — re-arm and wait.
            Observed::Pending => a.arm(WantState::Stopped)?,
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
            // Running — a failed start. Give up (the cutover child then clears the
            // marker + exits; the SCM's restart-on-failure re-drives a transient one).
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

    use std::cell::UnsafeCell;
    use std::ffi::c_void;
    use std::io;
    use std::num::NonZeroU32;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    use windows::core::{HRESULT, HSTRING};
    use windows::Win32::Foundation::{
        ERROR_SERVICE_CANNOT_ACCEPT_CTRL, ERROR_SERVICE_NOTIFY_CLIENT_LAGGING, ERROR_SERVICE_NOT_ACTIVE,
    };
    use windows::Win32::System::Services::{
        ControlService, NotifyServiceStatusChangeW, StartServiceW, SC_HANDLE, SERVICE_CONTROL_STOP, SERVICE_NOTIFY,
        SERVICE_NOTIFY_2W, SERVICE_NOTIFY_RUNNING, SERVICE_NOTIFY_START_PENDING, SERVICE_NOTIFY_STATUS_CHANGE,
        SERVICE_NOTIFY_STOPPED, SERVICE_NOTIFY_STOP_PENDING, SERVICE_RUNNING, SERVICE_STATUS, SERVICE_STOPPED,
    };
    use windows::Win32::System::Threading::SleepEx;

    use super::{Observed, WantState};
    use crate::cutover::registration::{Arming, Registration, Settle};

    mod handles;
    use handles::Handles;

    #[cfg(test)]
    #[path = "system_tests.rs"]
    mod system_tests;

    /// Receives the callback-reported current state across the `SleepEx` wait
    /// (its address is handed to the SCM as `pContext`). Atomics: the APC writes
    /// these from the kernel's callback context, so the awaiting loop must not
    /// treat them as loop-invariant. `fired` is the callback's last access.
    struct LastStatus {
        current_state: AtomicU32,
        fired: AtomicBool,
    }

    /// Everything one `NotifyServiceStatusChangeW` call hands the SCM: the notify
    /// buffer and the status slot its `pContext` names. The buffer is in an
    /// `UnsafeCell` because the SCM writes it from another thread while this
    /// process holds `&` references to the record.
    struct NotifyRecord {
        notify: UnsafeCell<SERVICE_NOTIFY_2W>,
        status: LastStatus,
    }

    // The notify record is 88 bytes on 64-bit Windows: the 80-byte
    // `SERVICE_NOTIFY_2W` plus the 8-byte `LastStatus`. Every leak figure in
    // these docs rests on it, so a layout change must fail the build.
    #[cfg(target_pointer_width = "64")]
    const _: () = assert!(std::mem::size_of::<NotifyRecord>() == 88);

    impl NotifyRecord {
        /// A fresh record owned by a [`Registration`], its buffer's `pContext`
        /// already pointing at its own status slot. The only way to make one:
        /// the binding happens before the registration exists, so no record the
        /// SCM may already see is ever rebound.
        fn registered() -> Registration<Self> {
            Registration::new_with(
                Self {
                    notify: UnsafeCell::new(SERVICE_NOTIFY_2W {
                        dwVersion: SERVICE_NOTIFY_STATUS_CHANGE,
                        pfnNotifyCallback: Some(notify_callback),
                        ..Default::default()
                    }),
                    status: LastStatus {
                        current_state: AtomicU32::new(0),
                        fired: AtomicBool::new(false),
                    },
                },
                |record| {
                    // SAFETY: `Registration::new_with` runs this on the record's
                    // final address before the registration exists, so nothing
                    // else has the record and nothing else reads or writes the
                    // buffer.
                    unsafe {
                        (*record.notify.get()).pContext = (&record.status as *const LastStatus).cast_mut().cast()
                    };
                },
            )
        }

        /// The buffer to pass to `NotifyServiceStatusChangeW`.
        fn buffer(&self) -> *const SERVICE_NOTIFY_2W {
            self.notify.get()
        }
    }

    // SAFETY: single-shot notification: once `fired` is set the callback has
    // run and nothing can name the record again. (Why an unfired record is
    // never freed: see the `registration` module doc.)
    unsafe impl Settle for NotifyRecord {
        fn is_settled(&self) -> bool {
            self.status.fired.load(Ordering::Acquire)
        }
    }

    /// `NotifyServiceStatusChangeW` delivers the new status via an APC into this
    /// callback. The SCM hands back the `SERVICE_NOTIFY_2W` buffer as
    /// `pparameter`; we read its `pContext` (our `*mut LastStatus`) and copy out
    /// the current state. Runs on the thread that issued the alertable wait.
    ///
    /// The SCM always passes back the buffer registered in `arm`, with its
    /// `pContext` intact. If it ever does not, no callback can report and the
    /// waiter would park forever, so the process aborts: that is the intended
    /// outcome of a broken SCM contract. `abort` rather than a panic so that it
    /// holds in every build profile and allocates nothing in an APC.
    unsafe extern "system" fn notify_callback(pparameter: *const c_void) {
        // SAFETY: `pparameter` is the buffer the SCM was given in `arm`.
        if unsafe { deliver(pparameter.cast()) }.is_err() {
            std::process::abort();
        }
    }

    /// A notification the SCM could not have sent, were its contract kept.
    #[derive(Debug, PartialEq, Eq)]
    enum ContractBreach {
        NullBuffer,
        NullContext,
    }

    /// Copies the state in `buffer` into the status slot its `pContext` names and
    /// marks the slot fired.
    ///
    /// # Safety
    ///
    /// A non-null `buffer` is readable, and a non-null `pContext` in it is the
    /// `LastStatus` of a `NotifyRecord` that stays allocated until this call has
    /// returned (see `Settle for NotifyRecord`).
    unsafe fn deliver(buffer: *const SERVICE_NOTIFY_2W) -> Result<(), ContractBreach> {
        if buffer.is_null() {
            return Err(ContractBreach::NullBuffer);
        }
        // SAFETY: per the contract above.
        let slot = unsafe { (*buffer).pContext as *const LastStatus };
        if slot.is_null() {
            return Err(ContractBreach::NullContext);
        }
        // SAFETY: as above.
        unsafe {
            (*slot)
                .current_state
                .store((*buffer).ServiceStatus.dwCurrentState.0, Ordering::Release);
            (*slot).fired.store(true, Ordering::Release);
        }
        Ok(())
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
    ///
    /// The stop wait also arms RUNNING: a service that was START_PENDING when
    /// the control went out refused it, and RUNNING is the only state from
    /// which `stop_via_notify` can re-issue it. Without that bit the wait
    /// blocks forever on a service that started instead of stopping.
    fn want_to_mask(want: WantState, started: bool) -> SERVICE_NOTIFY {
        match want {
            WantState::Stopped => SERVICE_NOTIFY_STOPPED | SERVICE_NOTIFY_STOP_PENDING | SERVICE_NOTIFY_RUNNING,
            WantState::Running if started => {
                SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_STOPPED | SERVICE_NOTIFY_START_PENDING
            }
            WantState::Running => SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_START_PENDING,
        }
    }

    /// Test seam for the two SCM outcomes a live SCM will not produce on demand.
    /// Production runs [`NoHooks`].
    #[doc(hidden)]
    pub trait Hooks {
        /// Called with the address of each fresh record just before
        /// `NotifyServiceStatusChangeW`. `Some(rc)` skips the call and acts as its
        /// failure code. Success is not injectable: it would leave an armed
        /// wait with nothing registered at the SCM, which never wakes.
        fn intercept_notify(&mut self, _record: usize) -> Option<NonZeroU32> {
            None
        }

        /// `Some(error)` makes `reopen` fail to open the handles with it.
        fn fail_open(&mut self) -> Option<io::Error> {
            None
        }
    }

    /// The production [`Hooks`]: both calls reach the real SCM.
    #[doc(hidden)]
    pub struct NoHooks;

    impl Hooks for NoHooks {}

    /// Owns the SCM + service handles and the registration of the latest `arm`.
    ///
    /// Each `arm` builds a fresh [`NotifyRecord`] instead of rewriting one, so a
    /// callback from an earlier arm can never see a buffer a later arm is filling.
    /// A record is freed only after its callback has run, so an APC the SCM
    /// already queued still finds live memory at the thread's next alertable
    /// wait. An unsettled record is leaked (see CONTRIBUTING.md): one record
    /// (88 bytes on 64-bit Windows) per `NotifyServiceStatusChangeW` call that
    /// did not settle, i.e. that dropped pending, failed, or returned
    /// `ERROR_SERVICE_NOTIFY_CLIENT_LAGGING`. Nothing caps how many such calls
    /// are made (the LAGGING retry has no cap), so nothing caps the leak.
    pub struct SystemScmActor<H: Hooks = NoHooks> {
        /// `None` only after a `reopen` that failed part-way; every use then errs.
        /// Declared before `arming` so the handles close first on drop.
        handles: Option<Handles>,
        service_name: HSTRING,
        /// What the latest `arm` left behind; only a confirmed one is waited on.
        arming: Arming<NotifyRecord>,
        /// The state most recently awaited (for the debug trace).
        awaiting: WantState,
        /// Whether `start()` has been issued. Gates the two-phase arm: the STOPPED
        /// notify bit is added only after start (see `want_to_mask`).
        started: bool,
        hooks: H,
    }

    impl SystemScmActor {
        /// Open the SCM + service handles with query/stop/start access.
        pub fn open(service_name: &str) -> io::Result<Self> {
            Self::open_with(service_name, NoHooks)
        }
    }

    impl<H: Hooks> SystemScmActor<H> {
        /// [`open`](SystemScmActor::open) with `hooks` in place of the real SCM
        /// outcomes they intercept.
        #[doc(hidden)]
        pub fn open_with(service_name: &str, hooks: H) -> io::Result<Self> {
            let name = HSTRING::from(service_name);
            let handles = Handles::open(&name)?;
            Ok(Self {
                handles: Some(handles),
                service_name: name,
                arming: Arming::Idle,
                awaiting: WantState::Stopped,
                started: false,
                hooks,
            })
        }

        /// Close + reopen both handles. Used on
        /// `ERROR_SERVICE_NOTIFY_CLIENT_LAGGING`, which the SCM raises when the
        /// client missed a notification: the handle's notify queue must be
        /// dropped and re-established.
        fn reopen(&mut self) -> io::Result<()> {
            // Close first (the documented remedy), by taking the handles out so a
            // failed open below leaves nothing for `Drop` to close again.
            self.handles = None;
            let opened = match self.hooks.fail_open() {
                Some(error) => Err(error),
                None => Handles::open(&self.service_name),
            };
            self.handles = Some(opened?);
            Ok(())
        }

        /// The open service handle, or an error after a failed `reopen`.
        fn service(&self) -> io::Result<SC_HANDLE> {
            self.handles
                .as_ref()
                .map(Handles::service)
                .ok_or_else(|| io::Error::other("SCM handles closed by a failed reopen"))
        }
    }

    // No `Drop` impl: field order is the drop order.

    impl<H: Hooks> super::ScmActor for SystemScmActor<H> {
        fn arm(&mut self, want: WantState) -> io::Result<()> {
            self.awaiting = want;
            let mask = want_to_mask(want, self.started);
            // Whatever this arm does, the previous one is no longer what a wait
            // may rely on.
            self.arming.unconfirm();
            loop {
                // Before the record exists: a failure here registers nothing.
                let service = self.service()?;
                let registration = NotifyRecord::registered();
                let buffer = registration.get().buffer();
                let address = registration.get() as *const NotifyRecord as usize;
                // Stored before the call: a failed call may still have registered the record.
                self.arming.begin(registration);
                let rc = match self.hooks.intercept_notify(address) {
                    Some(rc) => rc.get(),
                    // SAFETY: `service` is a live handle and `buffer` points at the
                    // record `arming` now owns, which is freed only once settled.
                    None => unsafe { NotifyServiceStatusChangeW(service, mask, buffer) },
                };
                if rc == 0 {
                    self.arming.confirm();
                    return Ok(());
                }
                if rc == ERROR_SERVICE_NOTIFY_CLIENT_LAGGING.0 {
                    tracing::warn!("SCM notify client lagging: reopening the SCM handles and arming again");
                    self.reopen()?;
                    continue; // re-arm against the fresh handle
                }
                return Err(io::Error::from_raw_os_error(rc as i32));
            }
        }

        fn control_stop(&mut self) -> io::Result<()> {
            let mut status = SERVICE_STATUS::default();
            let service = self.service()?;
            match unsafe { ControlService(service, SERVICE_CONTROL_STOP, &mut status) } {
                Ok(()) => Ok(()),
                // The service stopped between the caller's early-return query and
                // this control. The STOPPED arm has already queued the
                // notification, so the wait still completes — benign.
                Err(e) if e.code() == HRESULT::from_win32(ERROR_SERVICE_NOT_ACTIVE.0) => Ok(()),
                // The service is STOPPED, STOP_PENDING or START_PENDING — the
                // three states from which the SCM refuses a stop control
                // outright. STOP_PENDING is the reachable one: `ProxyManager`'s
                // teardown is unbounded (#556), so a bridge that is already
                // stopping stays there long enough for an uninstall to land in
                // the window. All three are covered by the stop wait's arm
                // (STOPPED | STOP_PENDING | RUNNING) — see `stop_via_notify`,
                // which re-issues this control on the RUNNING observation that
                // a refused START_PENDING resolves to.
                Err(e) if e.code() == HRESULT::from_win32(ERROR_SERVICE_CANNOT_ACCEPT_CTRL.0) => Ok(()),
                Err(e) => Err(io::Error::other(e)),
            }
        }

        fn start(&mut self) -> io::Result<()> {
            let r = self
                .service()
                .and_then(|service| unsafe { StartServiceW(service, None) }.map_err(io::Error::other));
            // Mark started even if StartServiceW errored: the two-phase arm keys on
            // "start was attempted", and the caller propagates the error anyway.
            self.started = true;
            r
        }

        fn wait_callback(&mut self) -> io::Result<Observed> {
            // A failed reopen closed the handles, and nothing can fire without
            // them.
            self.service()?;
            // Alertable wait: blocks until the SCM delivers the notify APC, which
            // runs `notify_callback` and sets `status.fired`. A spurious early
            // wake (an unrelated APC) re-enters the wait. Only the last `arm`'s
            // record, and only if its call succeeded, is one the SCM will fire.
            let Some(record) = self.arming.confirmed() else {
                return Err(io::Error::other("wait_callback without a successful arm"));
            };
            let status = &record.status;
            while !status.fired.load(Ordering::Acquire) {
                unsafe { SleepEx(u32::MAX, true) };
            }
            let state = status.current_state.load(Ordering::Acquire);
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
pub use system::{Hooks, NoHooks, SystemScmActor};

#[cfg(test)]
#[path = "scm_wait_tests.rs"]
mod scm_wait_tests;
