//! Event-driven SCM stop/start waits via `NotifyServiceStatusChangeW` — a real
//! kernel rendezvous (an APC delivered on the actual state transition, awaited
//! in `SleepEx(INFINITE, TRUE)`), replacing the windows.rs sleep-poll. The
//! orchestration is a pure state machine over a `ScmActor`; the real impl drives
//! the raw `windows`-crate SCM FFI behind it.

pub mod call_error;
pub mod retire;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WantState {
    Stopped,
    Running,
}

/// The service state a `wait_callback` observed. Distinct from `WantState`: a
/// callback can report a state that is neither what the caller wants nor its
/// opposite. What each state means for a waiter is decided once, on this type
/// ([`Observed::for_stop_wait`], [`Observed::for_start_wait`]), never at a call
/// site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observed {
    Running,
    Stopped,
    StartPending,
    StopPending,
}

/// What a stop wait does on seeing a state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopStep {
    /// The service is stopped.
    Finished,
    /// The service can take a Stop now.
    SendStop,
    /// Nothing to send: the service is between states and the wait re-arms.
    KeepWaiting,
}

/// What a start wait does on seeing a state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartStep {
    Finished,
    /// A terminal `Stopped` after `start()` is a FAILED start (the swapped-in
    /// bridge stopped instead of reaching Running).
    Failed,
    KeepWaiting,
}

impl Observed {
    /// The stop wait's policy for this state.
    ///
    /// A control is sent only into a state that takes it. The SCM refuses
    /// `ControlService(STOP)` outright in STOPPED, STOP_PENDING and
    /// START_PENDING, so a Stop sent on any of those either errs or is lost;
    /// RUNNING is the one state that accepts it. A START_PENDING service is
    /// waited out and reaches RUNNING (or STOPPED), whose observation then
    /// decides.
    pub fn for_stop_wait(self) -> StopStep {
        match self {
            Observed::Stopped => StopStep::Finished,
            Observed::Running => StopStep::SendStop,
            // The service is already on its way to STOPPED.
            Observed::StopPending => StopStep::KeepWaiting,
            // Not yet running; a Stop would be refused.
            Observed::StartPending => StopStep::KeepWaiting,
        }
    }

    /// The start wait's policy for this state.
    pub fn for_start_wait(self) -> StartStep {
        match self {
            Observed::Running => StartStep::Finished,
            Observed::Stopped => StartStep::Failed,
            Observed::StartPending => StartStep::KeepWaiting,
            // A stop in flight is not a failed start yet; its STOPPED is.
            Observed::StopPending => StartStep::KeepWaiting,
        }
    }
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
/// `NotifyServiceStatusChangeW`.
///
/// The wait is level-triggered: it arms first, and the arm reports the
/// service's current state at once, so what to do is decided by a state the
/// SCM reported, never by a guess about it (see [`Observed::for_stop_wait`]).
/// A Stop goes out only on a RUNNING observation. The SCM refuses it in every
/// other state, and a service the SCM has just restarted is START_PENDING
/// without any way to tell from outside; a control sent blind into that state
/// fails or is lost, which is how an uninstall landing on a restart used to
/// fail (bindreams/hole#1099). A START_PENDING service is waited out until it
/// is RUNNING (and gets its Stop then) or STOPPED. The wait re-arms after every
/// callback, since the notification is single-shot, and carries no bound: the
/// SCM bounds START_PENDING itself, and a service that hangs in STOP_PENDING is
/// the documented gap in CONTRIBUTING.md.
///
/// The cutover's `stop_service_wait_stopped` and the `retire` session use this.
pub fn stop_via_notify<A: ScmActor>(a: &mut A) -> std::io::Result<()> {
    a.arm(WantState::Stopped)?;
    loop {
        let observed = a.wait_callback()?;
        match observed.for_stop_wait() {
            StopStep::Finished => {
                tracing::info!(?observed, "SCM stop wait: service is stopped");
                return Ok(());
            }
            StopStep::SendStop => {
                tracing::info!(?observed, "SCM stop wait: sending Stop");
                a.control_stop()?;
            }
            StopStep::KeepWaiting => tracing::info!(?observed, "SCM stop wait: not sending Stop, waiting"),
        }
        a.arm(WantState::Stopped)?;
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
        match a.wait_callback()?.for_start_wait() {
            StartStep::Finished => return Ok(()),
            // Give up (the cutover child then clears the marker + exits; the
            // SCM's restart-on-failure re-drives a transient failure).
            StartStep::Failed => {
                return Err(std::io::Error::other(
                    "service stopped before reaching Running (failed start)",
                ))
            }
            StartStep::KeepWaiting => a.arm(WantState::Running)?,
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

    use windows::core::HSTRING;
    use windows::Win32::Foundation::{
        ERROR_SERVICE_CANNOT_ACCEPT_CTRL, ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_MARKED_FOR_DELETE,
        ERROR_SERVICE_NOTIFY_CLIENT_LAGGING, ERROR_SERVICE_NOT_ACTIVE,
    };
    use windows::Win32::System::Services::{
        ControlService, NotifyServiceStatusChangeW, StartServiceW, SC_HANDLE, SERVICE_CONTROL_STOP, SERVICE_NOTIFY,
        SERVICE_NOTIFY_2W, SERVICE_NOTIFY_RUNNING, SERVICE_NOTIFY_START_PENDING, SERVICE_NOTIFY_STATUS_CHANGE,
        SERVICE_NOTIFY_STOPPED, SERVICE_NOTIFY_STOP_PENDING, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS,
        SERVICE_STOPPED, SERVICE_STOP_PENDING,
    };
    use windows::Win32::System::Threading::SleepEx;

    use super::call_error::{self, classify_control_stop, win32_code_of_hresult, ScmCall, ScmCallError};
    use super::{Observed, WantState};
    use crate::cutover::registration::{Arming, Registration, Settle};

    // `call_error` classifies the control answers by number so its tests run on
    // any host; the numbers must be the Win32 ones.
    const _: () = assert!(ERROR_SERVICE_CANNOT_ACCEPT_CTRL.0 == call_error::ERROR_SERVICE_CANNOT_ACCEPT_CTRL);
    const _: () = assert!(ERROR_SERVICE_NOT_ACTIVE.0 == call_error::ERROR_SERVICE_NOT_ACTIVE);
    const _: () = assert!(ERROR_SERVICE_DOES_NOT_EXIST.0 == call_error::ERROR_SERVICE_DOES_NOT_EXIST);
    const _: () = assert!(ERROR_SERVICE_MARKED_FOR_DELETE.0 == call_error::ERROR_SERVICE_MARKED_FOR_DELETE);

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
    /// The stop wait arms every state a service can be in, because it decides
    /// what to do from the state the arm reports (see `stop_via_notify`): STOPPED
    /// ends it, RUNNING is the one state a Stop is sent in, and START_PENDING
    /// (a service the SCM has just restarted) and STOP_PENDING are waited out.
    /// Leaving a state out would leave the wait blind to it.
    fn want_to_mask(want: WantState, started: bool) -> SERVICE_NOTIFY {
        match want {
            WantState::Stopped => {
                SERVICE_NOTIFY_STOPPED
                    | SERVICE_NOTIFY_START_PENDING
                    | SERVICE_NOTIFY_STOP_PENDING
                    | SERVICE_NOTIFY_RUNNING
            }
            WantState::Running if started => {
                SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_STOPPED | SERVICE_NOTIFY_START_PENDING
            }
            WantState::Running => SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_START_PENDING,
        }
    }

    /// The observation for a raw `SERVICE_STATUS.dwCurrentState`, or `None` for
    /// a state the masks never arm (the pause states).
    fn observed_from_state(state: u32) -> Option<Observed> {
        match state {
            s if s == SERVICE_RUNNING.0 => Some(Observed::Running),
            s if s == SERVICE_STOPPED.0 => Some(Observed::Stopped),
            s if s == SERVICE_START_PENDING.0 => Some(Observed::StartPending),
            s if s == SERVICE_STOP_PENDING.0 => Some(Observed::StopPending),
            _ => None,
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
                return Err(ScmCallError {
                    call: ScmCall::NotifyServiceStatusChange,
                    code: rc,
                }
                .into_io());
            }
        }

        fn control_stop(&mut self) -> io::Result<()> {
            let mut status = SERVICE_STATUS::default();
            let service = self.service()?;
            match unsafe { ControlService(service, SERVICE_CONTROL_STOP, &mut status) } {
                Ok(()) => Ok(()),
                Err(e) => classify_control_stop(win32_code_of_hresult(e.code().0)).map_err(ScmCallError::into_io),
            }
        }

        fn start(&mut self) -> io::Result<()> {
            let r = self.service().and_then(|service| {
                unsafe { StartServiceW(service, None) }.map_err(|e| {
                    ScmCallError {
                        call: ScmCall::StartService,
                        code: win32_code_of_hresult(e.code().0),
                    }
                    .into_io()
                })
            });
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
            observed_from_state(state).ok_or_else(|| {
                io::Error::other(format!(
                    "the SCM reported service state {state}, which no wait here arms for"
                ))
            })
        }
    }
}

#[cfg(target_os = "windows")]
pub use system::{Hooks, NoHooks, SystemScmActor};

#[cfg(test)]
#[path = "scm_wait_tests.rs"]
mod scm_wait_tests;
