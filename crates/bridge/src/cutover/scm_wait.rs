//! Event-driven SCM stop/start waits via `NotifyServiceStatusChangeW` — a real
//! kernel rendezvous (an APC delivered on the actual state transition, awaited
//! in `SleepEx(INFINITE, TRUE)`), replacing the windows.rs sleep-poll. The
//! orchestration is a pure state machine over a `ScmActor`; the real impl drives
//! the raw `windows`-crate SCM FFI behind it.

pub mod call_error;
pub mod hold;
pub mod retire;
pub mod scan;
pub mod settle;

use hold::ProcessFate;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WantState {
    Stopped,
    Running,
}

/// The states an arm for `want` asks to be told about, before `except` is left
/// out; `started` is whether `start()` has been issued.
///
/// An arm reports the service's CURRENT state at once if it is one of these
/// (the `NotifyServiceStatusChangeW` behaviour the first arm of every wait
/// relies on; see [`Observed::for_stop_wait`]). A re-arm that
/// still asked for the state it was just told would be told it again at once,
/// for as long as the state lasted: a busy loop of SCM calls. So a re-arm names
/// the state it just acted on as `except`, and waits for the service to leave
/// it.
///
/// A start wait includes STOPPED only after `start()`: the service is STOPPED
/// before it, and the arm would report that as a failed start.
pub fn states_to_arm(want: WantState, started: bool, except: Option<Observed>) -> Vec<Observed> {
    let base: &[Observed] = match want {
        WantState::Stopped => &[
            Observed::Stopped,
            Observed::StartPending,
            Observed::StopPending,
            Observed::Running,
        ],
        WantState::Running if started => &[Observed::Stopped, Observed::StartPending, Observed::Running],
        WantState::Running => &[Observed::StartPending, Observed::Running],
    };
    let states: Vec<Observed> = base.iter().copied().filter(|state| Some(*state) != except).collect();
    debug_assert!(!states.is_empty(), "an arm for no state never fires");
    states
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

/// How far the process id the SCM reports for a state can be trusted
/// ([`Observed::reported_pid`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportedPid {
    /// The id names the service's process.
    Valid,
    /// The id "may not be valid": it can name no process, or another one.
    MayBeInvalid,
    /// The state has no process to name.
    Never,
}

impl ReportedPid {
    /// Whether an id that no process has means the service's process has
    /// exited. Only where the id is valid is that a fact about the service;
    /// where it may be invalid it is a fact about the id.
    pub fn gone_id_is_an_exit(self) -> bool {
        match self {
            ReportedPid::Valid => true,
            ReportedPid::MayBeInvalid => false,
            ReportedPid::Never => false,
        }
    }
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

/// What the drain of a service marked for deletion does on seeing a state. It
/// waits on the service's process, not on a notification: whether an arm works
/// on a marked service has not been measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainStep {
    /// Nothing live is named: the service is stopped, or the process it names
    /// has exited. Wait out every held process and look once more.
    Finished,
    /// Running: send the Stop, then wait for the process to exit.
    StopThenAwaitExit,
    /// The process is already leaving: wait for it to exit.
    AwaitExit,
    /// No Stop is accepted yet and no process exit is near: wait for the
    /// service to leave START_PENDING through the stop wait.
    AwaitRunning,
    /// A live state with no process held to wait on: the only event left is
    /// the SCM's own notification, so the stop wait.
    AwaitStatus,
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
    ///
    /// The process is ground truth for whether the state is current: one that
    /// has exited is gone whatever the SCM still reports, so the service counts
    /// as stopped. The SCM's status can lag the exit.
    pub fn for_stop_wait(self, process: ProcessFate) -> StopStep {
        match process {
            ProcessFate::Exited => StopStep::Finished,
            ProcessFate::Unheld => self.for_stop_wait_by_state(),
            ProcessFate::Alive => self.for_stop_wait_by_state(),
        }
    }

    fn for_stop_wait_by_state(self) -> StopStep {
        match self {
            Observed::Stopped => StopStep::Finished,
            Observed::Running => StopStep::SendStop,
            // The service is already on its way to STOPPED.
            Observed::StopPending => StopStep::KeepWaiting,
            // Not yet running; a Stop would be refused.
            Observed::StartPending => StopStep::KeepWaiting,
        }
    }

    /// The drain's policy for this state and the fate of the process it names.
    ///
    /// The process, not the status, says whether anything is left: one that has
    /// exited leaves nothing, and a live state with no process held leaves only
    /// the SCM's own notification to wait on, so neither re-looks in a loop.
    pub fn for_drain_step(self, process: ProcessFate) -> DrainStep {
        match process {
            ProcessFate::Exited => DrainStep::Finished,
            ProcessFate::Alive => match self {
                Observed::Stopped => DrainStep::Finished,
                Observed::Running => DrainStep::StopThenAwaitExit,
                Observed::StopPending => DrainStep::AwaitExit,
                Observed::StartPending => DrainStep::AwaitRunning,
            },
            ProcessFate::Unheld => match self {
                Observed::Stopped => DrainStep::Finished,
                Observed::Running => DrainStep::AwaitStatus,
                Observed::StopPending => DrainStep::AwaitStatus,
                Observed::StartPending => DrainStep::AwaitStatus,
            },
        }
    }

    /// Whether a service in this state may have a process behind it, whose id
    /// the SCM reports. A process outlives the STOPPED the SCM reports for it,
    /// so the process, not the state, is what an uninstall waits out.
    ///
    /// The id is a claim: Microsoft documents that in START_PENDING and
    /// STOP_PENDING it "may not be valid", and in STOPPED it "is never valid"
    /// ([`QueryServiceStatusEx`, Remarks](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex#remarks)).
    /// So a `true` here only says an id is worth opening; the hold keeps the
    /// process only if its token carries the service SID
    /// ([`ProcessHolds::hold_current`](hold::ProcessHolds::hold_current)).
    pub fn names_a_process(self) -> bool {
        match self.reported_pid() {
            ReportedPid::Valid => true,
            ReportedPid::MayBeInvalid => true,
            ReportedPid::Never => false,
        }
    }

    /// How far the id the SCM reports in this state can be trusted, from the
    /// same Microsoft remarks as [`names_a_process`](Self::names_a_process).
    pub fn reported_pid(self) -> ReportedPid {
        match self {
            Observed::Running => ReportedPid::Valid,
            Observed::StartPending => ReportedPid::MayBeInvalid,
            Observed::StopPending => ReportedPid::MayBeInvalid,
            Observed::Stopped => ReportedPid::Never,
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
    /// Register a status-change notification for `want`, leaving out `except`
    /// (see [`states_to_arm`]). `NotifyServiceStatusChangeW` is single-shot, so
    /// the sequence re-arms after every callback.
    fn arm(&mut self, want: WantState, except: Option<Observed>) -> std::io::Result<()>;
    fn control_stop(&mut self) -> std::io::Result<()>;
    fn start(&mut self) -> std::io::Result<()>;
    /// Block in an alertable wait until the armed notification fires; return the
    /// service's observed state from the callback buffer.
    fn wait_callback(&mut self) -> std::io::Result<Observed>;
    /// The fate of the process behind the state `wait_callback` last reported.
    /// An actor that holds no process answers [`ProcessFate::Unheld`].
    fn process_fate(&mut self) -> std::io::Result<ProcessFate>;
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
/// callback, since the notification is single-shot, leaving out the state it
/// just acted on ([`states_to_arm`]), and carries no bound: the SCM bounds
/// START_PENDING itself, and a service that hangs in STOP_PENDING, or keeps
/// running after accepting a Stop, is the documented gap in CONTRIBUTING.md.
///
/// A Stop that fails is read against a fresh arm for every state: the failure
/// is about the RUNNING state it was sent on, and the service may have left it
/// since (stopped, or begun to) in a way that answers with any code. Only a
/// service still RUNNING, over a process that has not exited, makes the failure
/// the wait's own: the actor's [`ScmActor::process_fate`] is the ground truth
/// when the SCM's status lags the process.
///
/// The `retire` session uses this. The cutover's `stop_service_wait_stopped`
/// runs [`settle::settle_stopped`].
pub fn stop_via_notify<A: ScmActor>(a: &mut A) -> std::io::Result<()> {
    a.arm(WantState::Stopped, None)?;
    let mut observed = a.wait_callback()?;
    loop {
        match observed.for_stop_wait(a.process_fate()?) {
            StopStep::Finished => {
                tracing::info!(?observed, "SCM stop wait: service is stopped");
                return Ok(());
            }
            StopStep::SendStop => {
                tracing::info!(?observed, "SCM stop wait: sending Stop");
                match a.control_stop() {
                    Ok(()) => a.arm(WantState::Stopped, Some(observed))?,
                    Err(refused) => {
                        a.arm(WantState::Stopped, None)?;
                        observed = a.wait_callback()?;
                        if observed.for_stop_wait(a.process_fate()?) == StopStep::SendStop {
                            return Err(refused);
                        }
                        tracing::info!(
                            ?observed,
                            error = %refused,
                            "SCM stop wait: the Stop was refused, but the service is no longer running"
                        );
                        continue;
                    }
                }
            }
            StopStep::KeepWaiting => {
                tracing::info!(?observed, "SCM stop wait: not sending Stop, waiting");
                a.arm(WantState::Stopped, Some(observed))?;
            }
        }
        observed = a.wait_callback()?;
    }
}

/// Start the service, gated strictly on a real RUNNING callback; re-arms after a
/// non-terminal callback. Critical ordering: arm RUNNING BEFORE issuing start,
/// else the service can reach RUNNING before the arm and the notification only
/// fires on the NEXT entry into RUNNING — a hang. The cutover's
/// `start_service_wait_running` uses this.
pub fn start_via_notify<A: ScmActor>(a: &mut A) -> std::io::Result<()> {
    a.arm(WantState::Running, None)?;
    a.start()?;
    loop {
        let observed = a.wait_callback()?;
        match observed.for_start_wait() {
            StartStep::Finished => return Ok(()),
            // Give up (the cutover child then clears the marker + exits; the
            // SCM's restart-on-failure re-drives a transient failure).
            StartStep::Failed => {
                return Err(std::io::Error::other(
                    "service stopped before reaching Running (failed start)",
                ))
            }
            StartStep::KeepWaiting => a.arm(WantState::Running, Some(observed))?,
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
        ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_MARKED_FOR_DELETE, ERROR_SERVICE_NOTIFY_CLIENT_LAGGING,
    };
    use windows::Win32::System::Services::{
        ControlService, NotifyServiceStatusChangeW, QueryServiceStatusEx, StartServiceW, SC_STATUS_PROCESS_INFO,
        SERVICE_CONTROL_STOP, SERVICE_NOTIFY, SERVICE_NOTIFY_2W, SERVICE_NOTIFY_RUNNING, SERVICE_NOTIFY_START_PENDING,
        SERVICE_NOTIFY_STATUS_CHANGE, SERVICE_NOTIFY_STOPPED, SERVICE_NOTIFY_STOP_PENDING, SERVICE_QUERY_STATUS,
        SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP,
        SERVICE_STOPPED, SERVICE_STOP_PENDING,
    };
    use windows::Win32::System::Threading::SleepEx;

    use super::call_error::{self, win32_code_of_hresult, ScmCall, ScmCallError};
    use super::hold::Look;
    use super::settle::{StopActor, WaitKind};
    use super::{states_to_arm, Observed, ProcessFate, WantState};
    use crate::cutover::registration::{Arming, Registration, Settle};

    // `call_error` classifies the control answers by number so its tests run on
    // any host; the numbers must be the Win32 ones.
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

    /// The `NotifyServiceStatusChangeW` mask that asks for `states`.
    ///
    /// Which states a wait asks for is decided in [`super::states_to_arm`], where
    /// it is tested on every host; this is only the SCM's bit for each.
    fn states_to_mask(states: &[Observed]) -> SERVICE_NOTIFY {
        states
            .iter()
            .fold(SERVICE_NOTIFY(0), |mask, state| mask | notify_bit(*state))
    }

    /// The SCM's notify bit for entering `state`.
    fn notify_bit(state: Observed) -> SERVICE_NOTIFY {
        match state {
            Observed::Stopped => SERVICE_NOTIFY_STOPPED,
            Observed::StartPending => SERVICE_NOTIFY_START_PENDING,
            Observed::StopPending => SERVICE_NOTIFY_STOP_PENDING,
            Observed::Running => SERVICE_NOTIFY_RUNNING,
        }
    }

    /// The observation for a raw `SERVICE_STATUS.dwCurrentState`, or `None` for
    /// a state the masks never arm (the pause states).
    pub(crate) fn observed_from_state(state: u32) -> Option<Observed> {
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

        /// Called before each arm opens its handles. `Some(error)` makes that
        /// open fail with it.
        fn fail_open(&mut self) -> Option<io::Error> {
            None
        }
    }

    /// The production [`Hooks`]: both calls reach the real SCM.
    #[doc(hidden)]
    pub struct NoHooks;

    impl Hooks for NoHooks {}

    /// Owns the SCM + service handles the queries and controls use, the handles
    /// of the latest arm, and the registration of that arm.
    ///
    /// Each arm opens handles of its own, so no arm repeats the same service and
    /// state on one handle, which the SCM does not queue at once
    /// ([`NotifyServiceStatusChangeW`, Remarks](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-notifyservicestatuschangew#remarks)).
    /// It also builds a fresh [`NotifyRecord`] instead of rewriting one, so a
    /// callback from an earlier arm can never see a buffer a later arm is filling.
    /// A record is freed only after its callback has run, so an APC the SCM
    /// already queued still finds live memory at the thread's next alertable
    /// wait. An unsettled record is leaked (see CONTRIBUTING.md): one record
    /// (88 bytes on 64-bit Windows) per `NotifyServiceStatusChangeW` call that
    /// did not settle, i.e. that dropped pending, failed, or returned
    /// `ERROR_SERVICE_NOTIFY_CLIENT_LAGGING`. Nothing caps how many such calls
    /// are made (the LAGGING retry has no cap), so nothing caps the leak.
    pub struct SystemScmActor<H: Hooks = NoHooks> {
        /// The handles of the latest arm. The next arm closes them, which cancels
        /// what is outstanding on them. Declared before `arming` so they close
        /// first on drop.
        armed: Option<Handles>,
        /// The handles for queries and controls.
        handles: Handles,
        service_name: HSTRING,
        /// What the latest `arm` left behind; only a confirmed one is waited on.
        arming: Arming<NotifyRecord>,
        /// The state most recently awaited (for the debug trace).
        awaiting: WantState,
        /// Whether `start()` has been issued. Gates the two-phase arm: the STOPPED
        /// notify bit is added only after start (see [`super::states_to_arm`]).
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
            Self::open_with_access(service_name, SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_START, hooks)
        }

        /// [`open_with`](Self::open_with) with the query and control handle
        /// opened for `access` only.
        fn open_with_access(service_name: &str, access: u32, hooks: H) -> io::Result<Self> {
            let name = HSTRING::from(service_name);
            let handles = Handles::open(&name, access)?;
            Ok(Self {
                armed: None,
                handles,
                service_name: name,
                arming: Arming::Idle,
                awaiting: WantState::Stopped,
                started: false,
                hooks,
            })
        }

        /// Arms a notification for `states` on handles opened for it, closing
        /// the previous arm's first.
        ///
        /// `ERROR_SERVICE_NOTIFY_CLIENT_LAGGING` means the client missed a
        /// notification and "should close the handle to the SCM, open a new
        /// handle, and call this function again": the next pass of the loop,
        /// which opens fresh handles for every arm.
        fn arm_states(&mut self, states: &[Observed]) -> io::Result<()> {
            let mask = states_to_mask(states);
            // Whatever this arm does, the previous one is no longer what a wait
            // may rely on.
            self.arming.unconfirm();
            loop {
                // Closing the previous handles cancels what is outstanding on them.
                self.armed = None;
                let opened = match self.hooks.fail_open() {
                    Some(error) => Err(error),
                    None => Handles::open(&self.service_name, SERVICE_QUERY_STATUS),
                };
                let service = self.armed.insert(opened?).service();
                // Before the record exists: a failure here registers nothing.
                let registration = NotifyRecord::registered();
                let buffer = registration.get().buffer();
                let address = registration.get() as *const NotifyRecord as usize;
                // Stored before the call: a failed call may still have registered the record.
                self.arming.begin(registration);
                let rc = match self.hooks.intercept_notify(address) {
                    Some(rc) => rc.get(),
                    // SAFETY: `service` is a live handle (`armed` closes it only
                    // on the next arm or on drop) and `buffer` points at the
                    // record `arming` now owns, which is freed only once settled.
                    None => unsafe { NotifyServiceStatusChangeW(service, mask, buffer) },
                };
                if rc == 0 {
                    self.arming.confirm();
                    return Ok(());
                }
                if rc == ERROR_SERVICE_NOTIFY_CLIENT_LAGGING.0 {
                    tracing::warn!("SCM notify client lagging: arming again on fresh handles");
                    continue;
                }
                return Err(ScmCallError {
                    call: ScmCall::NotifyServiceStatusChange,
                    code: rc,
                }
                .into_io());
            }
        }

        /// Sleeps until the latest arm's notification fires and returns the
        /// state it reports, as the SCM's number.
        fn wait_for_the_armed_notification(&mut self) -> io::Result<u32> {
            // Alertable wait: blocks until the SCM delivers the notify APC, which
            // runs `notify_callback` and sets `status.fired`. A spurious early
            // wake (an unrelated APC) re-enters the wait. Only the last arm's
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
            Ok(state)
        }

        /// `ControlService(STOP)` on the control handle.
        fn send_stop(&mut self) -> io::Result<()> {
            let mut status = SERVICE_STATUS::default();
            match unsafe { ControlService(self.handles.service(), SERVICE_CONTROL_STOP, &mut status) } {
                Ok(()) => Ok(()),
                Err(e) => Err(ScmCallError {
                    call: ScmCall::ControlService,
                    code: win32_code_of_hresult(e.code().0),
                }
                .into_io()),
            }
        }
    }

    // No `Drop` impl: field order is the drop order.

    impl<H: Hooks> super::ScmActor for SystemScmActor<H> {
        fn arm(&mut self, want: WantState, except: Option<Observed>) -> io::Result<()> {
            self.awaiting = want;
            self.arm_states(&states_to_arm(want, self.started, except))
        }

        fn control_stop(&mut self) -> io::Result<()> {
            self.send_stop()
        }

        fn start(&mut self) -> io::Result<()> {
            let r = unsafe { StartServiceW(self.handles.service(), None) }.map_err(|e| {
                ScmCallError {
                    call: ScmCall::StartService,
                    code: win32_code_of_hresult(e.code().0),
                }
                .into_io()
            });
            // Mark started even if StartServiceW errored: the two-phase arm keys on
            // "start was attempted", and the caller propagates the error anyway.
            self.started = true;
            r
        }

        fn wait_callback(&mut self) -> io::Result<Observed> {
            let state = self.wait_for_the_armed_notification()?;
            observed_from_state(state).ok_or_else(|| {
                io::Error::other(format!(
                    "the SCM reported service state {state}, which no wait here arms for"
                ))
            })
        }

        fn process_fate(&mut self) -> io::Result<ProcessFate> {
            Ok(ProcessFate::Unheld)
        }
    }

    /// This actor holds no process: it queries the SCM's state and arms on it,
    /// and its looks name no process ([`ProcessFate::Unheld`]), so the loop
    /// never waits on one.
    impl<H: Hooks> StopActor for SystemScmActor<H> {
        fn observe(&mut self) -> io::Result<Look> {
            let mut status = SERVICE_STATUS_PROCESS::default();
            let mut needed = 0u32;
            // SAFETY: the buffer is `status`'s own storage, of exactly its size,
            // and the handle is live for `self`.
            unsafe {
                QueryServiceStatusEx(
                    self.handles.service(),
                    SC_STATUS_PROCESS_INFO,
                    Some(std::slice::from_raw_parts_mut(
                        std::ptr::from_mut(&mut status).cast::<u8>(),
                        std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
                    )),
                    &mut needed,
                )
            }
            .map_err(|e| {
                ScmCallError {
                    call: ScmCall::QueryServiceStatusEx,
                    code: win32_code_of_hresult(e.code().0),
                }
                .into_io()
            })?;
            let state = status.dwCurrentState.0;
            let observed = observed_from_state(state).ok_or_else(|| {
                io::Error::other(format!(
                    "the service reported state {state}, which is not one it can be stopped from"
                ))
            })?;
            Ok(Look {
                observed,
                fate: ProcessFate::Unheld,
                held_alive: false,
                ever_held: false,
            })
        }

        fn arm_leaving(&mut self, from: Observed) -> io::Result<()> {
            self.awaiting = WantState::Stopped;
            self.arm_states(&states_to_arm(WantState::Stopped, false, Some(from)))
        }

        fn control_stop(&mut self) -> io::Result<()> {
            self.send_stop()
        }

        /// The wait kind selects a failure bound once the owner sets one; until
        /// then every wait is unbounded.
        fn await_callback(&mut self, _kind: WaitKind) -> io::Result<()> {
            self.wait_for_the_armed_notification().map(drop)
        }

        fn await_held_exits(&mut self, _kind: WaitKind) -> io::Result<()> {
            unreachable!("a look of this actor holds no process, so no step waits for one to exit")
        }

        /// Holds nothing: the cutover's stop does not look for a process the SCM
        /// no longer names.
        fn hold_scanned(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}

/// The observation for a raw `SERVICE_STATUS.dwCurrentState`.
#[cfg(target_os = "windows")]
pub(crate) use system::observed_from_state;
#[cfg(target_os = "windows")]
pub use system::{Hooks, NoHooks, SystemScmActor};

#[cfg(test)]
#[path = "scm_wait_tests.rs"]
mod scm_wait_tests;
