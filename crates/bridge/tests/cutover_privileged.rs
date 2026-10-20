//! Privileged-lane cutover proofs (the bindreams/hole#165 isolation contract,
//! TUN lane). Real rename/SCM/renamex_np FFI driven through `hole_bridge`'s
//! public API. NOT `#[ignore]`d and do NOT skip on missing privilege — a default
//! `cargo nextest` run on an unelevated box runs them and FAILS LOUD; opting out
//! is the explicit `SKULD_LABELS="!tun"` filter, and CI provisions the elevation.
//!
//! These key on SERVICE-STATE transitions (`NotifyServiceStatusChange`), the
//! on-disk `same_file::Handle` identity FLIP, and the `/v1/version` flip — NEVER
//! loopback. The GitHub Actions Windows runner drops inbound loopback to the test
//! exe, so a loopback probe cannot tell a working cutover from a broken one (the
//! PR1 lesson); the egress/identity/service-state signals are the only reliable
//! ones on the runner.
//!
//! An INTEGRATION test (not a lib module) on purpose: Cargo guarantees the
//! `test_idle` helper `[[bin]]` is built before this target and injects
//! `CARGO_BIN_EXE_test_idle` (a lib unit-test target gets neither).
//!
//! Cross-binary serialization of the global WFP/pf/TUN state these touch lives in
//! `.config/nextest.toml` (`global_net_state` test-group) — skuld's `serial = TUN`
//! only serializes within one binary, and this is a third binary alongside the
//! bridge + tun-engine lib-test binaries.
//!
//! COUPLED NAMES: that group's filter matches these tests by the
//! `cutover_global_net_state_` name prefix. Renaming the prefix WITHOUT updating
//! `.config/nextest.toml` drops the test from the group → a silent cross-binary
//! race with the other real-net tests. Change both together.

#![allow(clippy::disallowed_methods)] // test spawns its own test binaries (attended)

hole_test_observability::register!();

fn main() {
    skuld::run_all();
}

#[skuld::label]
const TUN: skuld::Label;

/// Cross-binary serialization for tests that mutate GLOBAL OS network state —
/// the `.config/nextest.toml` `global_net_state` test-group's `max-threads = 1`
/// gate. This is a separate compiled binary, not part of `hole-bridge`'s lib
/// target, so it needs its own declaration (bindreams/hole#894).
#[skuld::label]
const GLOBAL_NET_STATE: skuld::Label;

// Probes and their helpers live in `cutover_privileged/`; a crate root resolves
// `mod` beside itself, where Cargo would take each file for a test target.
#[cfg(target_os = "windows")]
#[path = "cutover_privileged/arm_probes.rs"]
mod arm_probes;
#[cfg(target_os = "windows")]
#[path = "cutover_privileged/raw_scm.rs"]
mod raw_scm;
#[cfg(target_os = "windows")]
#[path = "cutover_privileged/record_proofs.rs"]
mod record_proofs;
#[cfg(target_os = "windows")]
#[path = "cutover_privileged/recording.rs"]
mod recording;
#[cfg(target_os = "windows")]
#[path = "cutover_privileged/restart_probes.rs"]
mod restart_probes;
#[cfg(target_os = "windows")]
#[path = "cutover_privileged/sid_probes.rs"]
mod sid_probes;

#[cfg(target_os = "windows")]
use hole_bridge::cutover::os::windows::WindowsCutoverOs;
#[cfg(target_os = "windows")]
use hole_bridge::cutover::os::CutoverOs;

/// The on-disk image identity must FLIP across a rename-away-then-move-in swap
/// (the GUI self-heal precondition: `same_file::Handle` inequality is what makes
/// `decide_self_heal` return Relaunch), and the swap must succeed WHILE the image
/// is mapped by a running process (the running-exe rename held `FILE_SHARE_DELETE`
/// — the load-bearing D1 premise). Non-privileged, but joins the TUN lane so it
/// serializes with the real-net tests.
///
/// Spawns a COPY of the idle helper in a tempdir — never the cargo target bin,
/// whose path cargo's macOS uplift removes+recreates on every no-op build.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_running_exe_rename_flips_handle_identity() {
    let dir = tempfile::tempdir().unwrap();
    let idle = std::path::Path::new(env!("CARGO_BIN_EXE_test_idle"));
    let exe = dir.path().join("live.exe");
    std::fs::copy(idle, &exe).unwrap();
    let mut child = std::process::Command::new(&exe).spawn().expect("spawn the idle image");

    let before = same_file::Handle::from_path(&exe).unwrap();
    let renamed = dir.path().join("live.exe.old-0.3.0");
    // The cutover primitive: rename the LIVE binary aside (POSIX-semantics rename
    // of an image held FILE_SHARE_DELETE), then move new bytes onto the canonical
    // path. A copy of the same helper stands in for the "new" image.
    std::fs::rename(&exe, &renamed).expect("rename a running exe must succeed (FILE_SHARE_DELETE)");
    std::fs::copy(idle, &exe).unwrap();
    let after = same_file::Handle::from_path(&exe).unwrap();

    assert_ne!(
        before, after,
        "same_file::Handle identity must FLIP across the swap (the self-heal precondition)"
    );
    assert!(
        child.try_wait().unwrap().is_none(),
        "the child must still be running after its image was renamed underneath it"
    );
    let _ = child.kill();
    let _ = child.wait();
}

/// Waits for the SCM to finish deleting a service: `DeleteService` only marks
/// one that is still running, and the SCM removes it once its process has exited
/// and every handle to it has closed.
#[cfg(target_os = "windows")]
mod scm_deletion {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, Ordering};

    use windows::core::{HRESULT, PCWSTR};
    use windows::Win32::Foundation::{
        LocalFree, ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_NOTIFY_CLIENT_LAGGING, HLOCAL,
    };
    use windows::Win32::System::Services::{
        CloseServiceHandle, NotifyServiceStatusChangeW, OpenSCManagerW, OpenServiceW, SC_HANDLE, SC_MANAGER_CONNECT,
        SC_MANAGER_ENUMERATE_SERVICE, SERVICE_NOTIFY_2W, SERVICE_NOTIFY_DELETED, SERVICE_NOTIFY_STATUS_CHANGE,
        SERVICE_QUERY_STATUS,
    };
    use windows::Win32::System::Threading::SleepEx;

    struct ScHandle(SC_HANDLE);
    impl Drop for ScHandle {
        fn drop(&mut self) {
            // SAFETY: the handle is a live one returned by the SCM open calls.
            // Closing an SCM handle cancels its outstanding notification.
            let _ = unsafe { CloseServiceHandle(self.0) };
        }
    }

    /// Runs as an APC on the thread that waits in `wait_until_deleted`.
    unsafe extern "system" fn deleted_callback(parameter: *const c_void) {
        // SAFETY: the SCM passes back the `SERVICE_NOTIFY_2W` armed below, and
        // its `pContext` is a leaked `AtomicBool`.
        let notify = unsafe { &*(parameter as *const SERVICE_NOTIFY_2W) };
        if notify.dwNotificationStatus == 0 && !notify.pszServiceNames.is_null() {
            // SAFETY: for a created/deleted notification the SCM allocates the
            // name list and leaves freeing it to the callback.
            let _ = unsafe { LocalFree(Some(HLOCAL(notify.pszServiceNames.0.cast()))) };
        }
        // SAFETY: as above.
        unsafe { &*(notify.pContext as *const AtomicBool) }.store(true, Ordering::Release);
    }

    /// Returns once no service named `name` exists. Each pass arms the
    /// notification, then reads the real state: a deletion that lands in between
    /// has already queued its callback, so the wait cannot miss it. The wait
    /// carries no bound: the service goes when its process exits.
    pub fn wait_until_deleted(name: &str) -> windows::core::Result<()> {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        loop {
            // Leaked on purpose: an APC queued before the handle closes can still
            // run at any later alertable wait, and must find live memory.
            let fired: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
            let notify: &'static SERVICE_NOTIFY_2W = Box::leak(Box::new(SERVICE_NOTIFY_2W {
                dwVersion: SERVICE_NOTIFY_STATUS_CHANGE,
                pfnNotifyCallback: Some(deleted_callback),
                pContext: (fired as *const AtomicBool).cast_mut().cast(),
                ..Default::default()
            }));
            // A fresh handle per pass: closing the old one cancels its
            // notification and clears ERROR_SERVICE_NOTIFY_CLIENT_LAGGING.
            // SAFETY: plain FFI calls; `wide` is NUL-terminated and outlives them.
            let scm = ScHandle(unsafe {
                OpenSCManagerW(
                    PCWSTR::null(),
                    PCWSTR::null(),
                    SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
                )
            }?);
            let rc = unsafe { NotifyServiceStatusChangeW(scm.0, SERVICE_NOTIFY_DELETED, notify) };
            if rc == ERROR_SERVICE_NOTIFY_CLIENT_LAGGING.0 {
                continue;
            }
            if rc != 0 {
                return Err(HRESULT::from_win32(rc).into());
            }
            match unsafe { OpenServiceW(scm.0, PCWSTR(wide.as_ptr()), SERVICE_QUERY_STATUS) } {
                // Still listed: a service marked for deletion opens.
                Ok(service) => drop(ScHandle(service)),
                Err(e) if e.code() == HRESULT::from_win32(ERROR_SERVICE_DOES_NOT_EXIST.0) => return Ok(()),
                Err(e) => return Err(e),
            }
            // The APC runs inside this alertable wait; an unrelated APC just
            // re-enters it.
            while !fired.load(Ordering::Acquire) {
                // SAFETY: plain FFI call.
                unsafe { SleepEx(u32::MAX, true) };
            }
        }
    }
}

/// A throwaway `HoleBridge` SCM service the test provisions itself, backed by the
/// `test_service` helper bin. Created on `install`, stopped + deleted on
/// `Drop` (best-effort, so a panic never strands it). Self-contained on purpose:
/// the test owns its fixture instead of assuming CI installed one — that
/// assumption is exactly what left the test unrunnable.
#[cfg(target_os = "windows")]
struct ProvisionedService;

#[cfg(target_os = "windows")]
impl ProvisionedService {
    fn install(helper: &std::path::Path) -> Self {
        Self::install_with_args(helper, vec![])
    }

    /// `install`, with `launch_arguments` appended to the service's ImagePath.
    fn install_with_args(helper: &std::path::Path, launch_arguments: Vec<std::ffi::OsString>) -> Self {
        Self::install_with(helper, launch_arguments, None)
    }

    /// `install_with_args`, and, when `restart_after` is given, the SCM's
    /// restart-on-failure action with that delay. The delay is configuration the
    /// SCM acts on, never something a test waits out: a long one keeps a killed
    /// service in STOPPED for the rest of the test, a short one lets the SCM
    /// restart it while the test blocks on the helper's parked event.
    fn install_with(
        helper: &std::path::Path,
        launch_arguments: Vec<std::ffi::OsString>,
        restart_after: Option<std::time::Duration>,
    ) -> Self {
        Self::create(helper, launch_arguments, restart_after, true)
    }

    /// `install`, but the service never gets a service SID: its process is what
    /// a service started by a version that predates the SID looks like.
    fn install_without_sid(helper: &std::path::Path) -> Self {
        Self::create(helper, vec![], None, false)
    }

    /// `install_without_sid`, with `launch_arguments` on the service's ImagePath.
    fn install_without_sid_with_args(helper: &std::path::Path, launch_arguments: Vec<std::ffi::OsString>) -> Self {
        Self::create(helper, launch_arguments, None, false)
    }

    /// The service as `install` registers it, with the configuration `install`
    /// requires (`registration::configure_new_service`: the description and the
    /// service SID type) unless `with_sid` is false.
    fn create(
        helper: &std::path::Path,
        launch_arguments: Vec<std::ffi::OsString>,
        restart_after: Option<std::time::Duration>,
        with_sid: bool,
    ) -> Self {
        use hole_bridge::platform::os::SERVICE_NAME;
        use windows_service::service::{
            ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
            ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceType,
        };
        use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

        // Every test's `Drop` returns only once the service is gone, so a
        // registered one here is a leftover of a run that was killed before its
        // `Drop`. Waiting it out could never end (see `require_no_leftover`).
        Self::require_no_leftover();
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .expect("open SCM with CREATE_SERVICE (the TUN lane runs elevated)");
        let info = ServiceInfo {
            name: std::ffi::OsString::from(SERVICE_NAME),
            display_name: std::ffi::OsString::from("Hole Bridge (test)"),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::OnDemand,
            error_control: ServiceErrorControl::Normal,
            executable_path: helper.to_path_buf(),
            launch_arguments,
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        };
        let service = manager
            .create_service(
                &info,
                ServiceAccess::START
                    | ServiceAccess::STOP
                    | ServiceAccess::QUERY_STATUS
                    | ServiceAccess::DELETE
                    | ServiceAccess::CHANGE_CONFIG,
            )
            .expect("create the throwaway HoleBridge service");
        if with_sid {
            // The steps `install` takes, so the fixture cannot drift from them.
            hole_bridge::platform::os::registration::configure_new_service(&service)
                .expect("configure the throwaway service as install does");
        }
        if let Some(delay) = restart_after {
            service
                .update_failure_actions(ServiceFailureActions {
                    reset_period: ServiceFailureResetPeriod::After(std::time::Duration::from_secs(86_400)),
                    reboot_msg: None,
                    command: None,
                    actions: Some(vec![ServiceAction {
                        action_type: ServiceActionType::Restart,
                        delay,
                    }]),
                })
                .expect("configure the throwaway service to restart on failure");
        }
        ProvisionedService
    }

    /// Whether `e` is the SCM's refusal to open a service with `code`.
    fn open_error_is(e: &windows_service::Error, code: windows::Win32::Foundation::WIN32_ERROR) -> bool {
        matches!(e, windows_service::Error::Winapi(io) if io.raw_os_error() == Some(code.0 as i32))
    }

    /// Panics, naming the service and its state, if a `HoleBridge` service is
    /// registered.
    ///
    /// A leftover can only come from a run whose process was killed before its
    /// `Drop` (a nextest `terminate-after`), because `teardown` returns only
    /// once the service is gone. Its service process is then still alive, and a
    /// service marked for deletion stays registered for as long as that process
    /// does, so waiting for the deletion would wait on an exit nothing in this
    /// test will cause, and an arm on it may not report at all. Every later test
    /// would hang at `starting`, with nothing naming why.
    fn require_no_leftover() {
        use hole_bridge::platform::os::SERVICE_NAME;
        use windows::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
        use windows_service::service::ServiceAccess;
        use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .expect("open the SCM to look for a leftover service");
        let service = match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            Ok(service) => service,
            Err(e) if Self::open_error_is(&e, ERROR_SERVICE_DOES_NOT_EXIST) => return,
            Err(e) => panic!("opening {SERVICE_NAME} to look for a leftover failed: {e}"),
        };
        match service.query_status() {
            Ok(status) => panic!(
                "a leftover {SERVICE_NAME} service is registered (state {:?}, process id {:?}; it may be marked \
                 for deletion): an earlier run was killed before it cleaned up, and waiting for it to go would \
                 wait on a process this test does not control. Stop or kill test_service.exe and delete the \
                 service, then run again",
                status.current_state, status.process_id
            ),
            Err(e) => panic!(
                "a leftover {SERVICE_NAME} service is registered and its state could not be read ({e}): an \
                 earlier run was killed before it cleaned up. Stop or kill test_service.exe and delete the \
                 service, then run again"
            ),
        }
    }

    /// Kills the throwaway service's process and deletes the service, returning
    /// only once it no longer exists. It acts on the service as it finds it: a
    /// probe that panicked can leave it running, or marked for deletion with
    /// its process alive (which still opens), and no cooperative Stop is waited
    /// on in either state.
    /// Best-effort: failures are reported on stderr, never panicked on, because
    /// this also runs from `Drop`.
    fn teardown() {
        use hole_bridge::platform::os::SERVICE_NAME;
        use windows::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
        use windows_service::service::ServiceAccess;
        use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

        let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) else {
            return;
        };
        let access = ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS | ServiceAccess::CHANGE_CONFIG;
        match manager.open_service(SERVICE_NAME, access) {
            Ok(service) => {
                scm_probe::forbid_restart(&service);
                // Any refusal leaves the wait below hanging, so say which it was.
                if let Err(e) = service.delete() {
                    eprintln!("teardown: deleting the throwaway service failed (awaiting deletion anyway): {e}");
                }
                // Deletion cannot complete while the service process is alive.
                scm_probe::kill_process_of(&service);
                // An open handle keeps the deletion pending.
                drop(service);
            }
            // Not present: nothing to clean.
            Err(e) if Self::open_error_is(&e, ERROR_SERVICE_DOES_NOT_EXIST) => return,
            Err(e) => eprintln!("teardown: opening the throwaway service failed (awaiting deletion anyway): {e}"),
        }
        drop(manager);
        if let Err(e) = scm_deletion::wait_until_deleted(SERVICE_NAME) {
            eprintln!("teardown: waiting for the throwaway service to be deleted failed: {e}");
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for ProvisionedService {
    fn drop(&mut self) {
        Self::teardown();
    }
}

/// The Windows cutover's SCM stop/start must gate strictly on real STOPPED then
/// RUNNING callbacks from `NotifyServiceStatusChange` — never a loopback probe.
/// This drives the actual production seam (`WindowsCutoverOs::stop_service_wait_stopped`
/// then `start_service_wait_running`, each opening its own `SystemScmActor` exactly
/// as the cutover child does) against a SELF-PROVISIONED throwaway service (the
/// `test_service` helper). The arm-before-start ORDERING is unit-proven
/// separately against a fake `ScmActor`; this is the real-service integration
/// half, NOT a full-bridge cutover e2e (no `images`, so the swap never runs).
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_real_scm_restart_gates_on_running_callback() {
    use hole_bridge::cutover::os::windows::WindowsCutoverOs;
    use hole_bridge::cutover::os::CutoverOs;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let _service = ProvisionedService::install(helper);

    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    // Bring the freshly-created (OnDemand → stopped) service up first, so the stop
    // half has something to stop and the final RUNNING is the restart's doing.
    os.start_service_wait_running()
        .expect("bring the throwaway service up via the production start seam");
    // The thing under test, via the production methods: each returns only once the
    // real STOPPED / RUNNING callback fires (no sleep, no loopback probe), so a
    // successful return IS the assertion.
    os.stop_service_wait_stopped()
        .expect("SCM stop must reach STOPPED via NotifyServiceStatusChange");
    os.start_service_wait_running()
        .expect("SCM restart must reach RUNNING via NotifyServiceStatusChange");
}

/// The cutover's stop wait on a service whose first instance fails on its Stop
/// and which the SCM restarts at once (restart-on-failure with no delay, and no
/// hardening, as the cutover leaves it). The wait arms before the Stop, so the
/// Stop's effect queues the callback whether it finds the service stopped or
/// already restarted, and it returns on a real event.
///
/// What the test proves is that the wait returns: a wait that armed after the
/// Stop, or that left out the state the restarted instance is in, can sleep
/// for good, and the job's wall clock is then the failure. It does not assert
/// the state afterwards, since a wait that reads the crashed instance's STOPPED
/// before the SCM's restart has run is right to return.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_stop_wait_returns_when_the_scm_restarts_the_service_at_once() {
    use hole_bridge::cutover::os::windows::WindowsCutoverOs;
    use hole_bridge::cutover::os::CutoverOs;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("crashed");
    let _service = ProvisionedService::install_with(
        helper,
        vec!["--crash-on-first-stop".into(), marker.clone().into_os_string()],
        Some(std::time::Duration::ZERO),
    );
    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    os.start_service_wait_running()
        .expect("bring the throwaway service up via the production start seam");

    os.stop_service_wait_stopped()
        .expect("the stop wait returns although the SCM restarts the service at once");
    assert!(marker.exists(), "the first instance must have failed on its Stop");
}

/// Reports whether this thread freed one watched block. The SCM's queueing is
/// not observable from outside the process, so the release of the notify record
/// itself is the observable.
#[cfg(target_os = "windows")]
mod freed_watch {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    thread_local! {
        static WATCHED: Cell<usize> = const { Cell::new(0) };
        static FREED: Cell<bool> = const { Cell::new(false) };
    }

    pub struct WatchingAlloc;

    // SAFETY: every call forwards to `System`; the watch state is const-initialised
    // thread-local `Cell`s with no destructor, so watching never allocates.
    unsafe impl GlobalAlloc for WatchingAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe { System.alloc(layout) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            if ptr as usize == WATCHED.with(Cell::get) {
                FREED.with(|f| f.set(true));
            }
            unsafe { System.dealloc(ptr, layout) }
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            unsafe { System.alloc_zeroed(layout) }
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            unsafe { System.realloc(ptr, layout, new_size) }
        }
    }

    /// Starts watching the live block at `address`, forgetting any earlier watch.
    pub fn watch(address: usize) {
        WATCHED.with(|w| w.set(address));
        FREED.with(|f| f.set(false));
    }

    /// Whether the watched block has been freed on this thread since `watch`.
    pub fn was_freed() -> bool {
        FREED.with(Cell::get)
    }
}

#[cfg(target_os = "windows")]
#[global_allocator]
static ALLOCATOR: freed_watch::WatchingAlloc = freed_watch::WatchingAlloc;

/// Scripts the two SCM outcomes a live SCM will not produce on demand and
/// records the address of every notify record a `SystemScmActor` creates.
#[cfg(target_os = "windows")]
struct Script {
    /// The address of each record, in the order `arm` created them.
    records: std::rc::Rc<std::cell::RefCell<Vec<usize>>>,
    /// Per `NotifyServiceStatusChangeW` call: `Some(rc)` replaces the call with a failure.
    notify: std::collections::VecDeque<Option<std::num::NonZeroU32>>,
    /// Per arm attempt, before it opens its handles: `Some(error)` makes the
    /// open fail.
    open: std::collections::VecDeque<Option<std::io::Error>>,
    /// The call whose record to hand to `freed_watch` as it is created.
    watch_call: Option<usize>,
}

#[cfg(target_os = "windows")]
impl Script {
    fn new() -> (Self, std::rc::Rc<std::cell::RefCell<Vec<usize>>>) {
        let records = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let script = Self {
            records: std::rc::Rc::clone(&records),
            notify: Default::default(),
            open: Default::default(),
            watch_call: None,
        };
        (script, records)
    }
}

#[cfg(target_os = "windows")]
impl hole_bridge::cutover::scm_wait::Hooks for Script {
    fn intercept_notify(&mut self, record: usize) -> Option<std::num::NonZeroU32> {
        let call = {
            let mut records = self.records.borrow_mut();
            records.push(record);
            records.len() - 1
        };
        if self.watch_call == Some(call) {
            freed_watch::watch(record);
        }
        self.notify.pop_front().flatten()
    }

    fn fail_open(&mut self) -> Option<std::io::Error> {
        self.open.pop_front().flatten()
    }
}

/// The service is STOPPED and the arm waits for RUNNING, so the notification stays
/// pending; a pending notification cannot be settled by an alertable SCM call
/// running a queued APC, which would legitimately free the record.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_dropping_an_actor_with_a_pending_notification_frees_no_notify_record() {
    use hole_bridge::cutover::scm_wait::{ScmActor, SystemScmActor, WantState};
    use hole_bridge::platform::os::SERVICE_NAME;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let _service = ProvisionedService::install(helper);

    let (mut script, records) = Script::new();
    script.watch_call = Some(0);
    let mut actor = SystemScmActor::open_with(SERVICE_NAME, script).expect("open the throwaway service");
    actor
        .arm(WantState::Running, None)
        .expect("arm against the stopped service");
    assert_eq!(records.borrow().len(), 1);
    drop(actor);
    assert!(
        !freed_watch::was_freed(),
        "dropping an actor whose notification has not been delivered freed its notify record"
    );
}

/// The converse of the test above.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_dropping_an_actor_after_its_callback_frees_the_notify_record() {
    use hole_bridge::cutover::os::windows::WindowsCutoverOs;
    use hole_bridge::cutover::os::CutoverOs;
    use hole_bridge::cutover::scm_wait::{Observed, ScmActor, SystemScmActor, WantState};
    use hole_bridge::platform::os::SERVICE_NAME;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let _service = ProvisionedService::install(helper);
    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    os.start_service_wait_running()
        .expect("bring the throwaway service up via the production start seam");

    let (mut script, records) = Script::new();
    script.watch_call = Some(0);
    let mut actor = SystemScmActor::open_with(SERVICE_NAME, script).expect("open the throwaway service");
    actor
        .arm(WantState::Stopped, None)
        .expect("arm against the running service");
    assert_eq!(
        actor.wait_callback().expect("the armed notification fires at once"),
        Observed::Running
    );
    assert_eq!(records.borrow().len(), 1);
    assert!(
        !freed_watch::was_freed(),
        "the record is freed while the actor holds it"
    );
    drop(actor);
    assert!(
        freed_watch::was_freed(),
        "dropping an actor whose callback already ran must release its notify record"
    );
}

/// Re-arming replaces the registration; the replaced record is still pending, so
/// it must not be freed.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_re_arming_while_a_notification_is_pending_frees_no_notify_record() {
    use hole_bridge::cutover::scm_wait::{ScmActor, SystemScmActor, WantState};
    use hole_bridge::platform::os::SERVICE_NAME;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let _service = ProvisionedService::install(helper);

    let (mut script, records) = Script::new();
    script.watch_call = Some(0);
    let mut actor = SystemScmActor::open_with(SERVICE_NAME, script).expect("open the throwaway service");
    actor
        .arm(WantState::Running, None)
        .expect("first arm against the stopped service");
    actor
        .arm(WantState::Running, None)
        .expect("second arm while the first is pending");
    assert_eq!(records.borrow().len(), 2);
    assert!(!freed_watch::was_freed(), "the pending record was freed by the re-arm");
}

#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_waiting_before_arming_errs_instead_of_hanging() {
    use hole_bridge::cutover::scm_wait::{ScmActor, SystemScmActor};
    use hole_bridge::platform::os::SERVICE_NAME;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let _service = ProvisionedService::install(helper);

    let mut actor = SystemScmActor::open(SERVICE_NAME).expect("open the throwaway service");
    let err = actor.wait_callback().expect_err("nothing is armed");
    assert!(
        err.to_string().contains("without a successful arm"),
        "unexpected error: {err}"
    );
}

/// A failed `NotifyServiceStatusChangeW` registers nothing the callback can ever
/// settle, so waiting on it would park the thread for good.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_waiting_after_a_failed_arm_errs_instead_of_hanging() {
    use hole_bridge::cutover::scm_wait::{ScmActor, SystemScmActor, WantState};
    use hole_bridge::platform::os::SERVICE_NAME;
    use windows::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let _service = ProvisionedService::install(helper);

    let (mut script, _records) = Script::new();
    script
        .notify
        .push_back(std::num::NonZeroU32::new(ERROR_SERVICE_DOES_NOT_EXIST.0));
    let mut actor = SystemScmActor::open_with(SERVICE_NAME, script).expect("open the throwaway service");
    actor.arm(WantState::Running, None).expect_err("the injected failure");
    let err = actor.wait_callback().expect_err("the last arm failed");
    assert!(
        err.to_string().contains("without a successful arm"),
        "unexpected error: {err}"
    );
}

/// The earlier arm succeeded, but the last one did not: the earlier registration
/// is no longer the one to wait on.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_waiting_after_an_arm_that_failed_over_a_good_one_errs_instead_of_hanging() {
    use hole_bridge::cutover::scm_wait::{ScmActor, SystemScmActor, WantState};
    use hole_bridge::platform::os::SERVICE_NAME;
    use windows::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let _service = ProvisionedService::install(helper);

    let (mut script, _records) = Script::new();
    script.notify.push_back(None);
    script
        .notify
        .push_back(std::num::NonZeroU32::new(ERROR_SERVICE_DOES_NOT_EXIST.0));
    let mut actor = SystemScmActor::open_with(SERVICE_NAME, script).expect("open the throwaway service");
    actor
        .arm(WantState::Running, None)
        .expect("first arm against the stopped service");
    actor.arm(WantState::Running, None).expect_err("the injected failure");
    let err = actor.wait_callback().expect_err("the last arm failed");
    assert!(
        err.to_string().contains("without a successful arm"),
        "unexpected error: {err}"
    );
}

/// `ERROR_SERVICE_NOTIFY_CLIENT_LAGGING` arms again on handles opened for the
/// retry. The lagging call's record is leaked, not freed.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_a_lagging_client_arms_again_on_fresh_handles() {
    use hole_bridge::cutover::os::windows::WindowsCutoverOs;
    use hole_bridge::cutover::os::CutoverOs;
    use hole_bridge::cutover::scm_wait::{Observed, ScmActor, SystemScmActor, WantState};
    use hole_bridge::platform::os::SERVICE_NAME;
    use windows::Win32::Foundation::ERROR_SERVICE_NOTIFY_CLIENT_LAGGING;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let _service = ProvisionedService::install(helper);
    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    os.start_service_wait_running()
        .expect("bring the throwaway service up via the production start seam");

    let (mut script, records) = Script::new();
    script
        .notify
        .push_back(std::num::NonZeroU32::new(ERROR_SERVICE_NOTIFY_CLIENT_LAGGING.0));
    script.watch_call = Some(0);
    let mut actor = SystemScmActor::open_with(SERVICE_NAME, script).expect("open the throwaway service");
    actor
        .arm(WantState::Stopped, None)
        .expect("the retry arms on fresh handles");
    assert_eq!(records.borrow().len(), 2, "the lagging call is retried once");
    assert_eq!(
        actor.wait_callback().expect("the retried notification fires at once"),
        Observed::Running
    );
    drop(actor);
    assert!(
        !freed_watch::was_freed(),
        "the lagging call's record was freed although its callback never ran"
    );
}

/// A retry whose handles fail to open fails that arm only: the actor's own
/// handle still answers, a later arm works, and the lagging call's record,
/// whose callback never ran, is not freed.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_a_failed_open_for_a_retry_fails_that_arm_only() {
    use hole_bridge::cutover::scm_wait::settle::StopActor;
    use hole_bridge::cutover::scm_wait::{Observed, ScmActor, SystemScmActor, WantState};
    use hole_bridge::platform::os::SERVICE_NAME;
    use windows::Win32::Foundation::ERROR_SERVICE_NOTIFY_CLIENT_LAGGING;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let _service = ProvisionedService::install(helper);

    let (mut script, records) = Script::new();
    script
        .notify
        .push_back(std::num::NonZeroU32::new(ERROR_SERVICE_NOTIFY_CLIENT_LAGGING.0));
    // The first attempt opens as usual; its retry's open fails.
    script.open.push_back(None);
    script
        .open
        .push_back(Some(std::io::Error::other("injected open failure")));
    script.watch_call = Some(0);
    let mut actor = SystemScmActor::open_with(SERVICE_NAME, script).expect("open the throwaway service");

    let err = actor.arm(WantState::Running, None).expect_err("the retry's open fails");
    assert!(
        err.to_string().contains("injected open failure"),
        "unexpected error: {err}"
    );
    assert_eq!(records.borrow().len(), 1, "no record is made for an open that failed");
    actor.wait_callback().expect_err("the last arm failed");
    assert_eq!(
        actor.observe().expect("the actor's own handle still answers").observed,
        Observed::Stopped
    );
    actor
        .arm(WantState::Running, None)
        .expect("a later arm opens handles of its own");
    drop(actor);
    assert!(
        !freed_watch::was_freed(),
        "the lagging call's record was freed although its callback never ran"
    );
}

/// How the throwaway service reacts to a Stop (`test_service --on-stop`).
#[cfg(target_os = "windows")]
#[derive(Clone, Copy)]
enum OnStop {
    ReportStopPending,
    StayRunning,
}

#[cfg(target_os = "windows")]
impl OnStop {
    fn flag_value(self) -> &'static str {
        match self {
            OnStop::ReportStopPending => "stop-pending",
            OnStop::StayRunning => "stay-running",
        }
    }

    /// The state the SCM answers the first Stop with (measured on
    /// windows-latest, twice): the service's own STOP_PENDING, or, when the
    /// StopPending report fails, the RUNNING it last reported.
    fn first_stop_state(self) -> windows::Win32::System::Services::SERVICE_STATUS_CURRENT_STATE {
        match self {
            OnStop::ReportStopPending => windows::Win32::System::Services::SERVICE_STOP_PENDING,
            OnStop::StayRunning => windows::Win32::System::Services::SERVICE_RUNNING,
        }
    }
}

/// What the SCM delivered to the throwaway service after its first Stop, and
/// what the service logged and ended with.
#[cfg(target_os = "windows")]
struct Delivery {
    first_stop: windows::Win32::System::Services::SERVICE_STATUS,
    interrogate: Result<windows::Win32::System::Services::SERVICE_STATUS, windows::core::Error>,
    second_stop: Result<windows::Win32::System::Services::SERVICE_STATUS, windows::core::Error>,
    final_status: windows::Win32::System::Services::SERVICE_STATUS,
    /// The controls the handler logged, in order.
    observed: Vec<String>,
}

/// Sends a Stop, an Interrogate and a second Stop to a throwaway service that
/// holds on a named event after the first Stop, then releases it and returns
/// what happened. The handler logs each control it receives before returning,
/// and the SCM answers a control only once the handler has returned, so the log
/// holds exactly the controls whose `ControlService` call succeeded.
#[cfg(target_os = "windows")]
fn deliver_controls_after_first_stop(on_stop: OnStop) -> Delivery {
    use hole_bridge::cutover::os::windows::WindowsCutoverOs;
    use hole_bridge::cutover::os::CutoverOs;
    use hole_bridge::cutover::scm_wait::{Observed, ScmActor, SystemScmActor, WantState};
    use hole_bridge::platform::os::SERVICE_NAME;
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Services::{
        CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_HANDLE,
        SC_MANAGER_CONNECT, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_STOP, SERVICE_INTERROGATE,
        SERVICE_QUERY_STATUS, SERVICE_STATUS, SERVICE_STOP,
    };
    use windows::Win32::System::Threading::{CreateEventW, SetEvent};

    struct Event(HANDLE);
    impl Drop for Event {
        fn drop(&mut self) {
            // SAFETY: the handle is the live event `CreateEventW` returned.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
    /// Signals the event on drop so a failed assertion cannot leave the service
    /// parked (it would break the next serial test's `install`). Declared after
    /// the service so it drops first.
    struct Unblock(HANDLE);
    impl Unblock {
        fn release(&self) -> windows::core::Result<()> {
            // SAFETY: the handle is the live event owned by `Event`, which
            // outlives this guard.
            unsafe { SetEvent(self.0) }
        }
    }
    impl Drop for Unblock {
        fn drop(&mut self) {
            let _ = self.release();
        }
    }
    struct ScHandle(SC_HANDLE);
    impl Drop for ScHandle {
        fn drop(&mut self) {
            // SAFETY: the handle is a live one returned by the SCM open calls.
            let _ = unsafe { CloseServiceHandle(self.0) };
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("controls.log");
    let event_name = format!("Global\\HoleServiceCtrlRelease{}", std::process::id());
    // Manual-reset, unsignalled: the service waits on it after its first Stop.
    // SAFETY: plain FFI call with no pointers beyond the valid name.
    let release = Event(
        unsafe { CreateEventW(None, true, false, &HSTRING::from(event_name.as_str())) }
            .expect("create the release event (the TUN lane runs elevated)"),
    );

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let _service = ProvisionedService::install_with_args(
        helper,
        vec![
            "--control-log".into(),
            log.clone().into_os_string(),
            "--release-event".into(),
            event_name.into(),
            "--on-stop".into(),
            on_stop.flag_value().into(),
        ],
    );
    let unblock = Unblock(release.0);
    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    os.start_service_wait_running()
        .expect("bring the throwaway service up via the production start seam");

    let name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: plain FFI calls; `name` is NUL-terminated and outlives them.
    let scm = ScHandle(unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }.unwrap());
    let service = ScHandle(
        unsafe {
            OpenServiceW(
                scm.0,
                PCWSTR(name.as_ptr()),
                SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_INTERROGATE,
            )
        }
        .unwrap(),
    );
    let send = |control: u32| -> Result<SERVICE_STATUS, windows::core::Error> {
        let mut status = SERVICE_STATUS::default();
        // SAFETY: `service` is a live handle and `status` outlives the call.
        unsafe { ControlService(service.0, control, &mut status) }.map(|()| status)
    };

    let first_stop = send(SERVICE_CONTROL_STOP).expect("the first Stop is delivered");
    let interrogate = send(SERVICE_CONTROL_INTERROGATE);
    let second_stop = send(SERVICE_CONTROL_STOP);

    unblock.release().unwrap();
    // Wait for the SCM's STOPPED notification without sending another Stop,
    // which the handler would log. A service that is still RUNNING fires the
    // notification at once, so each re-arm leaves out the state it was just
    // told, and the loop re-checks the real state on every report.
    let mut actor = SystemScmActor::open(SERVICE_NAME).expect("open the service for the STOPPED notification");
    let mut told = None;
    loop {
        actor.arm(WantState::Stopped, told).unwrap();
        let observed = actor.wait_callback().unwrap();
        if observed == Observed::Stopped {
            break;
        }
        told = Some(observed);
    }

    let mut final_status = SERVICE_STATUS::default();
    // SAFETY: `service` is a live handle and `final_status` outlives the call.
    unsafe { QueryServiceStatus(service.0, &mut final_status) }.unwrap();
    let observed = std::fs::read_to_string(&log)
        .expect("the handler logged the first Stop")
        .lines()
        .map(str::to_owned)
        .collect();
    Delivery {
        first_stop,
        interrogate,
        second_stop,
        final_status,
        observed,
    }
}

/// Records which controls the SCM delivers after the first Stop and asserts the
/// handler saw exactly those. The SCM refuses both later controls
/// (`ERROR_SERVICE_CANNOT_ACCEPT_CTRL`) whether the service reports STOP_PENDING
/// or RUNNING, so this cannot catch the freed-handler defect;
/// `service_ctrl_tests::handler_survives_every_control_the_scm_can_send_after_a_stop`
/// and the clippy bans pin it. The printed line is the measurement.
#[cfg(target_os = "windows")]
fn measure_controls_after_first_stop(on_stop: OnStop) {
    use windows::Win32::System::Services::{SERVICE_STATUS, SERVICE_STOPPED};

    let delivery = deliver_controls_after_first_stop(on_stop);

    assert_eq!(delivery.first_stop.dwCurrentState, on_stop.first_stop_state());
    let describe = |result: &Result<SERVICE_STATUS, windows::core::Error>| match result {
        Ok(status) => format!("delivered (state {})", status.dwCurrentState.0),
        Err(e) => format!("refused by the SCM ({e})"),
    };
    eprintln!(
        "SCM controls after Stop, service {} (first Stop answered state {}): Interrogate -> {}; second Stop -> {}",
        on_stop.flag_value(),
        delivery.first_stop.dwCurrentState.0,
        describe(&delivery.interrogate),
        describe(&delivery.second_stop),
    );
    assert_eq!(delivery.final_status.dwCurrentState, SERVICE_STOPPED);
    assert_eq!(
        delivery.final_status.dwWin32ExitCode, 0,
        "the service process must exit cleanly, not crash on a control after Stop"
    );

    let mut expected = vec!["Stop"];
    if delivery.interrogate.is_ok() {
        expected.push("Interrogate");
    }
    if delivery.second_stop.is_ok() {
        expected.push("Stop");
    }
    assert_eq!(
        delivery.observed, expected,
        "the handler must observe exactly the controls the SCM reported delivering"
    );
}

/// [`measure_controls_after_first_stop`] for a handler that reports STOP_PENDING,
/// as the bridge's does.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_service_controls_after_stop_are_measured() {
    measure_controls_after_first_stop(OnStop::ReportStopPending);
}

/// [`measure_controls_after_first_stop`] for a handler whose STOP_PENDING report
/// fails, so the service still reports RUNNING with STOP accepted.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_service_controls_after_stop_are_measured_while_the_service_reports_running() {
    measure_controls_after_first_stop(OnStop::StayRunning);
}

/// Named events a `test_service` parks on, and the guard that lets a failing
/// test release it so it cannot leave the service stuck.
#[cfg(target_os = "windows")]
mod named_event {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Threading::{CreateEventW, ResetEvent, SetEvent, WaitForSingleObject, INFINITE};

    /// A manual-reset event, created unsignalled.
    pub struct NamedEvent {
        handle: HANDLE,
        name: String,
    }

    impl NamedEvent {
        pub fn create(tag: &str) -> Self {
            let name = format!("Global\\Hole{tag}{}", std::process::id());
            // SAFETY: plain FFI call; the name is a valid HSTRING.
            let handle = unsafe { CreateEventW(None, true, false, &HSTRING::from(name.as_str())) }
                .expect("create the named event (the TUN lane runs elevated)");
            NamedEvent { handle, name }
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub fn signal(&self) {
            // SAFETY: `handle` is the live event this value owns.
            unsafe { SetEvent(self.handle) }.expect("signal the named event");
        }

        pub fn reset(&self) {
            // SAFETY: as above.
            unsafe { ResetEvent(self.handle) }.expect("reset the named event");
        }

        /// Blocks until the event is signalled. Unbounded on purpose: the event
        /// is the helper's own rendezvous, and a helper that never signals is
        /// bounded by the nextest terminate-after on these tests.
        pub fn wait(&self) {
            // SAFETY: as above.
            unsafe { WaitForSingleObject(self.handle, INFINITE) };
        }

        /// Signals the event when dropped. Declare it after the service
        /// fixture, so it drops first and a service parked on this event is
        /// released before the fixture's teardown waits for it to stop.
        pub fn release_on_drop(&self) -> ReleaseOnDrop {
            ReleaseOnDrop(self.handle)
        }
    }

    impl Drop for NamedEvent {
        fn drop(&mut self) {
            // SAFETY: the handle is the live event created above.
            let _ = unsafe { CloseHandle(self.handle) };
        }
    }

    pub struct ReleaseOnDrop(HANDLE);

    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            // SAFETY: the event outlives this guard (it is declared earlier).
            let _ = unsafe { SetEvent(self.0) };
        }
    }
}

/// Which of the processes the helper logged (`--pid-log`) are still running.
/// The SCM reports a service STOPPED before its process has exited, so this, not
/// the SCM, is what says nothing of the service is left.
#[cfg(target_os = "windows")]
mod left_behind {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use std::path::Path;

    use windows::core::PWSTR;
    use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, WaitForSingleObject, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };

    /// The ids the helper logged.
    pub fn logged(pid_log: &Path) -> Vec<u32> {
        std::fs::read_to_string(pid_log)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.trim().parse::<u32>().ok())
            .collect()
    }

    /// The logged ids whose process is still running.
    pub fn still_running(pid_log: &Path) -> Vec<u32> {
        logged(pid_log)
            .into_iter()
            .filter(|pid| is_running_helper(*pid))
            .collect()
    }

    /// Fails unless the helper logged at least `count` processes, so a test
    /// that expects a restarted instance knows one ran.
    pub fn assert_started(pid_log: &Path, count: usize) {
        let logged = logged(pid_log);
        assert!(
            logged.len() >= count,
            "the helper logged {logged:?}, fewer than the {count} processes the test expects"
        );
    }

    /// Fails unless every process the helper logged has exited. A log that
    /// names no process also fails: it would pass for any service, started or
    /// not.
    pub fn assert_none(pid_log: &Path) {
        assert!(
            !logged(pid_log).is_empty(),
            "the helper logged no process in {}: this check would prove nothing",
            pid_log.display()
        );
        let running = still_running(pid_log);
        assert!(
            running.is_empty(),
            "service processes still running after the call returned: {running:?}"
        );
    }

    fn is_running_helper(pid: u32) -> bool {
        // SAFETY: plain FFI call; no pointer is passed.
        let Ok(process) = (unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid) })
        else {
            // No process has this id: it has exited and been released.
            return false;
        };
        // SAFETY: `OpenProcess` returned a new handle this value now owns.
        let process = unsafe { OwnedHandle::from_raw_handle(process.0) };
        let handle = HANDLE(std::os::windows::io::AsRawHandle::as_raw_handle(&process));
        // SAFETY: `handle` is the live handle `process` owns.
        if unsafe { WaitForSingleObject(handle, 0) } == WAIT_OBJECT_0 {
            // Exited, kept in existence only by someone's handle.
            return false;
        }
        // Running. An id the OS has since given to another program is not the helper.
        let mut buffer = [0u16; 1024];
        let mut length = buffer.len() as u32;
        // SAFETY: `buffer` and `length` outlive the call and describe the same storage.
        unsafe { QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buffer.as_mut_ptr()), &mut length) }
            .expect("read the image of a running process");
        String::from_utf16_lossy(&buffer[..length as usize])
            .to_ascii_lowercase()
            .ends_with("test_service.exe")
    }
}

/// Raw SCM access for the tests: sending a control and reading a state without
/// going through the code under test.
#[cfg(target_os = "windows")]
mod scm_probe {
    use hole_bridge::platform::os::SERVICE_NAME;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Services::{
        CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_HANDLE,
        SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS, SERVICE_STATUS, SERVICE_STOP,
    };
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    struct ScHandle(SC_HANDLE);

    impl Drop for ScHandle {
        fn drop(&mut self) {
            // SAFETY: the handle is a live one returned by the SCM open calls.
            let _ = unsafe { CloseServiceHandle(self.0) };
        }
    }

    /// A handle that can send `HoleBridge` a Stop and read its state.
    pub struct Probe {
        service: ScHandle,
        _scm: ScHandle,
    }

    impl Probe {
        pub fn open() -> Self {
            let name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
            // SAFETY: plain FFI calls; `name` is NUL-terminated and outlives them.
            let scm = ScHandle(unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }.unwrap());
            let service = ScHandle(
                unsafe { OpenServiceW(scm.0, PCWSTR(name.as_ptr()), SERVICE_QUERY_STATUS | SERVICE_STOP) }.unwrap(),
            );
            Probe { service, _scm: scm }
        }

        /// `ControlService(STOP)`, answered as the SCM answered it.
        pub fn stop(&self) -> windows::core::Result<SERVICE_STATUS> {
            let mut status = SERVICE_STATUS::default();
            // SAFETY: `service` is a live handle and `status` outlives the call.
            unsafe { ControlService(self.service.0, SERVICE_CONTROL_STOP, &mut status) }.map(|()| status)
        }

        /// The state the SCM reports now (`SERVICE_STOPPED` is 1, START_PENDING 2,
        /// STOP_PENDING 3, RUNNING 4).
        pub fn state(&self) -> u32 {
            let mut status = SERVICE_STATUS::default();
            // SAFETY: `service` is a live handle and `status` outlives the call.
            unsafe { QueryServiceStatus(self.service.0, &mut status) }.unwrap();
            status.dwCurrentState.0
        }
    }

    pub fn state_name(state: u32) -> &'static str {
        match state {
            1 => "STOPPED",
            2 => "START_PENDING",
            3 => "STOP_PENDING",
            4 => "RUNNING",
            _ => "another state",
        }
    }

    /// The process id the SCM reports for the service now, if it reports one.
    /// Read before the service is marked for deletion: a marked service may
    /// refuse a new open.
    ///
    /// START_PENDING and STOP_PENDING may report none: Microsoft documents the
    /// id as possibly not valid there (`QueryServiceStatusEx`, Remarks).
    pub fn reported_service_process_id() -> Option<u32> {
        use windows_service::service::ServiceAccess;
        use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).unwrap();
        let service = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS).unwrap();
        service.query_status().unwrap().process_id
    }

    /// The id of the running service's process. For a caller whose setup has
    /// seen the service RUNNING, where the id is valid; a state the SCM may
    /// report no id for uses [`reported_service_process_id`].
    pub fn service_process_id() -> u32 {
        reported_service_process_id().expect("a running service has a process")
    }

    /// Sets the service's failure actions to none, so killing its process
    /// cannot bring it back. Best-effort, for teardown.
    pub fn forbid_restart(service: &windows_service::service::Service) {
        use std::time::Duration;
        use windows_service::service::{
            ServiceAction, ServiceActionType, ServiceFailureActions, ServiceFailureResetPeriod,
        };

        let _ = service.update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![ServiceAction {
                action_type: ServiceActionType::None,
                delay: Duration::ZERO,
            }]),
        });
    }

    /// Kills the process the SCM reports for `service` and returns once it has
    /// exited; nothing if it reports none or the process is already gone.
    /// Best-effort, for teardown, which also runs while a probe is panicking.
    /// Needs a handle with `QUERY_STATUS`.
    pub fn kill_process_of(service: &windows_service::service::Service) {
        use windows::Win32::System::Threading::{WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE};

        let Ok(status) = service.query_status() else { return };
        let Some(pid) = status.process_id else { return };
        // SAFETY: plain FFI calls on a handle this function opens and closes.
        unsafe {
            let Ok(process) = OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, false, pid) else {
                return;
            };
            // The exit follows a successful terminate, so the wait is on an event
            // that will happen.
            if TerminateProcess(process, 1).is_ok() {
                WaitForSingleObject(process, INFINITE);
            } else {
                eprintln!("teardown: killing the throwaway service's process {pid} was refused");
            }
            let _ = CloseHandle(process);
        }
    }

    /// A handle on process `pid`, taken while it is the service's, so a later
    /// [`wait_for_exit`] cannot land on a process that reused its id.
    pub fn watch_process(pid: u32) -> std::os::windows::io::OwnedHandle {
        use std::os::windows::io::FromRawHandle;
        use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;

        // SAFETY: plain FFI call.
        let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) }.expect("open the service process");
        // SAFETY: `OpenProcess` returned a new handle this value now owns.
        unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(process.0) }
    }

    /// Returns once the process `process` watches has exited. Unbounded on
    /// purpose: the caller has already made it exit.
    pub fn wait_for_exit(process: &std::os::windows::io::OwnedHandle) {
        use windows::Win32::System::Threading::{WaitForSingleObject, INFINITE};

        let handle = HANDLE(std::os::windows::io::AsRawHandle::as_raw_handle(process));
        // SAFETY: `handle` is the live handle `process` owns.
        unsafe { WaitForSingleObject(handle, INFINITE) };
    }

    /// Kills process `pid` the way Task Manager would.
    pub fn terminate_process(pid: u32) {
        // SAFETY: plain FFI calls on a handle this function opens and closes.
        unsafe {
            let process: HANDLE = OpenProcess(PROCESS_TERMINATE, false, pid).expect("open the service process");
            let killed = TerminateProcess(process, 1);
            let _ = CloseHandle(process);
            killed.expect("kill the service process");
        }
    }

    /// Kills the service's process, so the SCM sees a failure and applies the
    /// service's failure actions.
    pub fn kill_service_process() {
        terminate_process(service_process_id());
    }
}

/// Returns once the throwaway service reports RUNNING, with no Stop sent: each
/// pass arms for every state and acts on the one it is told.
#[cfg(target_os = "windows")]
fn wait_until_running() {
    use hole_bridge::cutover::scm_wait::{Observed, ScmActor, SystemScmActor, WantState};
    use hole_bridge::platform::os::SERVICE_NAME;

    let mut actor = SystemScmActor::open(SERVICE_NAME).expect("open the service to wait for RUNNING");
    let mut told = None;
    loop {
        actor.arm(WantState::Stopped, told).unwrap();
        let observed = actor.wait_callback().unwrap();
        match observed {
            Observed::Running => return,
            Observed::Stopped => panic!("the service stopped while waiting for it to run"),
            Observed::StartPending | Observed::StopPending => told = Some(observed),
        }
    }
}

/// Returns once the throwaway service reports STOPPED, with no Stop sent.
#[cfg(target_os = "windows")]
fn wait_until_stopped() {
    use hole_bridge::cutover::scm_wait::{Observed, ScmActor, SystemScmActor, WantState};
    use hole_bridge::platform::os::SERVICE_NAME;

    let mut actor = SystemScmActor::open(SERVICE_NAME).expect("open the service to wait for STOPPED");
    let mut told = None;
    loop {
        actor.arm(WantState::Stopped, told).unwrap();
        let observed = actor.wait_callback().unwrap();
        if observed == Observed::Stopped {
            return;
        }
        told = Some(observed);
    }
}

/// Starts the throwaway service on its own thread: `StartService` may not
/// return while a held helper sits in START_PENDING.
#[cfg(target_os = "windows")]
fn start_in_background() -> std::thread::JoinHandle<windows_service::Result<()>> {
    use hole_bridge::platform::os::SERVICE_NAME;
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    std::thread::spawn(|| {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        manager
            .open_service(SERVICE_NAME, ServiceAccess::START)?
            .start::<&str>(&[])
    })
}

/// The stop probe (bindreams/hole#1099): what the SCM answers a Stop sent to a
/// service in each state a restart passes through, and what an arm for every
/// state reports there. These are the facts the stop wait's policy rests on,
/// printed so a run states them instead of the code assuming them.
///
/// The arm is measured first (it changes nothing), then the Stop. The held
/// scenarios release the helper after both, so the wait always has a transition
/// to fire on: if the arm does not report the current state, the result is the
/// RUNNING the release produces, and the line says so.
#[cfg(target_os = "windows")]
mod stop_probe {
    use hole_bridge::cutover::scm_wait::{Observed, ScmActor, SystemScmActor, WantState};
    use hole_bridge::platform::os::SERVICE_NAME;

    use super::named_event::NamedEvent;
    use super::scm_probe::{state_name, Probe};
    use super::ProvisionedService;

    /// What one scenario measured.
    pub struct Reading {
        pub state_before: u32,
        pub stop: windows::core::Result<windows::Win32::System::Services::SERVICE_STATUS>,
        pub first_report: Observed,
    }

    pub fn print(scenario: &str, reading: &Reading) {
        let stop = match &reading.stop {
            Ok(status) => format!("delivered, answered state {}", state_name(status.dwCurrentState.0)),
            Err(e) => format!("refused: {e}"),
        };
        eprintln!(
            "SCM stop probe, {scenario}: state {}; ControlService(STOP) -> {stop}; arm for STOPPED|START_PENDING|STOP_PENDING|RUNNING first reported {:?}",
            state_name(reading.state_before),
            reading.first_report,
        );
    }

    /// Arms for every state on a fresh actor, sends a Stop, and takes the first
    /// report. `after_report` runs once the report is in hand, so nothing it does
    /// (releasing a parked helper) can change what was reported.
    fn arm_stop_wait(probe: &Probe, after_report: impl FnOnce()) -> Reading {
        let mut actor = SystemScmActor::open(SERVICE_NAME).expect("open the service to arm on");
        let state_before = probe.state();
        actor.arm(WantState::Stopped, None).expect("arm for every state");
        let stop = probe.stop();
        let first_report = actor.wait_callback().expect("the armed notification fires");
        after_report();
        Reading {
            state_before,
            stop,
            first_report,
        }
    }

    pub fn running(helper: &std::path::Path) -> Reading {
        let _service = ProvisionedService::install(helper);
        let mut os = super::WindowsCutoverOs {
            images: vec![],
            target_version: "test".into(),
        };
        super::CutoverOs::start_service_wait_running(&mut os).expect("bring the service up");
        let probe = Probe::open();
        let reading = arm_stop_wait(&probe, || {});
        assert_eq!(reading.state_before, 4, "the scenario is a RUNNING service");
        reading
    }

    /// A killed service whose restart is a long way off: STOPPED, restart pending.
    pub fn stopped_with_a_restart_pending(helper: &std::path::Path) -> Reading {
        let _service = ProvisionedService::install_with(helper, vec![], Some(std::time::Duration::from_secs(60 * 60)));
        let mut os = super::WindowsCutoverOs {
            images: vec![],
            target_version: "test".into(),
        };
        super::CutoverOs::start_service_wait_running(&mut os).expect("bring the service up");
        super::scm_probe::kill_service_process();
        super::wait_until_stopped();
        let probe = Probe::open();
        let reading = arm_stop_wait(&probe, || {});
        assert_eq!(reading.state_before, 1, "the scenario is a STOPPED service");
        reading
    }

    /// A service held in START_PENDING by `flag` (`--hold-start`: attached and
    /// reporting; `--delay-attach`: created, not yet attached).
    pub fn held_start_pending(helper: &std::path::Path, flag: &str) -> Reading {
        let parked = NamedEvent::create("ProbeParked");
        let release = NamedEvent::create("ProbeRelease");
        let _service = ProvisionedService::install_with(
            helper,
            vec![
                flag.into(),
                release.name().into(),
                "--parked-event".into(),
                parked.name().into(),
            ],
            None,
        );
        let _release_on_drop = release.release_on_drop();
        let starter = super::start_in_background();
        parked.wait();
        let probe = Probe::open();
        let reading = arm_stop_wait(&probe, || release.signal());
        starter.join().unwrap().expect("the held service starts once released");
        assert_eq!(reading.state_before, 2, "the scenario is a START_PENDING service");
        reading
    }
}

#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_stop_probe_running() {
    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    stop_probe::print("RUNNING", &stop_probe::running(helper));
}

#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_stop_probe_stopped_with_a_restart_pending() {
    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    stop_probe::print(
        "STOPPED, restart pending",
        &stop_probe::stopped_with_a_restart_pending(helper),
    );
}

#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_stop_probe_start_pending_after_attach() {
    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    stop_probe::print(
        "START_PENDING, attached",
        &stop_probe::held_start_pending(helper, "--hold-start"),
    );
}

#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_stop_probe_start_pending_before_attach() {
    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    stop_probe::print(
        "START_PENDING, process not attached",
        &stop_probe::held_start_pending(helper, "--delay-attach"),
    );
}

/// The service-SID probe: whether the token of a process carries the
/// `NT SERVICE\HoleBridge` SID, and with which access rights the token can be read
/// at all. These are the facts the identity check (`ServiceSid::is_in_token_of`)
/// rests on, printed so a run states them instead of the code assuming them.
///
/// The caller is an elevated administrator, which `create_service` needs, and
/// that caller is what these tests assert on: it must open the service's
/// process and read its token. A LocalSystem caller (the MSI custom action)
/// cannot be had without a second SYSTEM process; the scan probe
/// (`sid_probes::cutover_global_net_state_probe_scan_by_service_sid`) runs one
/// as a scheduled task and prints what it could read.
#[cfg(target_os = "windows")]
mod sid_probe {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

    use hole_bridge::platform::os::{ServiceSid, SERVICE_NAME};
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{
        AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, TokenGroups, LUID_AND_ATTRIBUTES,
        SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_GROUPS, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };

    /// What the production identity check answered.
    #[derive(Debug)]
    pub enum ProductionCheck {
        /// The SCM reported no process id, so there was nothing to open.
        NoProcessId,
        /// The process or its token could not be opened with the hold's rights.
        Unreadable,
        /// The check ran: whether the token carries the service SID.
        Answered(bool),
        /// A step outside the open (the SID lookup, a second open) failed.
        Failed(String),
    }

    impl ProductionCheck {
        /// What this answer is, said once per variant.
        fn meaning(&self) -> String {
            match self {
                ProductionCheck::NoProcessId => {
                    "the SCM named no process in this state, so there was nothing to open".into()
                }
                ProductionCheck::Unreadable => {
                    "the process or its token could not be opened with the hold's rights from this caller (an elevated administrator without SeDebugPrivilege); the lines above say which step was refused and with what code".into()
                }
                ProductionCheck::Answered(true) => {
                    "the token carries the service SID: the check can tell this process from a stranger".into()
                }
                ProductionCheck::Answered(false) => {
                    "the token does not carry the service SID: a stranger, or a service process started before the SID type was set".into()
                }
                ProductionCheck::Failed(reason) => format!("a step around the check failed: {reason}"),
            }
        }
    }

    /// What one process's token measured.
    pub struct Measure {
        /// One line per (rights, step) attempted.
        pub lines: Vec<String>,
        /// The answer of the production check with the rights it opens with.
        pub production_check: ProductionCheck,
    }

    /// The service SID as the OS's own tool prints it (`sc showsid`), the
    /// expected value derived apart from the code under test.
    pub fn sc_showsid() -> String {
        let out = std::process::Command::new("sc.exe")
            .args(["showsid", SERVICE_NAME])
            .output()
            .expect("run sc.exe showsid");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join(" | ")
    }

    /// Enables `SeDebugPrivilege` on this process's token; says what happened.
    fn enable_se_debug() -> String {
        let mut token = HANDLE::default();
        // SAFETY: plain FFI calls on this process's own token, closed below.
        unsafe {
            if let Err(e) = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) {
                return format!("could not open own token: {e}");
            }
            let mut luid = Default::default();
            if let Err(e) = LookupPrivilegeValueW(None, SE_DEBUG_NAME, &mut luid) {
                let _ = CloseHandle(token);
                return format!("could not look up SeDebugPrivilege: {e}");
            }
            let privileges = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            let adjusted = AdjustTokenPrivileges(token, false, Some(&privileges), 0, None, None);
            // `AdjustTokenPrivileges` succeeds even when nothing was assigned;
            // the last error says which.
            let assigned = windows::Win32::Foundation::GetLastError();
            let _ = CloseHandle(token);
            match adjusted {
                Err(e) => format!("AdjustTokenPrivileges failed: {e}"),
                Ok(()) if assigned == windows::Win32::Foundation::ERROR_NOT_ALL_ASSIGNED => {
                    "not held by this token (ERROR_NOT_ALL_ASSIGNED)".into()
                }
                Ok(()) => "enabled".into(),
            }
        }
    }

    /// The groups of `process`'s token as SID strings, or the failing step.
    fn token_groups(process: &OwnedHandle) -> Result<Vec<String>, String> {
        let mut token = HANDLE::default();
        // SAFETY: `process` is a live handle; `token` is an out-parameter.
        unsafe { OpenProcessToken(HANDLE(process.as_raw_handle()), TOKEN_QUERY, &mut token) }
            .map_err(|e| format!("OpenProcessToken(TOKEN_QUERY) -> Err {e}"))?;
        // SAFETY: `OpenProcessToken` returned a new handle this value now owns.
        let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
        let token = HANDLE(token.as_raw_handle());
        let mut len = 0u32;
        // SAFETY: the sizing call; its expected failure is ignored.
        let _ = unsafe { GetTokenInformation(token, TokenGroups, None, 0, &mut len) };
        let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
        // SAFETY: `buf` holds at least `len` bytes.
        unsafe { GetTokenInformation(token, TokenGroups, Some(buf.as_mut_ptr().cast()), len, &mut len) }
            .map_err(|e| format!("GetTokenInformation(TokenGroups) -> Err {e}"))?;
        // SAFETY: on success `buf` holds a `TOKEN_GROUPS` and its entries.
        let groups = unsafe {
            let groups = &*buf.as_ptr().cast::<TOKEN_GROUPS>();
            std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize)
        };
        let mut names = Vec::new();
        for group in groups {
            let mut raw = PWSTR::null();
            // SAFETY: the group's SID is valid inside `buf`; `raw` is freed below.
            unsafe { ConvertSidToStringSidW(group.Sid, &mut raw) }
                .map_err(|e| format!("ConvertSidToStringSidW: {e}"))?;
            // SAFETY: `raw` is a NUL-terminated string owned until `LocalFree`.
            names.push(unsafe { raw.to_string() }.unwrap_or_default());
            // SAFETY: `raw` came from `LocalAlloc` inside the conversion.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(raw.0.cast())));
            }
        }
        Ok(names)
    }

    fn attempt(
        pid: u32,
        label: &str,
        rights: windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS,
    ) -> (String, bool) {
        // SAFETY: plain FFI call.
        let process = match unsafe { OpenProcess(rights, false, pid) } {
            Ok(handle) => {
                // SAFETY: `OpenProcess` returned a new handle this value owns.
                unsafe { OwnedHandle::from_raw_handle(handle.0) }
            }
            Err(e) => return (format!("  {label}: OpenProcess -> Err {e}"), false),
        };
        match token_groups(&process) {
            Ok(groups) => (
                format!("  {label}: OpenProcess -> Ok; token groups: {}", groups.join(", ")),
                true,
            ),
            Err(step) => (format!("  {label}: OpenProcess -> Ok; {step}"), false),
        }
    }

    /// Measures the process `pid` names; `None` is the SCM reporting no id.
    pub fn measure(pid: Option<u32>) -> Measure {
        let Some(pid) = pid else {
            return Measure {
                lines: vec!["  the SCM reported no process id: nothing to open".into()],
                production_check: ProductionCheck::NoProcessId,
            };
        };
        let mut lines = Vec::new();
        let query = PROCESS_QUERY_LIMITED_INFORMATION;
        let hold = PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;
        lines.push(attempt(pid, "PROCESS_QUERY_LIMITED_INFORMATION", query).0);
        let (line, opened) = attempt(
            pid,
            "PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION (what the hold opens)",
            hold,
        );
        lines.push(line);

        // The production check, on a handle opened with the hold's rights.
        let production_check = if opened {
            production_check(pid, hold)
        } else {
            ProductionCheck::Unreadable
        };

        lines.push(format!("  SeDebugPrivilege: {}", enable_se_debug()));
        lines.push(
            attempt(
                pid,
                "with SeDebugPrivilege, PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION",
                hold,
            )
            .0,
        );
        Measure {
            lines,
            production_check,
        }
    }

    fn production_check(pid: u32, hold: windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS) -> ProductionCheck {
        // SAFETY: plain FFI call.
        let handle = match unsafe { OpenProcess(hold, false, pid) } {
            Ok(handle) => handle,
            Err(e) => return ProductionCheck::Failed(format!("open again with the hold's rights: {e}")),
        };
        // SAFETY: `OpenProcess` returned a new handle this value owns.
        let process = unsafe { OwnedHandle::from_raw_handle(handle.0) };
        match ServiceSid::of(SERVICE_NAME).is_in_token_of(&process) {
            Ok(carries) => ProductionCheck::Answered(carries),
            Err(e) => ProductionCheck::Failed(format!("read the token the first attempt read: {e}")),
        }
    }

    /// Prints what was measured, for the process `reported` names.
    pub fn print(scenario: &str, reported: Option<u32>, measure: &Measure) {
        eprintln!(
            "service SID probe, {scenario} (pid: {reported:?}; None is the SCM naming no process); `sc showsid {SERVICE_NAME}`: {}
{}
               production check `ServiceSid::is_in_token_of` -> {:?}
               MEANS: {}",
            sc_showsid(),
            measure.lines.join("
"),
            measure.production_check,
            measure.production_check.meaning(),
        );
    }
}

/// Installs the throwaway service with the SID type set, brings it to the state
/// `flag` selects (RUNNING for `None`, START_PENDING for `--hold-start`) and
/// measures the process the SCM names there. The id is `None` when the SCM
/// reports none: the state's own contract allows it in START_PENDING, so it is
/// a result, not a failure.
#[cfg(target_os = "windows")]
fn service_sid_probe_of_a_service(helper: &std::path::Path, flag: Option<&str>) -> (Option<u32>, sid_probe::Measure) {
    let parked = named_event::NamedEvent::create("SidProbeParked");
    let release = named_event::NamedEvent::create("SidProbeRelease");
    let launch_arguments = match flag {
        Some(flag) => vec![
            flag.into(),
            release.name().into(),
            "--parked-event".into(),
            parked.name().into(),
        ],
        None => vec![],
    };
    let _service = ProvisionedService::install_with(helper, launch_arguments, None);
    let _release_on_drop = release.release_on_drop();
    match flag {
        Some(_) => {
            let starter = start_in_background();
            parked.wait();
            let reported = scm_probe::reported_service_process_id();
            let measure = sid_probe::measure(reported);
            release.signal();
            starter.join().unwrap().expect("the held service starts once released");
            (reported, measure)
        }
        None => {
            let mut os = WindowsCutoverOs {
                images: vec![],
                target_version: "test".into(),
            };
            CutoverOs::start_service_wait_running(&mut os).expect("bring the service up");
            // RUNNING was seen, where the id is valid.
            let pid = scm_probe::service_process_id();
            (Some(pid), sid_probe::measure(Some(pid)))
        }
    }
}

// The service-SID probes print what they measured and assert the answer of the
// production check for the elevated administrator that runs them.

/// Fails unless the production check answered `expected`.
#[cfg(target_os = "windows")]
fn assert_answers(measure: &sid_probe::Measure, expected: bool, scenario: &str) {
    assert!(
        matches!(measure.production_check, sid_probe::ProductionCheck::Answered(answer) if answer == expected),
        "{scenario}: the production check was expected to answer Answered({expected}), got {:?}",
        measure.production_check
    );
}

#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_service_sid_probe_running() {
    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let (reported, measure) = service_sid_probe_of_a_service(helper, None);
    sid_probe::print("RUNNING, service SID type set", reported, &measure);
    assert_answers(&measure, true, "RUNNING, service SID type set");
}

#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_service_sid_probe_start_pending() {
    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let (reported, measure) = service_sid_probe_of_a_service(helper, Some("--hold-start"));
    sid_probe::print("START_PENDING (--hold-start), service SID type set", reported, &measure);
}

/// What a service process started before the SID type was set looks like: its
/// token does not carry the SID.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_service_sid_probe_running_without_the_sid_type() {
    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let _service = ProvisionedService::install_without_sid(helper);
    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    CutoverOs::start_service_wait_running(&mut os).expect("bring the service up");
    // RUNNING was seen, where the id is valid.
    let pid = scm_probe::service_process_id();
    let measure = sid_probe::measure(Some(pid));
    sid_probe::print("RUNNING, service SID type NOT set", Some(pid), &measure);
    assert_answers(&measure, false, "RUNNING, service SID type NOT set");
}

/// The service's SID type as the OS's own tool prints it (`sc qsidtype`), read
/// apart from the code under test.
#[cfg(target_os = "windows")]
fn sc_qsidtype() -> String {
    use hole_bridge::platform::os::SERVICE_NAME;

    let out = std::process::Command::new("sc.exe")
        .args(["qsidtype", SERVICE_NAME])
        .output()
        .expect("run sc.exe qsidtype");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.lines()
        .find_map(|line| line.trim().strip_prefix("SERVICE_SID_TYPE:"))
        .unwrap_or_else(|| panic!("sc qsidtype printed no SERVICE_SID_TYPE line: {text}"))
        .trim()
        .to_owned()
}

/// A bridge service that was registered without the service SID type (what an
/// in-app update leaves behind) gets it when it starts, and a later start finds
/// it set and writes nothing. `test_service --sid-repair-log` runs the bridge's
/// own `registration::run_startup_repairs`, the function `run_service` calls
/// (a unit test pins that call and its place), before reporting RUNNING and
/// logs what it did, so the config is read once the start has returned, and the
/// second start's outcome says whether it wrote.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_service_without_the_sid_type_gets_it_at_startup() {
    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("sid-repair.log");
    let _service = ProvisionedService::install_without_sid_with_args(
        helper,
        vec!["--sid-repair-log".into(), log.clone().into_os_string()],
    );
    assert_eq!(sc_qsidtype(), "NONE", "the fixture starts without the SID type");

    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    CutoverOs::start_service_wait_running(&mut os).expect("start the service");
    assert_eq!(sc_qsidtype(), "UNRESTRICTED", "the first start sets the SID type");

    CutoverOs::stop_service_wait_stopped(&mut os).expect("stop the service");
    CutoverOs::start_service_wait_running(&mut os).expect("start the service again");
    assert_eq!(sc_qsidtype(), "UNRESTRICTED");

    let outcomes = std::fs::read_to_string(&log).expect("the helper logs each start's outcome");
    assert_eq!(
        outcomes.lines().collect::<Vec<_>>(),
        ["Applied", "AlreadySet"],
        "the first start writes the SID type and the second finds it set"
    );
}

/// `hole bridge install` gives the service the SID type, through the real
/// `install` on a throwaway binary path (the service is never started). A
/// service without it makes the uninstaller skip the wait for the service's
/// process, and nothing else in the suite fails for that.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_install_gives_the_service_its_sid_type() {
    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    ProvisionedService::require_no_leftover();
    // Deleted on drop, whatever `install` got done before it failed.
    let _service = ProvisionedService;
    hole_bridge::platform::os::install(helper).expect("install the service");
    assert_eq!(sc_qsidtype(), "UNRESTRICTED");
}

/// A process that is not the service: this test's own.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_service_sid_probe_a_stranger() {
    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let _service = ProvisionedService::install(helper);
    let pid = std::process::id();
    let measure = sid_probe::measure(Some(pid));
    sid_probe::print(
        "a stranger (this test's own process), service registered",
        Some(pid),
        &measure,
    );
    assert_answers(&measure, false, "a stranger");
}

/// `OpenProcess(PROCESS_SYNCHRONIZE)` on the service process from the caller's
/// token: the open every held process rests on. The caller here is an elevated
/// administrator (the TUN lane runs elevated, which `create_service` needs). A
/// SYSTEM caller (the MSI custom action) cannot be reproduced by a test without a
/// second SYSTEM process; its first real answer is the CI installer test's
/// uninstall, whose `gui-cli.log` dump names `OpenProcess` and its code if it was
/// refused.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_stop_probe_open_process_synchronize_on_the_service_process() {
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows::Win32::System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE};
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let _service = ProvisionedService::install(helper);
    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    CutoverOs::start_service_wait_running(&mut os).expect("bring the service up");
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).unwrap();
    let service = manager
        .open_service(hole_bridge::platform::os::SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .unwrap();
    let pid = service
        .query_status()
        .unwrap()
        .process_id
        .expect("a running service has a process");

    // SAFETY: plain FFI calls on a handle this test opens and closes.
    let opened = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) };
    let outcome = match &opened {
        Ok(handle) => {
            let waited = unsafe { WaitForSingleObject(*handle, 0) };
            let state = if waited == WAIT_TIMEOUT {
                "not signalled (the process is running)"
            } else if waited == WAIT_OBJECT_0 {
                "signalled (the process has exited)"
            } else {
                "another answer"
            };
            let _ = unsafe { CloseHandle(*handle) };
            format!("Ok; zero-timeout wait -> {state}")
        }
        Err(e) => format!("Err {e} (win32 code {})", e.code().0 & 0xFFFF),
    };
    eprintln!(
        "SCM stop probe, OpenProcess(PROCESS_SYNCHRONIZE) on the LocalSystem service process (pid {pid}) from an elevated administrator: {outcome}\n  \
         MEANS: Ok => the process hold (scm_wait/hold.rs, service_processes.rs) works for `hole bridge uninstall` run elevated, and \
         the zero-timeout wait is the exit check `ProcessFate` reads. Err 5 (ACCESS_DENIED) => every uninstall by an elevated \
         administrator fails with RetireError::Hold (\"the service's process could not be opened ...: OpenProcess failed\"), \
         where it worked before the hold existed, and the exit has to be awaited another way (an owner question). \
         SYSTEM (the MSI custom action) is not measured here."
    );
}

/// The hook that releases a parked helper as the retirement goes to sleep. The
/// service is parked in START_PENDING by construction, the look that said so is
/// recorded, and the wait the retirement is about to make is for a state change
/// only the release produces. What the helper does after its release is found
/// out by the code under test from the SCM, not from this hook.
#[cfg(target_os = "windows")]
fn releasing(release: &named_event::NamedEvent) -> recording::Hook<'_> {
    let mut released = false;
    Box::new(move |event| {
        let is_a_sleep = matches!(
            event,
            recording::Event::AwaitCallback | recording::Event::AwaitHeldExits
        );
        if is_a_sleep && !released {
            released = true;
            release.signal();
        }
    })
}

/// Retires the registered service through the production `retire`, over a
/// session that records each act, and returns the record. The session's
/// handles are closed first: they keep a deleted service registered, and a
/// test that waits for the deletion must not hold it.
#[cfg(target_os = "windows")]
fn deregister_recorded(hook: recording::Hook<'_>) -> recording::Trace {
    use hole_bridge::cutover::scm_wait::retire::{retire, Disposition};

    let mut session = recording::open_retire_session(hook);
    retire(&mut session, Disposition::Deregister).expect("the retirement succeeds");
    session.finish()
}

/// Retires a service parked in START_PENDING by `flag`, and checks it ends up
/// deregistered. The first look must be the parked START_PENDING (the case a
/// blind Stop used to be sent into), and the Stop must have come only after a
/// later RUNNING, with the start type already disabled.
#[cfg(target_os = "windows")]
fn retire_a_parked_service(flag: &str) {
    use hole_bridge::cutover::scm_wait::Observed;
    use hole_bridge::platform::os::SERVICE_NAME;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let parked = named_event::NamedEvent::create("RetireParked");
    let release = named_event::NamedEvent::create("RetireRelease");
    let _service = ProvisionedService::install_with(
        helper,
        vec![
            flag.into(),
            release.name().into(),
            "--parked-event".into(),
            parked.name().into(),
        ],
        None,
    );
    let _release_on_drop = release.release_on_drop();
    let starter = start_in_background();
    parked.wait();

    let trace = deregister_recorded(releasing(&release));

    starter.join().unwrap().expect("the held service starts once released");
    scm_deletion::wait_until_deleted(SERVICE_NAME).expect("the service is deleted");
    let observed = trace.observed();
    assert_eq!(
        observed.first(),
        Some(&Observed::StartPending),
        "the first look is the parked state: {observed:?}"
    );
    assert!(
        observed.contains(&Observed::Running),
        "the held service ran before it was stopped: {observed:?}"
    );
    assert!(trace.stops() > 0, "the service that ran needed a Stop: {trace:#?}");
    trace.assert_the_order_of_a_deregistration();
}

#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_uninstall_waits_out_a_service_held_in_start_pending() {
    retire_a_parked_service("--hold-start");
}

#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_uninstall_waits_out_a_service_not_yet_attached() {
    retire_a_parked_service("--delay-attach");
}

/// The SCM restarts a killed service (the restart delay is configuration; the
/// test blocks on the helper's parked event) and the retirement lands on the
/// restarted, START_PENDING instance. Neither instance's process may be left.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_uninstall_lands_on_the_instance_the_scm_just_restarted() {
    use hole_bridge::cutover::scm_wait::Observed;
    use hole_bridge::platform::os::SERVICE_NAME;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let dir = tempfile::tempdir().unwrap();
    let pid_log = dir.path().join("pids.log");
    let parked = named_event::NamedEvent::create("RestartParked");
    let release = named_event::NamedEvent::create("RestartRelease");
    let mut args: Vec<std::ffi::OsString> = vec![
        "--hold-start".into(),
        release.name().into(),
        "--parked-event".into(),
        parked.name().into(),
    ];
    args.extend(pid_log_args(&pid_log));
    let _service = ProvisionedService::install_with(helper, args, Some(std::time::Duration::from_secs(1)));
    let _release_on_drop = release.release_on_drop();

    // First instance: let it start, then kill it.
    let starter = start_in_background();
    parked.wait();
    release.signal();
    starter.join().unwrap().expect("the first instance starts");
    wait_until_running();
    release.reset();
    parked.reset();
    scm_probe::kill_service_process();

    // The SCM restarts it; the new instance parks in START_PENDING.
    parked.wait();

    let trace = deregister_recorded(releasing(&release));
    left_behind::assert_started(&pid_log, 2);
    left_behind::assert_none(&pid_log);
    scm_deletion::wait_until_deleted(SERVICE_NAME).expect("the service is deleted");
    let observed = trace.observed();
    assert_eq!(
        observed.first(),
        Some(&Observed::StartPending),
        "the first look is the restarted instance's START_PENDING: {observed:?}"
    );
    assert!(trace.stops() > 0, "the restarted instance needed a Stop: {trace:#?}");
    trace.assert_the_order_of_a_deregistration();
}

/// A killed service reads STOPPED while its restart is pending (an hour away,
/// so the state holds for the whole test). The retirement finds that state,
/// sends no Stop, and leaves no row and no process. This observes the state;
/// that the restart is suppressed is asserted through the start type every
/// retirement's record carries, not by waiting for an instance that must not
/// appear.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_uninstall_deregisters_a_killed_service_with_a_restart_pending() {
    use hole_bridge::cutover::scm_wait::Observed;
    use hole_bridge::platform::os::SERVICE_NAME;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let dir = tempfile::tempdir().unwrap();
    let pid_log = dir.path().join("pids.log");
    let _service = ProvisionedService::install_with(
        helper,
        pid_log_args(&pid_log),
        Some(std::time::Duration::from_secs(60 * 60)),
    );
    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    CutoverOs::start_service_wait_running(&mut os).expect("bring the service up");
    scm_probe::kill_service_process();
    wait_until_stopped();

    let trace = deregister_recorded(Box::new(|_| {}));
    left_behind::assert_none(&pid_log);
    scm_deletion::wait_until_deleted(SERVICE_NAME).expect("the service is deleted");
    assert_eq!(
        trace.observed().first(),
        Some(&Observed::Stopped),
        "the first look is the killed service's STOPPED: {trace:#?}"
    );
    assert_eq!(trace.stops(), 0, "a stopped service takes no Stop: {trace:#?}");
    trace.assert_the_order_of_a_deregistration();
}

/// The other side of the race the five-round smoke test below draws at random,
/// taken deterministically: the SCM has already restarted the killed service
/// (no delay) and the replacement is RUNNING when the retirement begins. The
/// retirement stops the second instance, and neither process is left.
///
/// The replacement's RUNNING is read from the helper's event, which it signals
/// once per start. The first instance's own signal is consumed before the
/// reset, so it cannot be mistaken for the replacement's.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_uninstall_stops_the_instance_the_scm_restarted_while_running() {
    use hole_bridge::cutover::scm_wait::Observed;
    use hole_bridge::platform::os::SERVICE_NAME;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let dir = tempfile::tempdir().unwrap();
    let pid_log = dir.path().join("pids.log");
    let running = named_event::NamedEvent::create("ReplacementRunning");
    let mut args = pid_log_args(&pid_log);
    args.extend(["--running-event".into(), running.name().into()]);
    let _service = ProvisionedService::install_with(helper, args, Some(std::time::Duration::ZERO));
    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    CutoverOs::start_service_wait_running(&mut os).expect("bring the service up");
    running.wait();
    running.reset();
    scm_probe::kill_service_process();
    running.wait();

    let trace = deregister_recorded(Box::new(|_| {}));
    left_behind::assert_started(&pid_log, 2);
    left_behind::assert_none(&pid_log);
    scm_deletion::wait_until_deleted(SERVICE_NAME).expect("the service is deleted");
    assert_eq!(
        trace.observed().first(),
        Some(&Observed::Running),
        "the first look is the replacement's RUNNING: {trace:#?}"
    );
    assert!(trace.stops() > 0, "the replacement needed a Stop: {trace:#?}");
    trace.assert_the_order_of_a_deregistration();
}

/// Who stops the service whose process then outlives STOPPED.
#[cfg(target_os = "windows")]
#[derive(Clone, Copy)]
enum StoppedBy {
    /// The retirement's own Stop, sent into a RUNNING service whose process it
    /// holds, so it waits on that process.
    TheRetirement,
    /// The test, before the retirement begins: the first look is already
    /// STOPPED, which names no process, so only the scan for the service's
    /// token can find the one that is left.
    TheTest,
}

/// A service process that outlives the STOPPED the SCM reports for it. The
/// helper reports STOPPED on the Stop, then parks until the test signals; the
/// uninstall must still be waiting on that process when the test looks.
///
/// The retirement runs on a thread over a recording session that sends
/// `Reached` as it begins to wait on the held process and `Returned` when the
/// retirement ends, both on one channel. The first message must be `Reached`,
/// with the helper alive; only then does the test let the process exit, so a
/// retirement that returns first never waited. There is no timing: the thread's
/// next message is whatever the retirement does next.
#[cfg(target_os = "windows")]
fn uninstall_waits_out_a_process_that_outlives_stopped(stopped_by: StoppedBy) {
    use hole_bridge::cutover::scm_wait::retire::{retire, Disposition, RetireError};
    use hole_bridge::platform::os::SERVICE_NAME;

    #[derive(Debug)]
    enum Message {
        /// The retirement began to wait on a held process; the helper
        /// processes alive at that moment.
        Reached(Vec<u32>),
        Returned(Result<(), RetireError>),
    }

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let dir = tempfile::tempdir().unwrap();
    let pid_log = dir.path().join("pids.log");
    let parked = named_event::NamedEvent::create("OutlivesParked");
    let exit = named_event::NamedEvent::create("OutlivesExit");
    let mut args = pid_log_args(&pid_log);
    args.extend([
        "--outlive-stopped".into(),
        exit.name().into(),
        "--parked-event".into(),
        parked.name().into(),
    ]);
    let _service = ProvisionedService::install_with_args(helper, args);
    let _exit_on_drop = exit.release_on_drop();
    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    CutoverOs::start_service_wait_running(&mut os).expect("bring the service up");
    let service_pids = left_behind::logged(&pid_log);
    assert_eq!(service_pids.len(), 1, "one service process so far: {service_pids:?}");

    if let StoppedBy::TheTest = stopped_by {
        scm_probe::Probe::open().stop().expect("the test stops the service");
        // The helper parks only after reporting STOPPED, so the retirement's
        // first look finds a stopped service whose process is still alive.
        parked.wait();
    }

    let (messages, inbox) = std::sync::mpsc::channel();
    let thread_pid_log = pid_log.clone();
    let retirement = std::thread::spawn(move || {
        let reached = messages.clone();
        let hook: recording::Hook<'_> = Box::new(move |event| {
            if matches!(event, recording::Event::AwaitHeldExits) {
                let _ = reached.send(Message::Reached(left_behind::still_running(&thread_pid_log)));
            }
        });
        let mut session = recording::open_retire_session(hook);
        let result = retire(&mut session, Disposition::Deregister);
        let trace = session.finish();
        let _ = messages.send(Message::Returned(result));
        trace
    });

    parked.wait();
    match inbox.recv().expect("the retirement ended without a message") {
        Message::Reached(alive) => {
            assert_eq!(
                alive, service_pids,
                "the process waited on is the helper's, and it is alive"
            )
        }
        returned @ Message::Returned(_) => panic!(
            "the uninstall returned while the service process was still alive, \
             without waiting on it: {returned:?}"
        ),
    }
    exit.signal();
    let mut waits = 1;
    let result = loop {
        match inbox.recv().expect("the retirement ended without returning") {
            Message::Reached(_) => waits += 1,
            Message::Returned(result) => break result,
        }
    };
    result.expect("the uninstall succeeds once the process exits");
    assert_eq!(waits, 1, "one wait on the held process, not a loop that spins");

    let trace = retirement.join().expect("the retirement thread");
    left_behind::assert_none(&pid_log);
    scm_deletion::wait_until_deleted(SERVICE_NAME).expect("the service is deleted");
    trace.assert_the_order_of_a_deregistration();
    match stopped_by {
        StoppedBy::TheRetirement => assert!(trace.stops() > 0, "the retirement stopped the service: {trace:#?}"),
        StoppedBy::TheTest => assert_eq!(trace.stops(), 0, "the service was already stopped: {trace:#?}"),
    }
}

#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_uninstall_waits_out_a_service_process_that_outlives_its_own_stop() {
    uninstall_waits_out_a_process_that_outlives_stopped(StoppedBy::TheRetirement);
}

#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_uninstall_finds_a_service_process_that_outlived_stopped_before_it_began() {
    uninstall_waits_out_a_process_that_outlives_stopped(StoppedBy::TheTest);
}

/// A service whose process the retirement cannot hold (one started before the
/// SID type, so its token has no service SID) has no exit to wait on: the SCM's
/// report of the Stop is the only event, so the arm for it must come before the
/// Stop. The record shows the order.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_uninstall_arms_before_the_stop_of_a_service_it_cannot_hold() {
    use hole_bridge::platform::os::SERVICE_NAME;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let _service = ProvisionedService::install_without_sid(helper);
    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    CutoverOs::start_service_wait_running(&mut os).expect("bring the service up");

    let trace = deregister_recorded(Box::new(|_| {}));
    scm_deletion::wait_until_deleted(SERVICE_NAME).expect("the service is deleted");
    trace.assert_the_order_of_a_deregistration();
    trace.assert_every_stop_follows_an_arm();
}

/// Unchanged behaviour: a RUNNING service is stopped and deregistered.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_uninstall_deregisters_a_running_service() {
    use hole_bridge::platform::os::SERVICE_NAME;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let dir = tempfile::tempdir().unwrap();
    let pid_log = dir.path().join("pids.log");
    let _service = ProvisionedService::install_with_args(helper, pid_log_args(&pid_log));
    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    CutoverOs::start_service_wait_running(&mut os).expect("bring the service up");

    hole_bridge::platform::os::uninstall().expect("uninstall a running service");
    // Before the deletion is awaited: the uninstall itself returns with no
    // service process left.
    left_behind::assert_none(&pid_log);
    scm_deletion::wait_until_deleted(SERVICE_NAME).expect("the service is deleted");
}

/// `ensure_stopped` stops without deregistering, and puts the restart back.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_ensure_stopped_leaves_the_service_registered() {
    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let dir = tempfile::tempdir().unwrap();
    let pid_log = dir.path().join("pids.log");
    let _service = ProvisionedService::install_with_args(helper, pid_log_args(&pid_log));
    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    CutoverOs::start_service_wait_running(&mut os).expect("bring the service up");

    hole_bridge::platform::os::ensure_stopped().expect("stop a running service");
    left_behind::assert_none(&pid_log);
    assert!(hole_bridge::platform::os::is_installed(), "stopped, not deregistered");
    assert_eq!(scm_probe::Probe::open().state(), 1, "the service is STOPPED");
}

/// A stop-only retirement turns restart-on-failure off while it stops the
/// service and must leave it as it found it. Writing a restart action back needs
/// `SERVICE_START` on the handle, which a handle without it answers with
/// "access denied" (a warning, so the service silently stops restarting).
/// Read back through `QueryServiceConfig2`, not inferred from the call's result.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_ensure_stopped_leaves_the_failure_actions_as_it_found_them() {
    use hole_bridge::platform::os::SERVICE_NAME;
    use windows_service::service::{ServiceAccess, ServiceActionType};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let dir = tempfile::tempdir().unwrap();
    let pid_log = dir.path().join("pids.log");
    let _service = ProvisionedService::install_with_args(helper, pid_log_args(&pid_log));
    // The failure actions `install` writes, by the production entry point.
    hole_bridge::platform::os::ensure_failure_actions().expect("give the service its restart-on-failure");
    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    CutoverOs::start_service_wait_running(&mut os).expect("bring the service up");

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).unwrap();
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_CONFIG)
        .expect("open the service to read its configuration back");
    let read = || {
        (
            service
                .get_failure_actions()
                .expect("QueryServiceConfig2: the failure actions"),
            service
                .get_failure_actions_on_non_crash_failures()
                .expect("QueryServiceConfig2: the non-crash flag"),
        )
    };
    let before = read();
    let restarts = |actions: &windows_service::service::ServiceFailureActions| {
        actions
            .actions
            .iter()
            .flatten()
            .any(|a| a.action_type == ServiceActionType::Restart)
    };
    assert!(restarts(&before.0), "the fixture restarts on failure: {before:?}");
    assert!(before.1, "the fixture restarts on a non-crash failure: {before:?}");

    hole_bridge::platform::os::ensure_stopped().expect("stop a running service");
    left_behind::assert_none(&pid_log);

    assert_eq!(read(), before, "the retirement put the failure actions back");
}

/// A handle on the registered service, held by the test, that can delete it.
/// While it is open it keeps the entry, so a delete through it leaves the
/// service marked for deletion and still listed.
#[cfg(target_os = "windows")]
fn open_to_delete() -> windows_service::service::Service {
    use hole_bridge::platform::os::SERVICE_NAME;
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .expect("open the SCM to hold the service");
    manager
        .open_service(SERVICE_NAME, ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS)
        .expect("open the registered service to delete it")
}

/// Marks the service for deletion through `holder`, and checks it is marked: a
/// second delete is answered `ERROR_SERVICE_MARKED_FOR_DELETE`, as documented
/// for `DeleteService`.
#[cfg(target_os = "windows")]
fn mark_for_deletion(holder: &windows_service::service::Service) {
    use windows::Win32::Foundation::ERROR_SERVICE_MARKED_FOR_DELETE;

    holder.delete().expect("mark the service for deletion");
    match holder.delete() {
        Err(windows_service::Error::Winapi(io))
            if io.raw_os_error() == Some(ERROR_SERVICE_MARKED_FOR_DELETE.0 as i32) => {}
        other => panic!("a second delete of a marked service is answered marked-for-delete: {other:?}"),
    }
}

/// A service already marked for deletion by someone else, running, when the
/// production retirement opens it: it opens, the start-type call is answered
/// as marked, the Stop goes through the open handle, and the retirement waits
/// out the process and succeeds without a delete of its own or a restore.
///
/// Proves: the retirement succeeds and the process is dead (so the marked
/// service was stopped through its handle), with no change issued after the
/// refusal. Red under: a start-type call answered as marked read as a
/// failure (`ServiceGone::harden_goes_on_marked` false for `MarkedForDeletion`),
/// or marked mode skipping the stop wait.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_uninstall_stops_a_service_marked_before_it_was_opened() {
    use hole_bridge::platform::os::SERVICE_NAME;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let dir = tempfile::tempdir().unwrap();
    let pid_log = dir.path().join("pids.log");
    let _service = ProvisionedService::install_with_args(helper, pid_log_args(&pid_log));
    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    CutoverOs::start_service_wait_running(&mut os).expect("bring the service up");
    let holder = open_to_delete();
    mark_for_deletion(&holder);

    let trace = deregister_recorded(Box::new(|_| {}));
    drop(holder);

    left_behind::assert_none(&pid_log);
    scm_deletion::wait_until_deleted(SERVICE_NAME).expect("the service is deleted");
    trace.assert_a_start_type_call_was_refused_as_marked_and_nothing_changed();
    trace.assert_every_stop_follows_a_running_look();
    assert!(trace.stops() > 0, "the running service needed a Stop: {trace:#?}");
}

/// The mark lands after the hardening and before the Stop: the hook marks the
/// service through a handle the test holds, at the first look. The start-type
/// write succeeded, the Stop goes through the open handle, the delete is
/// answered as marked and counts as done, and nothing is restored.
///
/// Proves: the delete's 1072 is not a failure and the Stop reaches a service
/// that was marked mid-retirement. Red under: `ServiceGone::delete_is_done`
/// false for `MarkedForDeletion` (the delete fails and the restore runs).
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_uninstall_stops_a_service_marked_between_the_hardening_and_the_stop() {
    use hole_bridge::cutover::scm_wait::retire::{FailureActions, StartWrite};
    use hole_bridge::platform::os::SERVICE_NAME;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let dir = tempfile::tempdir().unwrap();
    let pid_log = dir.path().join("pids.log");
    let _service = ProvisionedService::install_with_args(helper, pid_log_args(&pid_log));
    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    CutoverOs::start_service_wait_running(&mut os).expect("bring the service up");

    // The first look comes after the hardening, so the write has already
    // succeeded. The handle closes with the hook, when the session is
    // finished.
    let holder = open_to_delete();
    let mut marked = false;
    let hook: recording::Hook<'_> = Box::new(move |event| {
        if !marked && matches!(event, recording::Event::Observed(_)) {
            marked = true;
            mark_for_deletion(&holder);
        }
    });
    let trace = deregister_recorded(hook);

    left_behind::assert_none(&pid_log);
    scm_deletion::wait_until_deleted(SERVICE_NAME).expect("the service is deleted");
    trace.assert_every_stop_follows_a_running_look();
    assert!(trace.stops() > 0, "the running service needed a Stop: {trace:#?}");
    let events = trace.events();
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, recording::Event::SetStartType(_)))
            .collect::<Vec<_>>(),
        [&recording::Event::SetStartType(StartWrite::Disabled)],
        "one start-type write, the hardening's, and no restore: {trace:#?}"
    );
    assert!(
        !events.contains(&recording::Event::SetFailureActions(FailureActions::Restart)),
        "restart-on-failure was put back on a deleted service: {trace:#?}"
    );
    assert_eq!(
        trace.refusals(),
        [(recording::Call::Delete, true)],
        "the only refusal is the delete, answered as marked: {trace:#?}"
    );
    assert_eq!(
        events.last(),
        Some(&recording::Event::ClearRecord),
        "a delete answered as marked is a delete done, and the record goes after it: {trace:#?}"
    );
    trace.assert_the_record_written_was_cleared();
}

/// A service marked for deletion that has already stopped, its process gone,
/// while a handle held elsewhere keeps the entry. Nothing is left to stop, so
/// no Stop is sent and the retirement succeeds.
///
/// Proves: a marked, stopped service with no process is not a failure. Red
/// under: a start-type call answered as marked read as a failure.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_uninstall_of_a_marked_and_already_stopped_service_succeeds() {
    use hole_bridge::platform::os::SERVICE_NAME;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let dir = tempfile::tempdir().unwrap();
    let pid_log = dir.path().join("pids.log");
    let _service = ProvisionedService::install_with_args(helper, pid_log_args(&pid_log));
    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    CutoverOs::start_service_wait_running(&mut os).expect("bring the service up");
    let service_pids = left_behind::logged(&pid_log);
    assert_eq!(service_pids.len(), 1, "one service process so far: {service_pids:?}");
    let process = scm_probe::watch_process(service_pids[0]);

    scm_probe::Probe::open().stop().expect("the test stops the service");
    wait_until_stopped();
    scm_probe::wait_for_exit(&process);
    let holder = open_to_delete();
    mark_for_deletion(&holder);

    let trace = deregister_recorded(Box::new(|_| {}));
    drop(holder);

    left_behind::assert_none(&pid_log);
    scm_deletion::wait_until_deleted(SERVICE_NAME).expect("the service is deleted");
    assert_eq!(trace.stops(), 0, "a stopped service takes no Stop: {trace:#?}");
    trace.assert_a_start_type_call_was_refused_as_marked_and_nothing_changed();
}

/// A process that outlives an entry the SCM no longer has. The service is
/// stopped by the test, its helper parked after reporting STOPPED, and deleted
/// with no other handle open: the SCM drops the entry while the process lives.
/// The setup waits for the entry to go (no sooner than the SCM drops it): if
/// the SCM kept the marked entry while its process lives, this test would not
/// get past that wait, and the case would be the marked one above.
///
/// The retirement runs on a thread over survivors that report every act on one
/// channel. The test lets the helper exit only on the wait announced for it,
/// with the helper alive, so a retirement that returns first never waited. No
/// timing: the thread's next message is whatever the retirement does next.
///
/// Proves: the entry is absent at open, the retirement scans, waits on the
/// process, scans again, and returns `Ok(false)`, and no process is left. Red
/// under: `wait_out_survivors` returning without waiting.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_uninstall_waits_out_a_process_whose_entry_is_already_gone() {
    use hole_bridge::cutover::scm_wait::retire::{retire_over, Disposition, RetireError};
    use hole_bridge::platform::os::{GoneSession, RetireSession, SERVICE_NAME};
    use recording::SurvivorEvent;

    #[derive(Debug)]
    enum Message {
        Survivor(SurvivorEvent),
        Returned(Result<bool, RetireError>),
    }

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let dir = tempfile::tempdir().unwrap();
    let pid_log = dir.path().join("pids.log");
    let parked = named_event::NamedEvent::create("GoneParked");
    let exit = named_event::NamedEvent::create("GoneExit");
    let mut args = pid_log_args(&pid_log);
    args.extend([
        "--outlive-stopped".into(),
        exit.name().into(),
        "--parked-event".into(),
        parked.name().into(),
    ]);
    let _service = ProvisionedService::install_with_args(helper, args);
    let _exit_on_drop = exit.release_on_drop();
    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    CutoverOs::start_service_wait_running(&mut os).expect("bring the service up");
    let service_pids = left_behind::logged(&pid_log);
    assert_eq!(service_pids.len(), 1, "one service process so far: {service_pids:?}");

    scm_probe::Probe::open().stop().expect("the test stops the service");
    // The helper parks only after reporting STOPPED.
    parked.wait();
    let holder = open_to_delete();
    holder.delete().expect("delete the stopped service");
    drop(holder);
    scm_deletion::wait_until_deleted(SERVICE_NAME).expect("the entry goes while its process lives");
    assert_eq!(
        left_behind::still_running(&pid_log),
        service_pids,
        "the process outlives its entry"
    );

    let (messages, inbox) = std::sync::mpsc::channel();
    let retirement = std::thread::spawn(move || {
        let sink = messages.clone();
        let hook: recording::SurvivorHook<'_> = Box::new(move |event| {
            let _ = sink.send(Message::Survivor(*event));
        });
        let opening = RetireSession::open().expect("open the retire session");
        let result = retire_over(
            opening,
            || recording::RecordingSurvivors::new(GoneSession::default(), hook),
            Disposition::Deregister,
        );
        let _ = messages.send(Message::Returned(result));
    });

    let mut seen = vec![];
    let result = loop {
        match inbox.recv().expect("the retirement ended without returning") {
            Message::Survivor(event) => {
                seen.push(event);
                if event == SurvivorEvent::AwaitExits {
                    assert_eq!(
                        left_behind::still_running(&pid_log),
                        service_pids,
                        "the process waited on is the helper's, and it is alive"
                    );
                    exit.signal();
                }
            }
            Message::Returned(result) => break result,
        }
    };
    retirement.join().expect("the retirement thread");
    assert!(
        matches!(result, Ok(false)),
        "the entry is absent, so nothing was retired: {result:?}"
    );
    assert_eq!(
        seen,
        [
            SurvivorEvent::HoldScanned,
            SurvivorEvent::AnyAlive(true),
            SurvivorEvent::AwaitExits,
            SurvivorEvent::HoldScanned,
            SurvivorEvent::AnyAlive(false),
        ],
        "scan, wait on the process, and scan again until nothing is left"
    );
    left_behind::assert_none(&pid_log);
    hole_bridge::platform::os::ensure_stopped().expect("nothing is left to stop");
}

/// A name the SCM has no entry for, and no process carrying its token: there
/// is nothing to stop, which is success.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_ensure_stopped_on_an_unregistered_name_is_ok() {
    ProvisionedService::require_no_leftover();
    hole_bridge::platform::os::ensure_stopped().expect("an unregistered service is already stopped");
}

/// The helper's `--pid-log <path>` arguments.
#[cfg(target_os = "windows")]
fn pid_log_args(path: &std::path::Path) -> Vec<std::ffi::OsString> {
    vec!["--pid-log".into(), path.as_os_str().to_owned()]
}

/// How many times the smoke test below draws the race. Each round is a fresh
/// draw, none is a retry of another, and every round must pass.
#[cfg(target_os = "windows")]
const RACE_ROUNDS: usize = 5;

/// Smoke test for the race between the SCM's restart timer and the uninstall:
/// restart-on-failure with no delay, the service process killed, the uninstall
/// started at once. Which side wins each round is the SCM's to decide and is
/// not asserted; the two sides the uninstall can land on are each pinned by
/// their own test above. Whichever way it falls, the uninstall must succeed and
/// leave neither a service row nor a service process.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_uninstall_smoke_whichever_side_of_the_scm_restart_wins() {
    use hole_bridge::platform::os::SERVICE_NAME;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let dir = tempfile::tempdir().unwrap();
    for round in 0..RACE_ROUNDS {
        let pid_log = dir.path().join(format!("pids-{round}.log"));
        let _service =
            ProvisionedService::install_with(helper, pid_log_args(&pid_log), Some(std::time::Duration::ZERO));
        let mut os = WindowsCutoverOs {
            images: vec![],
            target_version: "test".into(),
        };
        CutoverOs::start_service_wait_running(&mut os).expect("bring the service up");

        scm_probe::kill_service_process();
        hole_bridge::platform::os::uninstall().unwrap_or_else(|e| panic!("round {round}: the uninstall failed: {e}"));

        left_behind::assert_none(&pid_log);
        scm_deletion::wait_until_deleted(SERVICE_NAME).unwrap_or_else(|e| panic!("round {round}: {e}"));
    }
}

/// macOS: renamex_np-swap the `.app` (a dir) + plain-rename the helper (a file)
/// via the production `execute_swap`, and assert the on-disk identity flipped
/// (RENAME_SWAP exchanged the directory entries). Real `renamex_np` FFI; runs
/// under `sudo` on the TUN lane. The all-or-nothing rollback ordering is unit-
/// proven cfg-free in `platform::swap_tests`; this proves the real primitive.
#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_swap_running_helper_preserves_identity() {
    use hole_bridge::platform::swap::{execute_swap, plan_swap, volume_supports_rename_swap, RenameSwapSupport};

    let dir = tempfile::tempdir().unwrap();
    // RENAME_SWAP is a per-volume capability; the tempdir's volume must advertise
    // it (APFS does). Fail loud if not — the destination volume is wrong.
    assert_eq!(
        volume_supports_rename_swap(dir.path()).unwrap(),
        RenameSwapSupport::Supported,
        "the destination volume must support RENAME_SWAP (APFS)"
    );

    // Staged `.app` (a dir) + old counterpart at the dest; staged helper file +
    // old helper at the dest. Staging + dest share a volume (one tempdir).
    let app_dest = dir.path().join("Hole.app");
    let app_staging = dir.path().join(".Hole.app.staging");
    std::fs::create_dir_all(app_dest.join("Contents/MacOS")).unwrap();
    std::fs::write(app_dest.join("Contents/MacOS/hole"), b"old-app").unwrap();
    std::fs::create_dir_all(app_staging.join("Contents/MacOS")).unwrap();
    std::fs::write(app_staging.join("Contents/MacOS/hole"), b"new-app").unwrap();
    let helper_dest = dir.path().join("com.hole.bridge");
    let helper_staging = dir.path().join("com.hole.bridge.new");
    std::fs::write(&helper_dest, b"old-helper").unwrap();
    std::fs::write(&helper_staging, b"new-helper").unwrap();

    let before_app = same_file::Handle::from_path(app_dest.join("Contents/MacOS/hole")).unwrap();
    let plan = plan_swap(&app_staging, &app_dest, &helper_staging, &helper_dest);
    execute_swap(&plan).expect("real renamex_np + rename swap must succeed on APFS");

    // The dest now holds the NEW bytes (identity flipped); the helper too.
    assert_eq!(std::fs::read(app_dest.join("Contents/MacOS/hole")).unwrap(), b"new-app");
    assert_eq!(std::fs::read(&helper_dest).unwrap(), b"new-helper");
    let after_app = same_file::Handle::from_path(app_dest.join("Contents/MacOS/hole")).unwrap();
    assert_ne!(
        before_app, after_app,
        "the `.app` image identity must FLIP across RENAME_SWAP"
    );
}
