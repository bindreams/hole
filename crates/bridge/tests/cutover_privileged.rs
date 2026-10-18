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
        LocalFree, ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_MARKED_FOR_DELETE, ERROR_SERVICE_NOTIFY_CLIENT_LAGGING,
        HLOCAL,
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
                Ok(service) => drop(ScHandle(service)),
                Err(e) if e.code() == HRESULT::from_win32(ERROR_SERVICE_DOES_NOT_EXIST.0) => return Ok(()),
                // Still listed, with the deletion pending.
                Err(e) if e.code() == HRESULT::from_win32(ERROR_SERVICE_MARKED_FOR_DELETE.0) => {}
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
        use hole_bridge::platform::os::SERVICE_NAME;
        use windows_service::service::{
            ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
            ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceType,
        };
        use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

        // Clear any residue, then create fresh. `teardown` returns only once the
        // service is gone: DeleteService merely marks a service whose process is
        // still running, and `create_service` fails with
        // ERROR_SERVICE_MARKED_FOR_DELETE until the process has exited and every
        // handle has closed.
        Self::teardown();
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

    /// Stops and deletes the throwaway service, returning only once it no longer
    /// exists. Best-effort: failures are reported on stderr, never panicked on,
    /// because this also runs from `Drop`.
    fn teardown() {
        use hole_bridge::cutover::os::windows::WindowsCutoverOs;
        use hole_bridge::cutover::os::CutoverOs;
        use hole_bridge::platform::os::SERVICE_NAME;
        use windows::Win32::Foundation::{ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_MARKED_FOR_DELETE};
        use windows_service::service::ServiceAccess;
        use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

        let open_error_is = |e: &windows_service::Error, code: windows::Win32::Foundation::WIN32_ERROR| matches!(e, windows_service::Error::Winapi(io) if io.raw_os_error() == Some(code.0 as i32));
        let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) else {
            return;
        };
        match manager.open_service(SERVICE_NAME, ServiceAccess::DELETE) {
            Ok(service) => {
                // A STOPPED notification, not a Stop request alone: deletion
                // cannot complete while the service process is alive.
                let mut os = WindowsCutoverOs {
                    images: vec![],
                    target_version: "test".into(),
                };
                if let Err(e) = os.stop_service_wait_stopped() {
                    eprintln!("teardown: stopping the throwaway service failed: {e}");
                }
                // Any refusal leaves the wait below hanging, so say which it was.
                if let Err(e) = service.delete() {
                    eprintln!("teardown: deleting the throwaway service failed (awaiting deletion anyway): {e}");
                }
                // An open handle keeps the deletion pending.
                drop(service);
            }
            // Not present: nothing to clean.
            Err(e) if open_error_is(&e, ERROR_SERVICE_DOES_NOT_EXIST) => return,
            // Deleted but not yet gone, should the open itself report it: only
            // the wait below applies.
            Err(e) if open_error_is(&e, ERROR_SERVICE_MARKED_FOR_DELETE) => {}
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
    /// Per `reopen`: `Some(error)` makes the handles fail to open.
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

/// `ERROR_SERVICE_NOTIFY_CLIENT_LAGGING` reopens the handles and arms again on
/// the fresh ones. The lagging call's record is leaked, not freed.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_a_lagging_client_reopens_and_arms_again() {
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
        .expect("the retry arms on the reopened handles");
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

/// A failed reopen leaves the actor without handles: every later use errs, and
/// the lagging call's record, whose callback never ran, is not freed on drop.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_a_failed_reopen_leaves_every_use_erring() {
    use hole_bridge::cutover::scm_wait::{ScmActor, SystemScmActor, WantState};
    use hole_bridge::platform::os::SERVICE_NAME;
    use windows::Win32::Foundation::ERROR_SERVICE_NOTIFY_CLIENT_LAGGING;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let _service = ProvisionedService::install(helper);

    let (mut script, _records) = Script::new();
    script
        .notify
        .push_back(std::num::NonZeroU32::new(ERROR_SERVICE_NOTIFY_CLIENT_LAGGING.0));
    script
        .open
        .push_back(Some(std::io::Error::other("injected open failure")));
    script.watch_call = Some(0);
    let mut actor = SystemScmActor::open_with(SERVICE_NAME, script).expect("open the throwaway service");

    let err = actor.arm(WantState::Running, None).expect_err("the reopen fails");
    assert!(
        err.to_string().contains("injected open failure"),
        "unexpected error: {err}"
    );
    actor.arm(WantState::Running, None).expect_err("no handles to arm on");
    actor.control_stop().expect_err("no handles to stop through");
    actor.start().expect_err("no handles to start through");
    actor.wait_callback().expect_err("the last arm failed");
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

    /// The logged ids whose process is still running.
    pub fn still_running(pid_log: &Path) -> Vec<u32> {
        std::fs::read_to_string(pid_log)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.trim().parse::<u32>().ok())
            .filter(|pid| is_running_helper(*pid))
            .collect()
    }

    /// Fails unless every process the helper logged has exited.
    pub fn assert_none(pid_log: &Path) {
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

    /// Kills the service's process the way Task Manager would, so the SCM sees
    /// a failure and applies the service's failure actions.
    pub fn kill_service_process() {
        use windows_service::service::ServiceAccess;
        use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).unwrap();
        let service = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS).unwrap();
        let pid = service
            .query_status()
            .unwrap()
            .process_id
            .expect("a running service has a process");
        // SAFETY: plain FFI calls on a handle this function opens and closes.
        unsafe {
            let process: HANDLE = OpenProcess(PROCESS_TERMINATE, false, pid).expect("open the service process");
            let killed = TerminateProcess(process, 1);
            let _ = CloseHandle(process);
            killed.expect("kill the service process");
        }
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
/// state reports there. These are the facts `stop_via_notify`'s policy rests on,
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
    /// report. `before_wait` runs between the Stop and the wait.
    fn arm_stop_wait(probe: &Probe, before_wait: impl FnOnce()) -> Reading {
        let mut actor = SystemScmActor::open(SERVICE_NAME).expect("open the service to arm on");
        let state_before = probe.state();
        actor.arm(WantState::Stopped, None).expect("arm for every state");
        let stop = probe.stop();
        before_wait();
        let first_report = actor.wait_callback().expect("the armed notification fires");
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

/// The drain after the delete rests on a handle opened before it still
/// working on a service marked for deletion. Measured here, one line per call,
/// each on that handle: a state query, an arm and its first report, a Stop, and
/// `stop_via_notify` to completion.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_stop_probe_handle_of_a_service_marked_for_delete() {
    use hole_bridge::cutover::scm_wait::retire::ServiceSession;
    use hole_bridge::cutover::scm_wait::{stop_via_notify, ScmActor, WantState};
    use hole_bridge::platform::os::RetireSession;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let _service = ProvisionedService::install(helper);
    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    CutoverOs::start_service_wait_running(&mut os).expect("bring the service up");

    let mut session = RetireSession::open()
        .expect("open the session")
        .expect("the service is registered");
    session.delete().expect("mark the running service for deletion");
    let observed = session.observe();
    let armed = session.arm(WantState::Stopped, None);
    let first_report = armed.is_ok().then(|| session.wait_callback());
    let stop = session.control_stop();
    let finished = stop_via_notify(&mut session);
    eprintln!(
        "SCM stop probe, handle opened before DeleteService on a RUNNING service:\n  \
         QueryServiceStatusEx -> {observed:?}\n  \
         NotifyServiceStatusChange arm -> {armed:?}; first report -> {first_report:?}\n  \
         ControlService(STOP) -> {stop:?}\n  \
         stop_via_notify -> {finished:?}\n  \
         MEANS: the drain (retire.rs `drain`) depends on the query and the Stop only. \
         If the query is Ok the drain's looks work; if it is Err every drain look fails as \
         RetireError::Drain and a service the SCM restarted between the stop and the delete \
         cannot be uninstalled (the drain needs another way to read the service). \
         If the Stop is Ok the drain's Stop for a live marked service is delivered; if it is Err \
         the drain fails with the Stop's code (RUNNING) and needs TerminateProcess or another route. \
         The arm and stop_via_notify lines say only whether the START_PENDING drain state \
         (`DrainStep::AwaitRunning`, the one that arms) can work: an arm Err there is a loud \
         RetireError::Drain, and the deputy's Q1 (TerminateProcess fallback) applies."
    );
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

/// The drain ends on a look taken before the last handle closes, so a start
/// after it is covered only if the SCM refuses to start a service marked for
/// deletion. This calls `StartService`, on the handle opened before the delete,
/// on a STOPPED service with a restart pending and prints the answer. The
/// restart is the SCM starting the service itself; `StartService` is the same
/// start asked for by a client, so the answer says whether a marked service can
/// be started at all. The restart delay is far off and never waited out.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_stop_probe_start_of_a_stopped_service_marked_for_delete() {
    use hole_bridge::cutover::scm_wait::call_error::{ScmCall, ScmCallError, ERROR_SERVICE_MARKED_FOR_DELETE};
    use hole_bridge::cutover::scm_wait::retire::{drain, ServiceSession};
    use hole_bridge::cutover::scm_wait::ScmActor;
    use hole_bridge::platform::os::SERVICE_NAME;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let _service = ProvisionedService::install_with(helper, vec![], Some(std::time::Duration::from_secs(60 * 60)));
    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    CutoverOs::start_service_wait_running(&mut os).expect("bring the service up");

    // The handle that outlives the delete, then the kill that leaves the
    // service STOPPED with its restart pending.
    let mut session = hole_bridge::platform::os::RetireSession::open()
        .expect("open the session")
        .expect("the service is registered");
    scm_probe::kill_service_process();
    wait_until_stopped();
    let before_delete = session.observe();
    session.delete().expect("mark the killed service for deletion");
    let started = session.start();
    let refused_as_marked = started.as_ref().err().is_some_and(|e| {
        e.get_ref()
            .and_then(|inner| inner.downcast_ref::<ScmCallError>())
            .is_some_and(|e| e.call == ScmCall::StartService && e.code == ERROR_SERVICE_MARKED_FOR_DELETE)
    });
    let meaning = match (&started, refused_as_marked) {
        (Err(_), true) => {
            "the SCM refuses to start a marked service: a start after the drain's last look cannot happen, \
             and the drain's restart coverage holds"
        }
        (Err(_), false) => {
            "StartService failed for another reason: this run does not say whether a marked service can be \
             started (check that the look before the delete was STOPPED)"
        }
        (Ok(()), _) => {
            "the SCM STARTS a marked service: a start after the drain's last look is possible, and the \
             drain's restart coverage does not hold (the owner decides what covers that window)"
        }
    };
    eprintln!(
        "SCM start probe, StartService on a handle opened before DeleteService of a STOPPED service with a restart pending: \
         look before the delete -> {before_delete:?}; StartService -> {started:?}\n  MEANS: {meaning}"
    );

    // Success left a live service; the drain stops it and awaits its process.
    let drained = drain(&mut session);
    eprintln!("SCM start probe: drain -> {drained:?}");
    drop(session);
    let _ = scm_deletion::wait_until_deleted(SERVICE_NAME);
}

/// A `ServiceSession` over the real one that releases a parked helper the
/// moment the first arm returns, and records what each wait reported. The arm
/// has by then asked the SCM for the current state, so the first report is the
/// parked state; the release then lets the helper move on, and the code under
/// test finds out what it did from the SCM, not from this wrapper.
#[cfg(target_os = "windows")]
struct ReleasingSession<'a> {
    inner: hole_bridge::platform::os::RetireSession,
    release: &'a named_event::NamedEvent,
    released: bool,
    reports: Vec<hole_bridge::cutover::scm_wait::Observed>,
}

#[cfg(target_os = "windows")]
impl<'a> ReleasingSession<'a> {
    fn open(release: &'a named_event::NamedEvent) -> Self {
        let inner = hole_bridge::platform::os::RetireSession::open()
            .expect("open the retire session")
            .expect("the service is registered");
        Self {
            inner,
            release,
            released: false,
            reports: vec![],
        }
    }
}

#[cfg(target_os = "windows")]
impl hole_bridge::cutover::scm_wait::ScmActor for ReleasingSession<'_> {
    fn arm(
        &mut self,
        want: hole_bridge::cutover::scm_wait::WantState,
        except: Option<hole_bridge::cutover::scm_wait::Observed>,
    ) -> std::io::Result<()> {
        self.inner.arm(want, except)?;
        if !self.released {
            self.released = true;
            self.release.signal();
        }
        Ok(())
    }
    fn control_stop(&mut self) -> std::io::Result<()> {
        self.inner.control_stop()
    }
    fn start(&mut self) -> std::io::Result<()> {
        self.inner.start()
    }
    fn wait_callback(&mut self) -> std::io::Result<hole_bridge::cutover::scm_wait::Observed> {
        let observed = self.inner.wait_callback()?;
        self.reports.push(observed);
        Ok(observed)
    }
    fn process_fate(&mut self) -> std::io::Result<hole_bridge::cutover::scm_wait::hold::ProcessFate> {
        self.inner.process_fate()
    }
}

#[cfg(target_os = "windows")]
impl hole_bridge::cutover::scm_wait::retire::ServiceSession for ReleasingSession<'_> {
    fn disable_restart(&mut self) -> std::io::Result<()> {
        self.inner.disable_restart()
    }
    fn restore_restart(&mut self) -> std::io::Result<()> {
        self.inner.restore_restart()
    }
    fn delete(&mut self) -> std::io::Result<()> {
        self.inner.delete()
    }
    fn observe(&mut self) -> std::io::Result<hole_bridge::cutover::scm_wait::hold::Look> {
        self.inner.observe()
    }
    fn hold_process(&mut self) -> std::io::Result<hole_bridge::cutover::scm_wait::hold::ProcessFate> {
        self.inner.hold_process()
    }
    fn await_exits(&mut self) -> std::io::Result<()> {
        self.inner.await_exits()
    }
}

/// Retires a service parked in START_PENDING by `flag`, through the production
/// `retire`, and checks it ends up deregistered. The first report must be the
/// parked START_PENDING (the case a blind Stop used to be sent into), and the
/// Stop must have come only after a later RUNNING.
#[cfg(target_os = "windows")]
fn retire_a_parked_service(flag: &str) {
    use hole_bridge::cutover::scm_wait::retire::{retire, Disposition};
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

    let mut session = ReleasingSession::open(&release);
    retire(&mut session, Disposition::Deregister).expect("the retirement succeeds");

    starter.join().unwrap().expect("the held service starts once released");
    scm_deletion::wait_until_deleted(SERVICE_NAME).expect("the service is deleted");
    assert_eq!(
        session.reports.first(),
        Some(&Observed::StartPending),
        "the first report is the parked state: {:?}",
        session.reports
    );
    assert!(
        session.reports.contains(&Observed::Running),
        "the held service ran before it was stopped: {:?}",
        session.reports
    );
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

/// The #1099 shape: the SCM restarts a killed service (the restart delay is
/// configuration; the test blocks on the helper's parked event) and the
/// retirement lands on the restarted, START_PENDING instance.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_uninstall_lands_on_the_instance_the_scm_just_restarted() {
    use hole_bridge::cutover::scm_wait::retire::{retire, Disposition};
    use hole_bridge::cutover::scm_wait::Observed;
    use hole_bridge::platform::os::SERVICE_NAME;

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let parked = named_event::NamedEvent::create("RestartParked");
    let release = named_event::NamedEvent::create("RestartRelease");
    let _service = ProvisionedService::install_with(
        helper,
        vec![
            "--hold-start".into(),
            release.name().into(),
            "--parked-event".into(),
            parked.name().into(),
        ],
        Some(std::time::Duration::from_secs(1)),
    );
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

    let mut session = ReleasingSession::open(&release);
    retire(&mut session, Disposition::Deregister).expect("the retirement succeeds");
    scm_deletion::wait_until_deleted(SERVICE_NAME).expect("the service is deleted");
    assert_eq!(
        session.reports.first(),
        Some(&Observed::StartPending),
        "the first report is the restarted instance's START_PENDING: {:?}",
        session.reports
    );
}

/// A killed service reads STOPPED while its restart is pending. The production
/// `uninstall` returns once it is deregistered.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_uninstall_deregisters_a_killed_service_with_a_restart_pending() {
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

    hole_bridge::platform::os::uninstall().expect("uninstall a stopped service with a restart pending");
    left_behind::assert_none(&pid_log);
    scm_deletion::wait_until_deleted(SERVICE_NAME).expect("the service is deleted");
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

/// The helper's `--pid-log <path>` arguments.
#[cfg(target_os = "windows")]
fn pid_log_args(path: &std::path::Path) -> Vec<std::ffi::OsString> {
    vec!["--pid-log".into(), path.as_os_str().to_owned()]
}

/// How many times the race below is run. The race is the SCM's restart timer
/// against the uninstall; each round is a fresh draw, none is a retry of
/// another, and every round must pass.
#[cfg(target_os = "windows")]
const RACE_ROUNDS: usize = 5;

/// The #1099 race itself: restart-on-failure with no delay, the service
/// process killed, the uninstall started at once. Whichever side wins each
/// round (the uninstall lands before the restart, between the stop and the
/// delete, or after the delete), it must succeed and leave neither a service
/// row nor a service process.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_uninstall_leaves_nothing_whichever_side_of_the_scm_restart_wins() {
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

/// The drain on a service already marked for deletion while RUNNING: the state
/// the restart slip produces, made directly. The Stop and the wait for the
/// process use no notification, so this passes whether or not an arm works on a
/// marked service (the probe below prints that), and returns with the process gone.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_drain_stops_and_awaits_a_running_service_marked_for_delete() {
    use hole_bridge::cutover::scm_wait::retire::{drain, ServiceSession};
    use hole_bridge::platform::os::{RetireSession, SERVICE_NAME};

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let dir = tempfile::tempdir().unwrap();
    let pid_log = dir.path().join("pids.log");
    let _service = ProvisionedService::install_with_args(helper, pid_log_args(&pid_log));
    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    CutoverOs::start_service_wait_running(&mut os).expect("bring the service up");

    let mut session = RetireSession::open()
        .expect("open the session")
        .expect("the service is registered");
    session.hold_process().expect("hold the running service's process");
    session.delete().expect("mark the running service for deletion");
    drain(&mut session).expect("drain the marked service");
    left_behind::assert_none(&pid_log);
    drop(session);
    scm_deletion::wait_until_deleted(SERVICE_NAME).expect("the service is deleted");
}

/// What the drain does with a service marked for deletion while START_PENDING,
/// where a Stop is refused and the process will not exit by itself: the one state
/// that goes through an arm. Prints the outcome (it is the measurement of what
/// an arm does on a marked service in that state); it asserts nothing about it.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_stop_probe_drain_of_a_start_pending_service_marked_for_delete() {
    use hole_bridge::cutover::scm_wait::retire::{drain, ServiceSession};

    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let parked = named_event::NamedEvent::create("MarkedParked");
    let release = named_event::NamedEvent::create("MarkedRelease");
    let _service = ProvisionedService::install_with(
        helper,
        vec![
            "--hold-start".into(),
            release.name().into(),
            "--parked-event".into(),
            parked.name().into(),
        ],
        None,
    );
    let _release_on_drop = release.release_on_drop();
    let starter = start_in_background();
    parked.wait();

    let mut session = ReleasingSession::open(&release);
    session.hold_process().expect("hold the starting service's process");
    session.delete().expect("mark the starting service for deletion");
    let drained = drain(&mut session);
    eprintln!(
        "SCM stop probe, drain of a service marked for deletion while START_PENDING: {drained:?}; reports {:?}",
        session.reports
    );
    let _ = starter.join();
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
