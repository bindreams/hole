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
        use hole_bridge::platform::os::SERVICE_NAME;
        use windows_service::service::{
            ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType,
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
        manager
            .create_service(
                &info,
                ServiceAccess::START | ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE,
            )
            .expect("create the throwaway HoleBridge service");
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
    actor.arm(WantState::Running).expect("arm against the stopped service");
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
    actor.arm(WantState::Stopped).expect("arm against the running service");
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
        .arm(WantState::Running)
        .expect("first arm against the stopped service");
    actor
        .arm(WantState::Running)
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
    actor.arm(WantState::Running).expect_err("the injected failure");
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
        .arm(WantState::Running)
        .expect("first arm against the stopped service");
    actor.arm(WantState::Running).expect_err("the injected failure");
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
        .arm(WantState::Stopped)
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

    let err = actor.arm(WantState::Running).expect_err("the reopen fails");
    assert!(
        err.to_string().contains("injected open failure"),
        "unexpected error: {err}"
    );
    actor.arm(WantState::Running).expect_err("no handles to arm on");
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
    // notification at once, so re-arm until STOPPED: each pass re-checks the
    // real state.
    let mut actor = SystemScmActor::open(SERVICE_NAME).expect("open the service for the STOPPED notification");
    loop {
        actor.arm(WantState::Stopped).unwrap();
        if actor.wait_callback().unwrap() == Observed::Stopped {
            break;
        }
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
