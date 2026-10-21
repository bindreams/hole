//! Proofs of the machine-wide lock over the service's start type and record
//! (`hole_bridge::platform::os::StartTypeLock`), on the real object and, where
//! a test needs one, a real service:
//!
//! - a token without Administrators can neither make the lock's namespace,
//!   make or open the mutex in it, nor wait on the lock, whether the lock is
//!   held or free;
//! - a retirement, and the update cutover's hold, are holders for every other
//!   thread, and the GUI's status read says a change is in progress meanwhile;
//! - an install's hold over the start type stays in force through every step it
//!   runs on its thread, and none of them waits on it.

use std::path::Path;

use hole_bridge::cutover::os::windows::WindowsCutoverOs;
use hole_bridge::cutover::os::CutoverOs;
use hole_bridge::disable_record::{DisabledState, RecordState};
use hole_bridge::platform::os::{self, Opening, RetireSession, StartTypeLock, BOUNDARY_NAME, MUTEX_LEAF, REQUIRED_SID};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, ERROR_ACCESS_DENIED, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::{
    CreateRestrictedToken, DuplicateTokenEx, SecurityImpersonation, TokenImpersonation, DISABLE_MAX_PRIVILEGE, PSID,
    SID_AND_ATTRIBUTES, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{
    AddSIDToBoundaryDescriptor, CreateBoundaryDescriptorW, CreateMutexExW, CreatePrivateNamespaceW,
    DeleteBoundaryDescriptor, GetCurrentProcess, OpenPrivateNamespaceW, OpenProcessToken, SetThreadToken,
};
use windows_service::service::{ServiceAccess, ServiceActionType, ServiceStartType};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::record_proofs::set_start_type;
use super::{scm_deletion, ProvisionedService, GLOBAL_NET_STATE, TUN};

fn helper() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_test_service"))
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Runs `f` on a new thread whose token is the current one with Administrators
/// disabled and every privilege dropped: what the GUI's unprivileged token has
/// of the lock's DACL's concern.
pub(super) fn as_a_standard_user<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|s| {
        s.spawn(|| {
            let mut process_token = HANDLE::default();
            // SAFETY: plain FFI; the out-handle is a local.
            unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_DUPLICATE | TOKEN_QUERY | windows::Win32::Security::TOKEN_ASSIGN_PRIMARY,
                    &mut process_token,
                )
            }
            .expect("open the process token");
            let sid_text = wide("S-1-5-32-544");
            let mut administrators = PSID::default();
            // SAFETY: NUL-terminated input; the SID is freed below.
            unsafe { ConvertStringSidToSidW(PCWSTR(sid_text.as_ptr()), &mut administrators) }.expect("parse the SID");
            let disable = [SID_AND_ATTRIBUTES {
                Sid: administrators,
                Attributes: 0,
            }];
            let mut restricted = HANDLE::default();
            // SAFETY: the token and the SID are live; the out-handle is a local.
            unsafe {
                CreateRestrictedToken(
                    process_token,
                    DISABLE_MAX_PRIVILEGE,
                    Some(&disable),
                    None,
                    None,
                    &mut restricted,
                )
            }
            .expect("make the token without Administrators");
            let mut impersonation = HANDLE::default();
            // SAFETY: as above.
            unsafe {
                DuplicateTokenEx(
                    restricted,
                    TOKEN_IMPERSONATE | TOKEN_QUERY,
                    None,
                    SecurityImpersonation,
                    TokenImpersonation,
                    &mut impersonation,
                )
            }
            .expect("make an impersonation token");
            // SAFETY: the token is live; this thread is the one impersonating.
            unsafe { SetThreadToken(None, Some(impersonation)) }.expect("impersonate it");
            let result = f();
            // SAFETY: reverts this thread; all handles and the SID are ours.
            unsafe {
                let _ = SetThreadToken(None, None);
                let _ = CloseHandle(impersonation);
                let _ = CloseHandle(restricted);
                let _ = CloseHandle(process_token);
                let _ = LocalFree(Some(HLOCAL(administrators.0)));
            }
            result
        })
        .join()
        .expect("the standard-user thread")
    })
}

/// The Win32 error of making (`make`) or opening the lock's private namespace
/// under `alias`, with the production boundary, as the calling thread's token.
/// `None`: it was made or opened.
fn namespace_refusal(alias: &str, make: bool) -> Option<u32> {
    let boundary_name = wide(BOUNDARY_NAME);
    let sid_text = wide(REQUIRED_SID);
    let alias = wide(alias);
    // SAFETY: NUL-terminated inputs outliving the calls; the SID and the
    // boundary descriptor are released below.
    unsafe {
        let mut sid = PSID::default();
        ConvertStringSidToSidW(PCWSTR(sid_text.as_ptr()), &mut sid).expect("parse the SID");
        let mut boundary = CreateBoundaryDescriptorW(PCWSTR(boundary_name.as_ptr()), 0);
        AddSIDToBoundaryDescriptor(&mut boundary, sid).expect("name the SID in the boundary");
        let namespace = if make {
            CreatePrivateNamespaceW(None, boundary.0, PCWSTR(alias.as_ptr()))
        } else {
            OpenPrivateNamespaceW(boundary.0, PCWSTR(alias.as_ptr()))
        };
        let refusal = (namespace.is_invalid() || namespace.0.is_null()).then(|| GetLastError().0);
        DeleteBoundaryDescriptor(boundary);
        let _ = LocalFree(Some(HLOCAL(sid.0)));
        refusal
    }
}

/// What a caller meets on the way to the lock's mutex by name: opening the
/// namespace under `alias`, then making (or opening, if it exists) the mutex
/// there. Microsoft: "a process can open an existing namespace even if it is
/// not within the boundary unless the creator restricted access", and the
/// open is measured to succeed for a token the namespace's DACL leaves out, so
/// what keeps a caller out is the second step.
#[derive(Debug)]
struct Reach {
    /// The Win32 error of the namespace open; `None`: it opened.
    opened: Option<u32>,
    /// The Win32 error of making or opening the mutex; `None`: the caller has
    /// a handle to it.
    mutex: Option<u32>,
}

impl Reach {
    fn of(alias: &str) -> Self {
        let opened = namespace_refusal(alias, false);
        let name = wide(&format!(r"{alias}\{MUTEX_LEAF}"));
        // SAFETY: `name` is NUL-terminated and outlives the call; the handle, if
        // any, is closed at once.
        let mutex = match unsafe { CreateMutexExW(None, PCWSTR(name.as_ptr()), 0, SYNCHRONIZE) } {
            Ok(handle) => {
                // SAFETY: just made, and closed only here.
                let _ = unsafe { CloseHandle(handle) };
                None
            }
            // The Win32 half of the HRESULT the call reports.
            Err(error) => Some(error.code().0 as u32 & 0xFFFF),
        };
        Self { opened, mutex }
    }

    /// Whether the caller was kept from the mutex, at the open or at the mutex.
    fn refused(&self) -> bool {
        let denied = Some(ERROR_ACCESS_DENIED.0);
        self.opened == denied || self.mutex == denied
    }
}

/// `SYNCHRONIZE`: all a wait needs.
const SYNCHRONIZE: u32 = 0x0010_0000;

/// Proves: a token without Administrators (what the GUI runs as) can neither
/// make the lock's namespace before any Hole process does, nor make or open the
/// mutex in it (the squat of the name), nor take or wait on the lock, whether an
/// administrator holds it or it is free, and an administrator's token reaches
/// the same mutex both ways. Red under: a boundary without the Administrators
/// SID, a DACL on the namespace or the mutex that admits another group, or a
/// right to wait given to anyone but SYSTEM and Administrators.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_a_token_without_administrators_can_neither_make_open_nor_wait_on_the_start_type_lock() {
    let held = StartTypeLock::machine_wide()
        .acquire()
        .expect("an administrator takes the lock");
    let control_held = Reach::of("hole-proof-control-held");
    let user_held = as_a_standard_user(|| {
        (
            StartTypeLock::machine_wide()
                .try_acquire()
                .err()
                .and_then(|e| e.raw_os_error()),
            namespace_refusal("hole-proof-squat", true),
            Reach::of("hole-proof-user-held"),
        )
    });
    drop(held);
    let control_free = Reach::of("hole-proof-control-free");
    let user_free = as_a_standard_user(|| {
        (
            StartTypeLock::machine_wide()
                .acquire()
                .err()
                .and_then(|e| e.raw_os_error()),
            namespace_refusal("hole-proof-squat-free", true),
            Reach::of("hole-proof-user-free"),
        )
    });
    let denied = Some(ERROR_ACCESS_DENIED.0);
    assert!(
        control_held.opened.is_none() && control_held.mutex.is_none(),
        "control: an administrator opens the namespace and the held mutex: {control_held:?}"
    );
    assert!(
        control_free.opened.is_none() && control_free.mutex.is_none(),
        "control: an administrator opens the namespace and makes the free mutex: {control_free:?}"
    );
    assert_eq!(
        user_held.0.map(|e| e as u32),
        denied,
        "a standard user's try on a held lock"
    );
    assert_eq!(user_held.1, denied, "a standard user's make of the namespace");
    assert!(
        user_held.2.refused(),
        "a standard user reaching the held lock's mutex by name: {:?}",
        user_held.2
    );
    assert_eq!(
        user_free.0.map(|e| e as u32),
        denied,
        "a standard user's take of a free lock"
    );
    assert_eq!(
        user_free.1, denied,
        "a standard user's make of the namespace, lock free"
    );
    assert!(
        user_free.2.refused(),
        "a standard user making the free lock's mutex by name (the squat): {:?}",
        user_free.2
    );
    assert!(
        StartTypeLock::machine_wide().try_acquire().expect("try").is_some(),
        "the lock is free and an administrator takes it"
    );
}

/// Whether another thread finds the lock held.
fn held_for_another_thread() -> bool {
    std::thread::scope(|s| {
        s.spawn(|| StartTypeLock::machine_wide().try_acquire().expect("try").is_none())
            .join()
            .expect("the probe's thread")
    })
}

fn gui_status_from_another_thread() -> DisabledState {
    std::thread::scope(|s| s.spawn(os::disabled_state).join().expect("the GUI read's thread"))
}

/// Proves: an open retirement session is a holder of the lock for every other
/// thread, the GUI's status read says a change is in progress while it is, and
/// the lock is free and the record decides once it is dropped. Red under: a
/// session that does not take the lock before its first read.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_a_retirement_holds_the_start_type_lock_until_it_ends() {
    let _service = ProvisionedService::install(helper());
    assert!(!held_for_another_thread(), "nothing holds it yet");

    let Opening::Opened(session) = RetireSession::open().expect("open the retirement") else {
        panic!("the provisioned service is registered");
    };
    assert!(held_for_another_thread(), "the retirement holds it");
    assert_eq!(
        gui_status_from_another_thread(),
        DisabledState::InChange,
        "the GUI's read does not wait for the lock, and the holder's change mark says a change is in progress though nothing is stamped yet"
    );

    drop(session);
    assert!(!held_for_another_thread(), "released with the session");
    assert_eq!(gui_status_from_another_thread(), DisabledState::NotDisabled);
}

/// The failure actions of the provisioned service, as the SCM holds them: whether
/// any is a restart.
fn restarts_on_failure() -> bool {
    let service = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .expect("open the SCM")
        .open_service(os::SERVICE_NAME, ServiceAccess::QUERY_CONFIG)
        .expect("open the service");
    service
        .get_failure_actions()
        .expect("QueryServiceConfig2: the failure actions")
        .actions
        .iter()
        .flatten()
        .any(|action| action.action_type == ServiceActionType::Restart)
}

fn start_type() -> ServiceStartType {
    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .expect("open the SCM")
        .open_service(os::SERVICE_NAME, ServiceAccess::QUERY_CONFIG)
        .expect("open the service")
        .query_config()
        .expect("query the configuration")
        .start_type
}

/// Proves: the update cutover's hold takes the lock, then hardens the service
/// the way a retirement does (the record, a Disabled start type, restart on
/// failure off), and its restore puts all three back before the lock is let go.
/// Red under: a hold that skips the hardening, or restores nothing.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_the_cutover_hold_hardens_the_service_and_restores_it() {
    let _service = ProvisionedService::install(helper());
    os::ensure_failure_actions().expect("give the service its restart-on-failure");
    assert!(restarts_on_failure(), "the fixture restarts on failure");
    // The fixture is registered OnDemand; the restore puts back the start type
    // it found, so the service starts out as an installed one is.
    set_start_type(ServiceStartType::AutoStart);
    assert_eq!(
        start_type(),
        ServiceStartType::AutoStart,
        "precondition: the start type the hold will find"
    );

    let mut os_actor = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    let mut hold = os_actor.hold_service().expect("hold the service");
    assert!(held_for_another_thread(), "the hold has the lock");
    assert_eq!(
        gui_status_from_another_thread(),
        DisabledState::InChange,
        "the record names the holding process, which is running"
    );
    assert_eq!(start_type(), ServiceStartType::Disabled, "the stop is final");
    assert!(!restarts_on_failure(), "nothing restarts the old image under the swap");
    assert_eq!(
        hole_bridge::disable_record::RecordKey::service().state(),
        RecordState::Present,
        "a kill here leaves the record that says whose disable this is"
    );

    hold.restore();
    assert_eq!(
        start_type(),
        ServiceStartType::AutoStart,
        "the restore puts back the start type the hold found"
    );
    assert!(restarts_on_failure(), "the restore puts restart-on-failure back");
    assert_eq!(
        hole_bridge::disable_record::RecordKey::service().state(),
        RecordState::Absent
    );
    assert!(held_for_another_thread(), "still held until the cutover is done");
    assert_eq!(
        gui_status_from_another_thread(),
        DisabledState::InChange,
        "the record is gone but the hold's change mark still names the running holder"
    );

    drop(hold);
    assert!(!held_for_another_thread(), "released with the hold");
    assert_eq!(
        gui_status_from_another_thread(),
        DisabledState::NotDisabled,
        "the change mark says the change ended"
    );
}

/// Proves: the steps an install runs between its first read and its last
/// write (the elevated `disabled_by`, the retirement, the repair, the
/// failure-actions refresh) take a lock their own thread already holds without
/// waiting on it, and the lock stays held for every other thread through all
/// of them and until the hold is dropped. Red under: a step that waits on the
/// lock (this test would hang), or one that releases it for good.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_an_install_holds_the_start_type_lock_through_every_step() {
    let _service = ProvisionedService::install(helper());
    let hold = os::hold_start_type().expect("hold the start type");
    assert!(held_for_another_thread(), "the hold has the lock");
    assert_eq!(gui_status_from_another_thread(), DisabledState::InChange);

    os::disabled_by().expect("the elevated read under the hold");
    assert!(held_for_another_thread(), "held after the read");
    os::ensure_stopped().expect("the retirement under the hold");
    assert!(held_for_another_thread(), "held after the retirement");
    os::repair_interrupted_change().expect("the repair under the hold");
    assert!(held_for_another_thread(), "held after the repair");
    os::ensure_failure_actions().expect("the failure-actions refresh under the hold");
    assert!(held_for_another_thread(), "held after the refresh");
    assert_eq!(
        gui_status_from_another_thread(),
        DisabledState::InChange,
        "still one change, however many steps it takes"
    );

    drop(hold);
    assert!(!held_for_another_thread(), "released with the hold");
}

/// Proves: a reinstall under a hold (deregister, then register a new service
/// whose key has no mark) reads as a change in progress once the new service
/// exists, not as an installed service with nothing the matter, until the hold
/// ends. Red under: an install that does not mark the key it just made.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_a_reinstall_marks_the_key_it_makes_as_a_change_in_progress() {
    use hole_bridge::platform::os::SERVICE_NAME;

    ProvisionedService::require_no_leftover();
    let _service = ProvisionedService;
    os::install(helper()).expect("install the service");
    let hold = os::hold_start_type().expect("hold the start type");

    os::uninstall().expect("deregister under the hold");
    scm_deletion::wait_until_deleted(SERVICE_NAME).expect("the old service is deleted, and its key with it");
    os::install(helper()).expect("register the new service under the hold");
    assert_eq!(
        gui_status_from_another_thread(),
        DisabledState::InChange,
        "the new key is marked: a read before the change ends sees a change, not an installed service"
    );

    drop(hold);
    assert_eq!(
        gui_status_from_another_thread(),
        DisabledState::NotDisabled,
        "the change ended with the hold"
    );
}
