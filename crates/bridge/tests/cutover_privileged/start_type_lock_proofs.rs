//! Proofs of the machine-wide lock over the service's start type and record
//! (`hole_bridge::platform::os::StartTypeLock`), on the real object and, where
//! a test needs one, a real service:
//!
//! - the lock's DACL grants SYSTEM and Administrators everything and a standard
//!   user's groups the wait and nothing else;
//! - a token without Administrators can wait on the lock, and cannot open it
//!   for more;
//! - a retirement, and the update cutover's hold, are holders for every other
//!   thread, and the GUI's status read says a change is in progress meanwhile.

use std::path::Path;

use hole_bridge::cutover::os::windows::WindowsCutoverOs;
use hole_bridge::cutover::os::CutoverOs;
use hole_bridge::disable_record::{DisabledState, RecordState};
use hole_bridge::platform::os::{self, Opening, RetireSession, StartTypeLock, MACHINE_WIDE_NAME};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, ERROR_ACCESS_DENIED, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{ConvertStringSidToSidW, GetSecurityInfo, SE_KERNEL_OBJECT};
use windows::Win32::Security::{
    CreateRestrictedToken, DuplicateTokenEx, SecurityImpersonation, TokenImpersonation, DACL_SECURITY_INFORMATION,
    DISABLE_MAX_PRIVILEGE, PSECURITY_DESCRIPTOR, PSID, SID_AND_ATTRIBUTES, TOKEN_DUPLICATE, TOKEN_IMPERSONATE,
    TOKEN_QUERY,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenMutexW, OpenProcessToken, SetThreadToken, MUTEX_ALL_ACCESS, SYNCHRONIZATION_ACCESS_RIGHTS,
};
use windows_service::service::{ServiceAccess, ServiceActionType, ServiceStartType};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::record_proofs::user_rights;
use super::{ProvisionedService, GLOBAL_NET_STATE, TUN};

/// `SYNCHRONIZE`: the right to wait on an object.
const SYNCHRONIZE: u32 = 0x0010_0000;
const READ_CONTROL: u32 = 0x0002_0000;

fn helper() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_test_service"))
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The lock's mutex opened for `access` by the calling thread's token.
fn open_lock_mutex(access: SYNCHRONIZATION_ACCESS_RIGHTS) -> windows::core::Result<HANDLE> {
    let name = wide(MACHINE_WIDE_NAME);
    // SAFETY: `name` is NUL-terminated and outlives the call.
    unsafe { OpenMutexW(access, false, PCWSTR(name.as_ptr())) }
}

/// The rights the ACE-naming SID `sid` has on the lock's DACL.
fn rights_on_the_lock(sid: &str) -> u32 {
    let handle = open_lock_mutex(SYNCHRONIZATION_ACCESS_RIGHTS(READ_CONTROL)).expect("open the lock for READ_CONTROL");
    let mut acl: *mut windows::Win32::Security::ACL = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `handle` is a live mutex handle with READ_CONTROL; the
    // descriptor is freed below.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut acl),
            None,
            Some(&mut descriptor),
        )
    };
    assert_eq!(status.0, 0, "GetSecurityInfo of the lock");
    let rights = if sid == "standard user" {
        user_rights("start-type lock", acl)
    } else {
        super::record_proofs::rights_of(acl, sid)
    };
    // SAFETY: both were returned by the calls above.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        let _ = CloseHandle(handle);
    }
    rights
}

/// Proves: SYSTEM and Administrators are granted every right on the lock, and
/// the groups of a standard user between them are granted `SYNCHRONIZE` and
/// nothing else, so an unprivileged GUI can wait on it and cannot release,
/// take over or change it. Red under: a DACL that grants Users more, or
/// Administrators less.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_the_start_type_lock_dacl_grants_a_user_the_wait_and_nothing_more() {
    let _held = StartTypeLock::machine_wide()
        .acquire()
        .expect("take the lock, which creates it");
    for privileged in ["S-1-5-18", "S-1-5-32-544"] {
        let rights = rights_on_the_lock(privileged);
        assert_eq!(
            rights & MUTEX_ALL_ACCESS.0,
            MUTEX_ALL_ACCESS.0,
            "{privileged} is granted {rights:#010x}, not every mutex right"
        );
    }
    let user = rights_on_the_lock("standard user");
    assert_eq!(
        user, SYNCHRONIZE,
        "a standard user's groups are granted {user:#010x}, not SYNCHRONIZE alone"
    );
}

/// Runs `f` on a new thread whose token is the current one with Administrators
/// disabled and every privilege dropped: what the GUI's unprivileged token has
/// of the lock's DACL's concern.
fn as_a_standard_user<T: Send>(f: impl FnOnce() -> T + Send) -> T {
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

/// Proves: a token without Administrators waits on the lock the way the GUI's
/// status read does (taking it when free, finding it held when not), and is
/// refused any right beyond `SYNCHRONIZE`. Red under: a DACL that grants
/// Authenticated Users more than the wait, or less.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_a_token_without_administrators_waits_on_the_start_type_lock() {
    let held = StartTypeLock::machine_wide().acquire().expect("take the lock");
    let (tried_tx, tried_rx) = std::sync::mpsc::channel();
    let (released_tx, released_rx) = std::sync::mpsc::channel::<()>();
    let (found_it_held, refusal, took_it_once_free) = std::thread::scope(|s| {
        let user = s.spawn(move || {
            as_a_standard_user(move || {
                let found_it_held = StartTypeLock::machine_wide()
                    .try_acquire()
                    .expect("try while held")
                    .is_none();
                let refusal = open_lock_mutex(MUTEX_ALL_ACCESS)
                    .err()
                    .map(|e| e.code().0 as u32 & 0xFFFF);
                tried_tx.send(()).expect("tell the holder");
                released_rx.recv().expect("the holder lets go");
                let took_it_once_free = StartTypeLock::machine_wide()
                    .try_acquire()
                    .expect("try when free")
                    .is_some();
                (found_it_held, refusal, took_it_once_free)
            })
        });
        tried_rx.recv().expect("the standard user's thread ended before trying");
        drop(held);
        released_tx.send(()).expect("tell the standard user");
        user.join().expect("the standard user's thread")
    });
    assert!(found_it_held, "the lock was held by an administrator thread");
    assert_eq!(
        refusal,
        Some(ERROR_ACCESS_DENIED.0),
        "a token without Administrators opened the lock for every right"
    );
    assert!(
        took_it_once_free,
        "the lock is free once released, and a standard user takes it"
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
    assert_eq!(gui_status_from_another_thread(), DisabledState::InChange);

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
    assert_eq!(start_type(), ServiceStartType::AutoStart);

    let mut os_actor = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    let mut hold = os_actor.hold_service().expect("hold the service");
    assert!(held_for_another_thread(), "the hold has the lock");
    assert_eq!(gui_status_from_another_thread(), DisabledState::InChange);
    assert_eq!(start_type(), ServiceStartType::Disabled, "the stop is final");
    assert!(!restarts_on_failure(), "nothing restarts the old image under the swap");
    assert_eq!(
        hole_bridge::disable_record::RecordKey::service().state(),
        RecordState::Present,
        "a kill here leaves the record that says whose disable this is"
    );

    hold.restore();
    assert_eq!(start_type(), ServiceStartType::AutoStart);
    assert!(restarts_on_failure());
    assert_eq!(
        hole_bridge::disable_record::RecordKey::service().state(),
        RecordState::Absent
    );
    assert!(held_for_another_thread(), "still held until the cutover is done");

    drop(hold);
    assert!(!held_for_another_thread(), "released with the hold");
}
