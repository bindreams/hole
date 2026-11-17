//! The retirement of a service by a caller that holds no `SeDebugPrivilege`: an
//! elevated prompt holds it disabled, and the Windows Installer service's
//! SYSTEM token does not hold it at all.
//!
//! The helper service runs the grant its entry calls first
//! (`platform::os::open_service_process_to_administrators`). The tests retire a
//! RUNNING service, a service held in START_PENDING and a child the service
//! leaves behind. Only the RUNNING service has a negative control, a service
//! started with `--no-grant`.

use hole_bridge::cutover::os::CutoverOs;
use hole_bridge::platform::os::process_access::RETIREMENT_ACCESS;
use hole_bridge::platform::os::token;
use hole_bridge::platform::os::uninstall;
use hole_bridge::service_scm::retire::RetireError;
use windows::core::HRESULT;
use windows::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, ERROR_SERVICE_NOT_ACTIVE, HANDLE};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, TokenPrivileges, LUID_AND_ATTRIBUTES, SE_DEBUG_NAME,
    SE_PRIVILEGE_REMOVED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcess, OpenProcessToken};

use super::{scm_probe, ProvisionedService, WindowsCutoverOs, GLOBAL_NET_STATE, TUN};

/// Removes `SeDebugPrivilege` from this process's token, and panics if the token
/// still lists it afterwards. Removal is permanent for the process, so it panics
/// outside nextest's one process per test.
pub fn remove_debug_privilege() {
    assert_eq!(
        std::env::var("NEXTEST_EXECUTION_MODE").as_deref(),
        Ok("process-per-test"),
        "Removing SeDebugPrivilege changes the token for good: run this test under `cargo nextest`, which gives each test its own process"
    );
    let mut token = HANDLE::default();
    // SAFETY: plain FFI calls on this process's own token, closed below.
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token)
            .expect("open this process's token");
        let mut luid = Default::default();
        LookupPrivilegeValueW(None, SE_DEBUG_NAME, &mut luid).expect("look up SeDebugPrivilege");
        let removal = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_REMOVED,
            }],
        };
        AdjustTokenPrivileges(token, false, Some(&removal), 0, None, None).expect("remove SeDebugPrivilege");

        let buffer = token::information(token, TokenPrivileges).expect("list the token's privileges");
        let listed = &*buffer.as_ptr().cast::<TOKEN_PRIVILEGES>();
        let held = std::slice::from_raw_parts(listed.Privileges.as_ptr(), listed.PrivilegeCount as usize);
        assert!(
            held.iter()
                .all(|p| (p.Luid.LowPart, p.Luid.HighPart) != (luid.LowPart, luid.HighPart)),
            "SeDebugPrivilege is still in the token after its removal"
        );
        CloseHandle(token).expect("close the token");
    }
}

/// A running service, with the caller's privilege gone before the uninstall.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_uninstall_deregisters_a_running_service_without_the_debug_privilege() {
    super::deregisters_a_running_service(remove_debug_privilege);
}

/// A child of the service that nothing stops, ended without the privilege.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_uninstall_terminates_an_orphan_without_the_debug_privilege() {
    super::uninstall_terminates_an_orphan(remove_debug_privilege);
}

/// A service the SCM holds in START_PENDING: its process is held and waited out
/// without the privilege.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_uninstall_ends_a_service_held_in_start_pending_without_the_debug_privilege() {
    super::retire_a_parked_service("--hold-start", remove_debug_privilege);
}

/// Sends the service a Stop through the SCM when dropped, so its helper exits by
/// itself. With the debug privilege gone, nothing in the test process can open or
/// end a `--no-grant` service's process, and the service's teardown would wait
/// for a deletion that cannot complete.
struct StopServiceOnDrop;

impl Drop for StopServiceOnDrop {
    fn drop(&mut self) {
        // The service is not active when the test body already stopped it.
        match scm_probe::Probe::open().stop() {
            Err(error) if error.code() != HRESULT::from_win32(ERROR_SERVICE_NOT_ACTIVE.0) => {
                eprintln!("the guard could not stop the service: {error}");
            }
            _ => {}
        }
    }
}

/// The negative control for the tests above, for the service's own RUNNING
/// process: one that never ran the grant (`--no-grant`) refuses the open the
/// retirement rests on, so the uninstall fails at the hold. Without this,
/// nothing shows those tests would fail without the grant.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_a_service_without_the_grant_refuses_the_open_without_the_debug_privilege() {
    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let _service = ProvisionedService::install_with_args(helper, vec!["--no-grant".into()]);
    let _stop = StopServiceOnDrop;
    let mut os = WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    };
    CutoverOs::start_service_wait_running(&mut os).expect("bring the service up");
    let pid = scm_probe::service_process_id();

    remove_debug_privilege();

    // SAFETY: plain FFI call; no pointer is passed.
    let opened = unsafe { OpenProcess(RETIREMENT_ACCESS, false, pid) };
    match opened {
        Ok(handle) => {
            // SAFETY: the handle was just opened and is not used again.
            let _ = unsafe { CloseHandle(handle) };
            panic!("the service's process opened for the retirement access though it never ran the grant");
        }
        Err(error) => assert_eq!(error.code(), HRESULT::from_win32(ERROR_ACCESS_DENIED.0), "{error}"),
    }

    let error = uninstall().expect_err("the uninstall cannot hold a process it may not open");
    assert!(
        matches!(error.downcast_ref::<RetireError>(), Some(RetireError::Hold(_))),
        "the failure is the hold's refused open: {error}"
    );
}
