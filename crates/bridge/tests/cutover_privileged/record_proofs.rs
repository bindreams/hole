//! Proofs, against a real service, of the record that an uninstall disabled it
//! (`hole_bridge::disable_record`):
//!
//! - at every act of a retirement, a Disabled service has its record, and the
//!   GUI's read says whose disable it is;
//! - an administrator's Disabled start type survives `ensure_stopped`;
//! - the repair resets only what the record says is ours;
//! - an unprivileged reader can query the service's start type and read the
//!   record, a value in the service's registry key, as installed, which is what
//!   the GUI's status does.
//!
//! The recording hook and the assertions read the SCM and the registry through
//! handles of their own, so what they see is what the GUI would see.

use std::path::Path;

use hole_bridge::cutover::os::windows::WindowsCutoverOs;
use hole_bridge::cutover::os::CutoverOs;
use hole_bridge::cutover::scm_wait::repair::RepairStep;
use hole_bridge::cutover::scm_wait::retire::{retire, Disposition};
use hole_bridge::disable_record::{DisabledBy, RecordKey, RecordState};
use hole_bridge::platform::os::{self, SERVICE_NAME};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertStringSidToSidW, GetEffectiveRightsFromAclW, GetNamedSecurityInfoW, NO_MULTIPLE_TRUSTEE, SE_REGISTRY_KEY,
    TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows::Win32::Security::{GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};
use windows::Win32::System::Services::{
    ChangeServiceConfigW, CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceObjectSecurity,
    ENUM_SERVICE_TYPE, SC_MANAGER_CONNECT, SERVICE_ERROR, SERVICE_NO_CHANGE, SERVICE_QUERY_CONFIG, SERVICE_START_TYPE,
};
use windows_service::service::{ServiceAccess, ServiceStartType};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::{left_behind, pid_log_args, recording, scm_deletion, scm_probe, ProvisionedService, GLOBAL_NET_STATE, TUN};

fn helper() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_test_service"))
}

fn os_actor() -> WindowsCutoverOs {
    WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    }
}

// The test's own reads and writes =====================================================================================

fn open_service(access: ServiceAccess) -> windows_service::service::Service {
    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .expect("open the SCM")
        .open_service(SERVICE_NAME, access)
        .expect("open the service")
}

/// The start type the SCM holds, read with `SERVICE_QUERY_CONFIG` alone on a
/// handle of its own, as the GUI reads it. `None` when the open or the read is
/// refused: a service marked for deletion may refuse the read.
fn start_type() -> Option<ServiceStartType> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).ok()?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_CONFIG).ok()?;
    service.query_config().ok().map(|config| config.start_type)
}

fn must_start_type() -> ServiceStartType {
    start_type().expect("the service's start type is readable")
}

/// Writes the start type the way an administrator's `sc config start=` does.
fn set_start_type(to: ServiceStartType) {
    let service = open_service(ServiceAccess::CHANGE_CONFIG);
    // SAFETY: the handle is the live one `service` owns; every pointer
    // argument is null, which `SERVICE_NO_CHANGE` and the documented null
    // defaults leave alone.
    unsafe {
        ChangeServiceConfigW(
            windows::Win32::System::Services::SC_HANDLE(service.raw_handle()),
            ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
            SERVICE_START_TYPE(to.to_raw()),
            SERVICE_ERROR(SERVICE_NO_CHANGE),
            PCWSTR::null(),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
    }
    .expect("ChangeServiceConfigW: set the start type");
}

fn record() -> RecordState {
    RecordKey::service().state()
}

fn clear_record() {
    RecordKey::service().clear().expect("clear the record");
}

/// Needs the service to exist: the record is a value in its key.
fn write_record() {
    RecordKey::service().write().expect("write the record");
}

/// Leaves no record behind, whatever the test did.
struct RecordCleanup;

impl Drop for RecordCleanup {
    fn drop(&mut self) {
        let _ = RecordKey::service().clear();
    }
}

// At every act of a retirement ========================================================================================

/// The invariant a kill at any act must find: a Disabled service has its
/// record, and the GUI's read names an interrupted uninstall as the cause. A
/// start type that is not Disabled is not attributed to anyone, whether or not
/// a record is left over it.
fn assert_a_disabled_service_has_its_record(at: &recording::Event) {
    let Some(start) = start_type() else {
        // A service marked for deletion may refuse the read; the record is
        // asserted wherever the read is answered.
        return;
    };
    let record = record();
    let by = os::disabled_state();
    match start {
        ServiceStartType::Disabled => {
            assert_eq!(
                record,
                RecordState::Present,
                "the service was left Disabled by a retirement with no record, at {at:?}"
            );
            assert_eq!(by, Some(DisabledBy::InterruptedUninstall), "at {at:?}");
        }
        _ => assert_eq!(by, None, "a service that is not disabled was attributed, at {at:?}"),
    }
}

fn retire_checking_the_invariant_at_every_act(disposition: Disposition) {
    let dir = tempfile::tempdir().unwrap();
    let pid_log = dir.path().join("pids.log");
    let _record = RecordCleanup;
    let _service = ProvisionedService::install_with_args(helper(), pid_log_args(&pid_log));
    clear_record();
    let before = must_start_type();
    CutoverOs::start_service_wait_running(&mut os_actor()).expect("bring the service up");

    let mut session = recording::open_retire_session(Box::new(assert_a_disabled_service_has_its_record));
    retire(&mut session, disposition).expect("the retirement succeeds");
    drop(session.finish());

    left_behind::assert_none(&pid_log);
    match disposition {
        Disposition::StopOnly => {
            assert_eq!(must_start_type(), before, "the start type the service had is back");
            assert_eq!(scm_probe::Probe::open().state(), 1, "the service is STOPPED");
        }
        Disposition::Deregister => {
            scm_deletion::wait_until_deleted(SERVICE_NAME).expect("the service is deleted");
        }
    }
    assert_eq!(record(), RecordState::Absent, "the retirement cleared its record");
    assert_eq!(os::disabled_state(), None);
}

/// Proves: the record is written before the start type is disabled and cleared
/// only after it is written back, so a kill at any act leaves no Disabled
/// service of ours without its record. Red under: the record written after the
/// start type, or cleared before the start type is restored.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_at_every_step_of_a_stop_only_retirement_a_disabled_service_has_its_record() {
    retire_checking_the_invariant_at_every_act(Disposition::StopOnly);
}

/// As above for the deregistration, whose delete leaves the service marked.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_at_every_step_of_a_deregistration_a_disabled_service_has_its_record() {
    retire_checking_the_invariant_at_every_act(Disposition::Deregister);
}

// An administrator's disable ==========================================================================================

/// Proves: a Disabled start type with no record is not ours, so the stop that
/// `ensure_stopped` makes neither writes a record nor puts the start type back
/// as Automatic, and the GUI's read calls it an administrator's. Red under:
/// `Hardening::plan` treating a Disabled service with no record as ours.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_an_administrators_disable_survives_ensure_stopped() {
    let dir = tempfile::tempdir().unwrap();
    let pid_log = dir.path().join("pids.log");
    let _record = RecordCleanup;
    let _service = ProvisionedService::install_with_args(helper(), pid_log_args(&pid_log));
    clear_record();
    CutoverOs::start_service_wait_running(&mut os_actor()).expect("bring the service up");
    set_start_type(ServiceStartType::Disabled);

    os::ensure_stopped().expect("stop a running service an administrator disabled");

    left_behind::assert_none(&pid_log);
    assert_eq!(must_start_type(), ServiceStartType::Disabled, "still Disabled");
    assert_eq!(
        record(),
        RecordState::Absent,
        "no record was made for a disable that is not ours"
    );
    assert_eq!(os::disabled_state(), Some(DisabledBy::Elsewhere));
    assert_eq!(
        os::disabled_by().expect("the elevated read"),
        Some(DisabledBy::Elsewhere)
    );
}

// The repair ==========================================================================================================

/// Proves: the repair resets exactly the service the record says is ours, over
/// a real service: record and Disabled reset to automatic and swept; a record
/// over a service that is not Disabled swept with the start type untouched; no
/// record over Disabled left alone; nothing found, nothing changed. Red under:
/// `RepairStep::of` answering ResetThenClear for a Disabled service with no
/// record.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_repair_resets_only_what_the_record_says_is_ours() {
    let _record = RecordCleanup;
    let _service = ProvisionedService::install(helper());

    // (start type, record) -> (step, start type after, who the GUI would say)
    let rows = [
        (
            ServiceStartType::Disabled,
            true,
            RepairStep::ResetThenClear,
            ServiceStartType::AutoStart,
            Some(DisabledBy::InterruptedUninstall),
        ),
        (
            ServiceStartType::OnDemand,
            true,
            RepairStep::ClearRecordOnly,
            ServiceStartType::OnDemand,
            None,
        ),
        (
            ServiceStartType::Disabled,
            false,
            RepairStep::LeaveDisabled,
            ServiceStartType::Disabled,
            Some(DisabledBy::Elsewhere),
        ),
        (
            ServiceStartType::OnDemand,
            false,
            RepairStep::Nothing,
            ServiceStartType::OnDemand,
            None,
        ),
    ];
    for (start, with_record, step, start_after, by) in rows {
        set_start_type(start);
        clear_record();
        if with_record {
            write_record();
        }
        assert_eq!(
            os::disabled_state(),
            by,
            "the GUI's read of {start:?}, record {with_record}"
        );

        let found = os::repair_interrupted_uninstall().expect("the repair");

        assert_eq!(found, step, "{start:?}, record {with_record}");
        assert_eq!(must_start_type(), start_after, "{start:?}, record {with_record}");
        assert_eq!(record(), RecordState::Absent, "{start:?}, record {with_record}");
    }
}

/// Proves: the record is a value in the service's own key, so it goes with the
/// service and nothing has to sweep it: after the service is deleted the record
/// reads absent and the repair has nothing to do. Red under: the record kept
/// anywhere the service's deletion does not reach.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_the_record_dies_with_its_service() {
    let _record = RecordCleanup;
    let service = ProvisionedService::install(helper());
    write_record();
    assert_eq!(record(), RecordState::Present);

    // Returns once the SCM has no entry for the service.
    drop(service);

    assert_eq!(record(), RecordState::Absent);
    assert_eq!(os::repair_interrupted_uninstall().unwrap(), RepairStep::Nothing);
    assert_eq!(os::disabled_state(), None, "no service is not a disabled service");
}

// What a service marked for deletion answers ==========================================================================

/// The start type read with `SERVICE_QUERY_CONFIG` alone on a handle of its
/// own, as the GUI reads it, or the call that was refused with its Win32 code.
fn describe_start_type_read() -> String {
    let manager = match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) {
        Ok(manager) => manager,
        Err(e) => return format!("OpenSCManager refused: {e:?}"),
    };
    let service = match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_CONFIG) {
        Ok(service) => service,
        Err(e) => return format!("OpenService(SERVICE_QUERY_CONFIG) refused: {e:?}"),
    };
    match service.query_config() {
        Ok(config) => format!("QueryServiceConfig answered start type {:?}", config.start_type),
        Err(e) => format!("QueryServiceConfig refused: {e:?}"),
    }
}

/// The service's registry key as a reader with query access finds it: whether
/// it opens, and the `DeleteFlag` value the SCM keeps there.
fn describe_key_read() -> String {
    let path = format!(r"SYSTEM\CurrentControlSet\Services\{SERVICE_NAME}");
    match windows_registry::LOCAL_MACHINE.open(path) {
        Ok(key) => format!("the key opens, DeleteFlag {:?}", key.get_u32("DeleteFlag")),
        Err(e) => format!("the key is refused: {e:?}"),
    }
}

/// Measurement: what the GUI's reads say about the entry a deregistration
/// leaves, and what happens to the record in the service's key. The service
/// here is Disabled, has a record and is marked for deletion while the test's
/// handle keeps it. If `QueryServiceConfig` answers Disabled and the record
/// still reads present, `disabled_state()` is `Some(InterruptedUninstall)` and
/// the GUI's status for a service that is being removed is
/// `Disabled(InterruptedUninstall)`; if the key is gone or the read refused,
/// the record reads as the key says (absent for a missing key, present for a
/// refusal).
///
/// The status is `hole::setup::bridge_install_status_with` over exactly the
/// three probes printed here: not installed, then running, then
/// `disabled_state()`. It is in the `hole` crate, which this test binary
/// cannot depend on. Asserts nothing about the answer; the line to read is
/// `MARKED ANSWER`.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_probe_marked_service_start_type_read() {
    let _record = RecordCleanup;
    let _service = ProvisionedService::install(helper());
    set_start_type(ServiceStartType::Disabled);
    write_record();
    let holder = super::open_to_delete();
    super::mark_for_deletion(&holder);

    let read = describe_start_type_read();
    eprintln!(
        "MARKED ANSWER: {read}. {}. record: {:?}. is_installed: {}. is_running: {}. disabled_state(): {:?}. disabled_by(): {:?}.",
        describe_key_read(),
        record(),
        os::is_installed(),
        os::is_running(),
        os::disabled_state(),
        os::disabled_by().map_err(|e| e.to_string()),
    );
    drop(holder);
}

// What an unprivileged reader can read ================================================================================

/// The well-known groups a standard interactive user's token holds, as SDDL
/// SIDs: INTERACTIVE, Authenticated Users, BUILTIN\Users, Everyone. The access
/// a standard user has is what these four grant between them.
const USER_GROUPS: [&str; 4] = ["S-1-5-4", "S-1-5-11", "S-1-5-32-545", "S-1-1-0"];

/// The access `acl` grants the SID `sid`, which `GetEffectiveRightsFromAclW`
/// computes from the ACEs that name the SID itself (not its members' groups).
fn rights_of(acl: *const windows::Win32::Security::ACL, sid: &str) -> u32 {
    let wide: Vec<u16> = sid.encode_utf16().chain(std::iter::once(0)).collect();
    let mut psid = PSID::default();
    // SAFETY: `wide` is NUL-terminated and outlives the call; the SID is freed below.
    unsafe { ConvertStringSidToSidW(PCWSTR(wide.as_ptr()), &mut psid) }.expect("parse the SID");
    let trustee = TRUSTEE_W {
        pMultipleTrustee: std::ptr::null_mut(),
        MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: PWSTR(psid.0.cast()),
    };
    let mut rights = 0u32;
    // SAFETY: `acl` is a live DACL, `trustee` names the SID parsed above, and
    // `rights` outlives the call.
    let status = unsafe { GetEffectiveRightsFromAclW(acl, &trustee, &mut rights) };
    // SAFETY: `psid` was allocated by `ConvertStringSidToSidW`, which asks for `LocalFree`.
    let _ = unsafe { LocalFree(Some(HLOCAL(psid.0))) };
    assert_eq!(status, ERROR_SUCCESS, "GetEffectiveRightsFromAclW for {sid}");
    rights
}

/// What the groups of a standard user grant between them on `acl`, with each
/// group's own share printed.
fn user_rights(what: &str, acl: *const windows::Win32::Security::ACL) -> u32 {
    let mut union = 0;
    for group in USER_GROUPS {
        let rights = rights_of(acl, group);
        eprintln!("{what}: {group} is granted {rights:#010x}");
        union |= rights;
    }
    union
}

/// The DACL of the service called `service_name`.
fn service_dacl(service_name: &str) -> Vec<u8> {
    let name: Vec<u16> = service_name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: plain FFI calls; `name` is NUL-terminated and outlives them.
    let scm = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }.expect("open the SCM");
    // READ_CONTROL (0x20000) is what reading the security descriptor needs.
    let service =
        unsafe { OpenServiceW(scm, PCWSTR(name.as_ptr()), 0x0002_0000) }.expect("open the service for READ_CONTROL");
    let mut needed = 0u32;
    // SAFETY: the sizing call, with no buffer, as documented.
    let _ = unsafe { QueryServiceObjectSecurity(service, DACL_SECURITY_INFORMATION.0, None, 0, &mut needed) };
    let mut buffer = vec![0u8; needed as usize];
    // SAFETY: `buffer` is `needed` bytes long and outlives the call.
    unsafe {
        QueryServiceObjectSecurity(
            service,
            DACL_SECURITY_INFORMATION.0,
            Some(PSECURITY_DESCRIPTOR(buffer.as_mut_ptr().cast())),
            needed,
            &mut needed,
        )
    }
    .expect("read the service's security descriptor");
    // SAFETY: both handles are live ones opened above.
    let _ = unsafe { CloseServiceHandle(service) };
    let _ = unsafe { CloseServiceHandle(scm) };
    buffer
}

/// Proves: a service created by the production `install()` lets a standard
/// interactive user open it for `SERVICE_QUERY_CONFIG`, the one right the GUI's
/// start-type read asks for, so the GUI can tell a disabled service from a
/// stopped one without elevation. If this fails the GUI cannot tell the two
/// cases apart unprivileged, and the design returns to the owner. Red under:
/// a security descriptor on the service that does not grant it (`sc sdset`).
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_the_service_dacl_lets_an_interactive_user_query_its_config() {
    ProvisionedService::require_no_leftover();
    // Deleted on drop, whatever `install` got done before it failed.
    let _service = ProvisionedService;
    os::install(helper()).expect("install the service");

    let mut descriptor = service_dacl(SERVICE_NAME);
    let mut present = windows::core::BOOL::default();
    let mut defaulted = windows::core::BOOL::default();
    let mut acl: *mut windows::Win32::Security::ACL = std::ptr::null_mut();
    // SAFETY: `descriptor` holds the descriptor the SCM filled in.
    unsafe {
        GetSecurityDescriptorDacl(
            PSECURITY_DESCRIPTOR(descriptor.as_mut_ptr().cast()),
            &mut present,
            &mut acl,
            &mut defaulted,
        )
    }
    .expect("read the DACL out of the descriptor");
    assert!(present.as_bool() && !acl.is_null(), "the service has a DACL");

    let rights = user_rights("service", acl);
    assert_ne!(
        rights & SERVICE_QUERY_CONFIG,
        0,
        "a standard user is not granted SERVICE_QUERY_CONFIG ({rights:#010x}): the GUI cannot read the start type"
    );
}

/// The DACL of the service's registry key, and the rights the groups of a
/// standard user are granted on it between them.
fn service_key_user_rights() -> u32 {
    let path: Vec<u16> = format!(r"MACHINE\SYSTEM\CurrentControlSet\Services\{SERVICE_NAME}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut acl: *mut windows::Win32::Security::ACL = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `path` is NUL-terminated and outlives the call; the descriptor is freed below.
    let status = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(path.as_ptr()),
            SE_REGISTRY_KEY,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut acl),
            None,
            &mut descriptor,
        )
    };
    assert_eq!(status, ERROR_SUCCESS, "read the service key's DACL");

    let rights = user_rights("service key", acl);
    // SAFETY: the descriptor was allocated by `GetNamedSecurityInfoW`, which asks for `LocalFree`.
    let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    rights
}

/// Proves: a standard user can read a value in the registry key of a service
/// made by the production `install()` (`KEY_QUERY_VALUE`), so the GUI can tell
/// an interrupted uninstall's disable from an administrator's. If this fails
/// the GUI cannot tell the two apart unprivileged, and the design returns to
/// the owner. Red under: a security descriptor on the key that grants Users
/// nothing.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_the_service_key_lets_an_interactive_user_read_the_record() {
    ProvisionedService::require_no_leftover();
    let _service = ProvisionedService;
    let _record = RecordCleanup;
    os::install(helper()).expect("install the service, which makes its key");
    write_record();

    let rights = service_key_user_rights();
    const KEY_QUERY_VALUE: u32 = 0x1;
    assert_ne!(
        rights & KEY_QUERY_VALUE,
        0,
        "a standard user cannot read the record ({rights:#010x}): the GUI cannot tell whose disable it is"
    );
}

/// Proves: a standard user cannot write the service's key, so the record is
/// Hole's to make: a value (or a subkey, or the key's security) a user could
/// set would let any user forge "an uninstall disabled this". Red under: a
/// security descriptor on the key that grants Users write.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_the_service_key_refuses_an_interactive_user_a_write() {
    ProvisionedService::require_no_leftover();
    let _service = ProvisionedService;
    os::install(helper()).expect("install the service, which makes its key");

    let rights = service_key_user_rights();
    const KEY_SET_VALUE: u32 = 0x2;
    const KEY_CREATE_SUB_KEY: u32 = 0x4;
    const DELETE: u32 = 0x1_0000;
    const WRITE_DAC: u32 = 0x4_0000;
    const WRITE_OWNER: u32 = 0x8_0000;
    let write = KEY_SET_VALUE | KEY_CREATE_SUB_KEY | DELETE | WRITE_DAC | WRITE_OWNER;
    assert_eq!(
        rights & write,
        0,
        "a standard user is granted write rights ({rights:#010x})"
    );
}
