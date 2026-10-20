use std::os::windows::io::{FromRawHandle, OwnedHandle};

use windows::Win32::System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

use super::{ServiceSid, SidRepair};

fn own_process() -> OwnedHandle {
    // SAFETY: plain FFI call.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, GetCurrentProcessId()) }
        .expect("open this process for a token query");
    // SAFETY: `OpenProcess` returned a new handle this value now owns.
    unsafe { OwnedHandle::from_raw_handle(handle.0) }
}

/// A SID the token carries is found in it. `Everyone` (S-1-1-0: revision 1, one
/// sub-authority, authority 1, sub-authority 0) is in every token. The
/// negative half, a real service SID absent from a process that is not the
/// service, needs a registered service (`NT SERVICE\<name>` resolves only for
/// one) and is asserted by `cutover_global_net_state_service_sid_probe_a_stranger`
/// (`tests/cutover_privileged.rs`).
#[skuld::test]
fn a_sid_the_token_carries_is_found_in_it() {
    let everyone = ServiceSid {
        sid: vec![0x0000_0101, 0x0100_0000, 0],
    };
    assert!(everyone
        .is_in_token_of(&own_process())
        .expect("read this process's token"));
}

/// A SID no ordinary token carries is not. `S-1-5-80-1` (revision 1, two
/// sub-authorities, authority 5, then 80 and 1) is the `NT SERVICE` domain's
/// first virtual account, which this process does not run as.
#[skuld::test]
fn a_sid_the_token_lacks_is_not_found_in_it() {
    let other = ServiceSid {
        sid: vec![0x0000_0201, 0x0500_0000, 80, 1],
    };
    assert!(!other.is_in_token_of(&own_process()).expect("read this process's token"));
}

/// The values are `winsvc.h`'s: `SERVICE_SID_TYPE_NONE` 0, `_UNRESTRICTED` 1,
/// `_RESTRICTED` 3. Only the type `bridge install` sets is left alone: the
/// uninstaller's token check needs the service's SID in the token, and a
/// service without the type (NONE) is the one an in-app update leaves behind.
#[skuld::test]
fn only_the_unrestricted_sid_type_is_left_alone() {
    assert_eq!(SidRepair::for_sid_type(0), SidRepair::Apply);
    assert_eq!(SidRepair::for_sid_type(1), SidRepair::Leave);
    assert_eq!(SidRepair::for_sid_type(3), SidRepair::Apply);
}
