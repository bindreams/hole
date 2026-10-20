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
    assert!(ServiceSid::everyone()
        .is_in_token_of(&own_process())
        .expect("read this process's token"));
}

/// A SID no ordinary token carries is not. `S-1-5-80-1` (revision 1, two
/// sub-authorities, authority 5, then 80 and 1) is the `NT SERVICE` domain's
/// first virtual account, which this process does not run as.
#[skuld::test]
fn a_sid_the_token_lacks_is_not_found_in_it() {
    assert!(!ServiceSid::nothing_carries()
        .is_in_token_of(&own_process())
        .expect("read this process's token"));
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

// The name-derived SID ================================================================================================

/// Microsoft's published SID for the `TrustedInstaller` service: a vector that
/// does not come from this code.
#[skuld::test]
fn the_sid_of_trustedinstaller_is_the_published_one() {
    assert_eq!(
        ServiceSid::of("TrustedInstaller").to_string(),
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    );
}

/// Both come from outside this code: `sc showsid <name>`, which prints a SID
/// even for a name no service has, and Python's
/// `hashlib.sha1(name.upper().encode("utf-16-le"))` read as five little-endian
/// DWORDs.
#[skuld::test]
fn the_sid_of_a_name_is_the_one_sc_showsid_prints() {
    assert_eq!(
        ServiceSid::of("HoleBridge").to_string(),
        "S-1-5-80-2360150170-1344213777-276432733-568477872-1069952987"
    );
    assert_eq!(
        ServiceSid::of("EventLog").to_string(),
        "S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122"
    );
}

#[skuld::test]
fn the_sid_of_a_name_ignores_its_case() {
    assert_eq!(ServiceSid::of("holebridge"), ServiceSid::of("HOLEBRIDGE"));
    assert_eq!(ServiceSid::of("HoleBridge"), ServiceSid::of("HOLEBRIDGE"));
}

/// The SCM's upper-casing is not spelled out beyond ASCII, so the derivation
/// refuses to guess for any other name.
#[skuld::test]
#[should_panic(expected = "ASCII")]
fn the_sid_of_a_non_ascii_name_is_refused() {
    let _ = ServiceSid::of("Hole\u{e9}Bridge");
}

/// The OS resolves services every Windows has, with no privilege, so this
/// compares the derivation to the OS on any machine.
#[skuld::test]
fn the_sid_of_a_name_is_the_os_sid_of_an_installed_service() {
    for name in ["TrustedInstaller", "EventLog", "Dnscache", "Winmgmt"] {
        let from_os = ServiceSid::os_lookup(name).unwrap_or_else(|e| panic!("resolve NT SERVICE\\{name}: {e}"));
        assert_eq!(ServiceSid::of(name), from_os, "{name}");
    }
}
