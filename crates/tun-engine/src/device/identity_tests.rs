use super::*;
use crate::device::config::TunName;
use crate::error::DeviceError;

const EXPECT: u128 = 0x1111_2222_3333_4444_5555_6666_7777_8888;
const ALIAS_NOT_FOUND_STATUS: u32 = 87; // ERROR_INVALID_PARAMETER
const SUCCESS_STATUS: u32 = 0;

#[skuld::test]
fn absent_alias_is_no_incumbent() {
    let result = classify_incumbent(ALIAS_NOT_FOUND_STATUS, None, EXPECT);
    assert!(
        matches!(result, Ok(Incumbent::None)),
        "an alias that does not resolve must classify as Incumbent::None (skip the check — the create path \
         is never judged), got {result:?}"
    );
}

#[skuld::test]
fn matching_guid_is_ours() {
    let result = classify_incumbent(SUCCESS_STATUS, Some(EXPECT), EXPECT);
    assert!(
        matches!(result, Ok(Incumbent::Ours)),
        "a resolved GUID equal to the expected constant must classify as Ours, got {result:?}"
    );
}

#[skuld::test]
fn mismatched_guid_is_foreign() {
    let other: u128 = 0x9999_aaaa_bbbb_cccc_dddd_eeee_ffff_0000;
    let result = classify_incumbent(SUCCESS_STATUS, Some(other), EXPECT);
    assert!(
        matches!(result, Ok(Incumbent::Foreign)),
        "a resolved GUID that differs from the expected constant must classify as Foreign, got {result:?}"
    );
}

/// A non-`ALIAS_NOT_FOUND` failure must never be reported as `Foreign` —
/// "cannot read" and "the GUID is not ours" are different facts, and
/// mis-mapping the first as the second would refuse a start that could not
/// even determine whether the adapter belongs to Hole.
#[skuld::test]
fn read_failure_is_not_a_foreign_adapter() {
    let access_denied_status: u32 = 5;
    let result = classify_incumbent(access_denied_status, None, EXPECT);
    assert!(
        result.is_err(),
        "a genuine read failure must be Err, never silently classified, got {result:?}"
    );
}

#[skuld::test]
fn foreign_adapter_error_is_pii_free_and_actionable() {
    let err = crate::error::DeviceError::ForeignAdapter {
        alias: "hole-tun".to_string(),
    };
    let text = err.to_string();
    assert!(
        text.contains("network-reset.py"),
        "the error must name the remedy script: {text}"
    );
    assert!(
        text.contains("hole-tun"),
        "the error must name the adapter alias: {text}"
    );
    // No filesystem path — no drive letter, no backslash. The alias is a
    // network-adapter friendly name, never a path.
    assert!(
        !text.contains('\\') && !text.contains(":\\"),
        "the error must not carry a filesystem path: {text}"
    );
}

// resolve_identity ====================================================================================================

/// A [`NameSource`] that panics if consulted — the guard against
/// reintroducing the Windows "not found" hazard: `Requested`'s identity must
/// come from the configured name alone, never from a read-back call.
struct PanickingNameSource;

impl NameSource for PanickingNameSource {
    fn tun_name(&self) -> std::io::Result<String> {
        panic!("read-back seam must not be called for TunName::Requested");
    }
}

#[skuld::test]
fn requested_alias_is_not_read_back() {
    let identity = resolve_identity(&TunName::Requested("hole-tun".to_string()), &PanickingNameSource, 42)
        .expect("Requested must never consult the seam, so this cannot fail");
    assert_eq!(identity.alias(), "hole-tun");
    assert_eq!(identity.luid(), 42);
}

/// A [`NameSource`] returning a fixed, pre-armed result — the seam
/// `TunName::KernelAssigned`'s read-back tests drive directly, without a
/// real device.
#[cfg(target_os = "macos")]
struct FakeNameSource(std::io::Result<String>);

#[cfg(target_os = "macos")]
impl NameSource for FakeNameSource {
    fn tun_name(&self) -> std::io::Result<String> {
        match &self.0 {
            Ok(name) => Ok(name.clone()),
            Err(e) => Err(std::io::Error::new(e.kind(), e.to_string())),
        }
    }
}

/// The returned name is deliberately something no config ever requested —
/// `KernelAssigned` has no requested name at all, so the identity can only
/// have come from the seam.
#[cfg(target_os = "macos")]
#[skuld::test]
fn kernel_assigned_alias_is_read_back() {
    let source = FakeNameSource(Ok("utun7".to_string()));
    let identity = resolve_identity(&TunName::KernelAssigned, &source, 0).expect("seam succeeded");
    assert_eq!(identity.alias(), "utun7");
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn kernel_assigned_build_fails_when_the_device_cannot_report_its_name() {
    let source = FakeNameSource(Err(std::io::Error::other("getsockopt(UTUN_OPT_IFNAME) failed")));
    let err = resolve_identity(&TunName::KernelAssigned, &source, 0).unwrap_err();
    assert!(
        matches!(err, DeviceError::TunOpen(_)),
        "a seam failure must be fatal via DeviceError::TunOpen — there is nothing to fall back to, got {err:?}"
    );
}
