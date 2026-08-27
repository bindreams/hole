use super::*;

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
