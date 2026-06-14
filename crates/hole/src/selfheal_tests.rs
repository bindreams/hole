use super::*;

// `decide` is pure and `#[cfg]`-free; identities are any `PartialEq` token
// (`u8` here, `same_file::Handle` in production).

#[skuld::test]
fn matched_operates() {
    assert_eq!(decide("7", Some("7"), 1u8, Some(1u8)), SelfHealAction::Operate);
}

#[skuld::test]
fn stale_image_relaunches() {
    // running != canonical, version differs ⇒ an update swapped us underneath.
    assert_eq!(decide("6", Some("7"), 1u8, Some(2u8)), SelfHealAction::Relaunch);
}

#[skuld::test]
fn absent_header_with_stale_image_relaunches() {
    // old bridge (no version header) + stale image ⇒ still relaunch.
    assert_eq!(decide("6", None, 1u8, Some(2u8)), SelfHealAction::Relaunch);
}

#[skuld::test]
fn same_image_mismatch_is_reinstall() {
    // I am the installed image but the bridge differs ⇒ genuine misconfig.
    assert_eq!(decide("7", Some("6"), 1u8, Some(1u8)), SelfHealAction::Reinstall);
}

#[skuld::test]
fn canonical_absent_is_transient() {
    // installed file momentarily missing mid-swap ⇒ retry, never fatal.
    assert_eq!(decide("6", Some("7"), 1u8, None::<u8>), SelfHealAction::Transient);
}
