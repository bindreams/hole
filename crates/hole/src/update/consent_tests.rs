use super::*;

#[skuld::test]
fn tray_consent_gates_on_lockdown() {
    assert_eq!(tray_consent_decision(true), TrayConsent::Proceed { consent: false });
    assert_eq!(tray_consent_decision(false), TrayConsent::AskUser);
}

#[skuld::test]
fn check_update_consent_polarity() {
    assert!(check_update_consent(false), "lockdown off ⇒ Install grants consent");
    assert!(!check_update_consent(true), "lockdown on ⇒ consent moot (false)");
}

#[skuld::test]
fn check_update_dialog_body_discloses_leak_only_when_lockdown_off() {
    // Derive the expectation from the single source of truth (the disclosure const),
    // so a rephrase can't silently drop the disclosure past the test.
    let off = check_update_dialog_body("1.2.3", false);
    assert!(
        off.contains("1.2.3") && off.contains(CHECK_LEAK_DISCLOSURE),
        "off must disclose the leak"
    );
    let on = check_update_dialog_body("1.2.3", true);
    assert!(
        on.contains("1.2.3") && !on.contains(CHECK_LEAK_DISCLOSURE),
        "on must not disclose a leak"
    );
}

#[skuld::test]
fn build_apply_update_maps_every_field() {
    use hole_common::protocol::BridgeRequest;
    // Distinct sentinels so a positional transposition of the four String args fails.
    let BridgeRequest::ApplyUpdate {
        payload_path,
        target_version,
        consent,
        sha256sums,
        sha256sums_minisig,
        asset_name,
        app_dest,
    } = build_apply_update(
        "/tmp/x.msi".into(),
        "9.9.9".into(),
        "SUMS".into(),
        "SIG".into(),
        "hole.msi".into(),
        Some("dest".into()),
        true,
    )
    else {
        panic!("expected ApplyUpdate");
    };
    assert_eq!(payload_path, std::path::PathBuf::from("/tmp/x.msi"));
    assert_eq!(target_version, "9.9.9");
    assert!(consent);
    assert_eq!(sha256sums, "SUMS");
    assert_eq!(sha256sums_minisig, "SIG");
    assert_eq!(asset_name, "hole.msi");
    assert_eq!(app_dest, Some("dest".to_string()));
    assert!(matches!(
        build_apply_update("/p".into(), "1".into(), "s".into(), "m".into(), "a".into(), None, false),
        BridgeRequest::ApplyUpdate { consent: false, .. }
    ));
}
