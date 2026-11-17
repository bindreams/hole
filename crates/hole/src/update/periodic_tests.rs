use super::*;
use crate::update::{UpdateInfo, Withdrawal};
use hole_common::version::ReleaseVersion;

fn offer(version: &str) -> UpdateInfo {
    UpdateInfo {
        version: ReleaseVersion::parse(version).unwrap(),
        asset_url: "https://example.com/asset".to_string(),
        asset_name: "asset".to_string(),
        sha256sums_url: "https://example.com/SHA256SUMS".to_string(),
        sha256sums_minisig_url: "https://example.com/SHA256SUMS.minisig".to_string(),
        html_url: Some(format!("https://example.com/releases/{version}")),
    }
}

fn withdrawal(version: &str) -> Withdrawal {
    Withdrawal {
        version: ReleaseVersion::parse(version).unwrap(),
        platforms: None,
        reason: "a reason".to_string(),
        url: "https://example.com/why".to_string(),
    }
}

fn found(offer: Option<UpdateInfo>, running_withdrawn: Option<Withdrawal>) -> UpdateCheck {
    UpdateCheck {
        offer,
        running_withdrawn,
    }
}

fn failure() -> UpdateError {
    UpdateError::Io(std::io::Error::other("unreachable"))
}

#[skuld::test]
fn a_failed_check_keeps_the_offer_and_the_warning() {
    let stored = found(Some(offer("0.8.0")), Some(withdrawal("0.7.0")));

    assert_eq!(state_after(&stored, &Err(failure())), stored);
}

#[skuld::test]
fn a_check_without_an_offer_drops_the_stored_one() {
    let stored = found(Some(offer("0.8.0")), None);

    assert_eq!(
        state_after(&stored, &Ok(UpdateCheck::default())),
        UpdateCheck::default()
    );
}

#[skuld::test]
fn a_check_replaces_the_offer_and_the_warning() {
    let stored = found(Some(offer("0.8.0")), Some(withdrawal("0.7.0")));
    let checked = found(Some(offer("0.8.1")), None);

    assert_eq!(state_after(&stored, &Ok(checked.clone())), checked);
}
