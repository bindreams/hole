//! Client-side consent surface for a lockdown-off in-place update: discloses that
//! the bridge restart briefly egresses cleartext and obtains the user's answer.

use hole_common::protocol::BridgeRequest;
use std::path::PathBuf;

pub const CONSENT_DIALOG_TITLE: &str = "Install Update";
pub const CONSENT_DIALOG_BODY: &str = "Installing this update restarts the VPN.\n\nWith Lockdown off, your internet traffic briefly goes out unencrypted while the VPN restarts.\n\nInstall this update?";
pub const CONSENT_LOCKDOWN_RACED_OFF: &str = "Lockdown changed during the update. Please try installing again.";

/// Tray consent action (badge path).
#[derive(Debug, PartialEq, Eq)]
pub enum TrayConsent {
    Proceed { consent: bool },
    AskUser,
}

pub fn tray_consent_decision(lockdown_enabled: bool) -> TrayConsent {
    if lockdown_enabled {
        TrayConsent::Proceed { consent: false }
    } else {
        TrayConsent::AskUser
    }
}

/// `consent` to send when the user installs from the check dialog: lockdown off ⇒
/// the merged dialog disclosed the leak (true); lockdown on ⇒ moot (false).
pub fn check_update_consent(lockdown_enabled: bool) -> bool {
    !lockdown_enabled
}

/// The leak disclosure the lockdown-off check dialog embeds — a single source of
/// truth shared by `check_update_dialog_body` and its test.
const CHECK_LEAK_DISCLOSURE: &str =
    "Installing it restarts the VPN. With Lockdown off, your traffic briefly goes out unencrypted while the VPN restarts.";

/// Body for the tray "Check for Updates" dialog; lockdown-off folds in the leak
/// disclosure so that path shows one dialog.
pub fn check_update_dialog_body(version: &str, lockdown_enabled: bool) -> String {
    if lockdown_enabled {
        format!("Version {version} is available.\n\nWould you like to install it now?")
    } else {
        format!("Version {version} is available.\n\n{CHECK_LEAK_DISCLOSURE}\n\nInstall it now?")
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_apply_update(
    payload_path: PathBuf,
    target_version: String,
    sha256sums: String,
    sha256sums_minisig: String,
    asset_name: String,
    app_dest: Option<String>,
    consent: bool,
) -> BridgeRequest {
    BridgeRequest::ApplyUpdate {
        payload_path,
        target_version,
        consent,
        sha256sums,
        sha256sums_minisig,
        asset_name,
        app_dest,
    }
}

#[cfg(test)]
#[path = "consent_tests.rs"]
mod consent_tests;
