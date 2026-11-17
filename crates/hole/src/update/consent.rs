//! Client-side consent surface for a lockdown-off in-place update: discloses that
//! the bridge restart briefly egresses cleartext and obtains the user's answer.

use hole_common::protocol::BridgeRequest;
use hole_common::version::ReleaseVersion;
use std::path::PathBuf;

use super::check::UpdateCheck;
use super::withdrawals::Withdrawal;

pub const CONSENT_DIALOG_TITLE: &str = "Install Update";
pub const CONSENT_DIALOG_BODY: &str = "Installing this update restarts the VPN.\n\nWith Lockdown off, your internet traffic briefly goes out unencrypted while the VPN restarts.\n\nInstall this update?";
pub const CONSENT_LOCKDOWN_RACED_OFF: &str = "Lockdown changed during the update. Please try installing again.";

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

/// The leak disclosure embedded in the lockdown-off check dialog.
const CHECK_LEAK_DISCLOSURE: &str =
    "Installing it restarts the VPN. With Lockdown off, your traffic briefly goes out unencrypted while the VPN restarts.";

/// Body for the tray "Check for Updates" dialog; the lockdown-off branch folds
/// in the leak disclosure so that path needs only one dialog. When the running version is withdrawn, the
/// body starts with the sentence the withdrawn-version dialog uses.
pub fn check_update_dialog_body(
    version: &str,
    lockdown_enabled: bool,
    running_withdrawn: Option<&Withdrawal>,
) -> String {
    let offer = if lockdown_enabled {
        format!("Version {version} is available.\n\nWould you like to install it now?")
    } else {
        format!("Version {version} is available.\n\n{CHECK_LEAK_DISCLOSURE}\n\nInstall it now?")
    };
    match running_withdrawn {
        Some(withdrawal) => format!("{}\n\n{offer}", withdrawn_dialog_body(withdrawal)),
        None => offer,
    }
}

pub const WITHDRAWN_DIALOG_TITLE: &str = "Version Withdrawn";

/// A dialog's title and body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialogText {
    pub title: &'static str,
    pub body: String,
}

/// Body of the dialog the tray's withdrawn-version item opens.
pub fn withdrawn_dialog_body(withdrawal: &Withdrawal) -> String {
    format!(
        "Hole {} was withdrawn.

{}",
        withdrawal.version, withdrawal.reason
    )
}

/// The dialog "Check for Updates" shows when no update is offered: the latest-version notice, or, when
/// the running version is withdrawn, that it was and that nothing newer exists yet.
pub fn no_update_dialog(running_version: &str, running_withdrawn: Option<&Withdrawal>) -> DialogText {
    match running_withdrawn {
        Some(withdrawal) => DialogText {
            title: WITHDRAWN_DIALOG_TITLE,
            body: format!(
                "Hole {} was withdrawn and no newer version is available yet.

{}",
                withdrawal.version, withdrawal.reason
            ),
        },
        None => DialogText {
            title: "No Updates Available",
            body: format!("You're running the latest version ({running_version})."),
        },
    }
}

/// The `hole upgrade` warning for a withdrawn running version.
pub fn cli_withdrawn_warning(withdrawal: &Withdrawal) -> String {
    format!(
        "this version ({}) was withdrawn: {} ({})",
        withdrawal.version, withdrawal.reason, withdrawal.url
    )
}

pub const STALE_OFFER_DIALOG_TITLE: &str = "Update No Longer Available";

/// Body shown when "Install Update" checked again and the offered version is no longer offered:
/// nothing was installed, and `now` says what is offered instead.
pub fn stale_offer_dialog_body(offered: &ReleaseVersion, now: &UpdateCheck) -> String {
    match &now.offer {
        Some(offer) => format!(
            "Version {offered} is no longer offered. Nothing was installed.

Version {} is available instead; choose Install Update to install it.",
            offer.version
        ),
        None => {
            format!("Version {offered} is no longer offered, and no update is available now. Nothing was installed.")
        }
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

pub const CONSENT_CLI_PROMPT: &str = "This update restarts the VPN. With Lockdown off, your traffic briefly goes out unencrypted during the restart.\nContinue? [y/N]: ";
pub const CONSENT_CLI_REFUSAL: &str = "this update briefly sends your traffic unencrypted during the restart unless Lockdown is on, so it needs confirmation. Re-run in a terminal, or pass --yes to confirm. (Enabling Lockdown avoids this.)";

#[derive(Debug, PartialEq, Eq)]
pub enum CliConsent {
    Proceed { consent: bool },
    Prompt,
    Refuse,
}

pub fn cli_consent_decision(lockdown_enabled: bool, yes: bool, interactive: bool) -> CliConsent {
    if lockdown_enabled {
        return CliConsent::Proceed { consent: false };
    }
    if yes {
        return CliConsent::Proceed { consent: true };
    }
    if interactive {
        return CliConsent::Prompt;
    }
    CliConsent::Refuse
}

/// Whether a read prompt line is an explicit yes; anything else — a bare Enter, an
/// EOF empty line, `n` — declines (default-deny [y/N]).
pub fn cli_answer_confirms(line: &str) -> bool {
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
#[path = "consent_tests.rs"]
mod consent_tests;
