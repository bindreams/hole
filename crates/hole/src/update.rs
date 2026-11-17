// Auto-update: check GitHub releases, download, and verify. The privileged
// bridge owns the install (binary swap + service restart) via the cutover; the
// GUI hands it the verified payload over `POST /v1/update-apply`.

pub(crate) mod check;
mod consent;
mod download;
mod error;
mod http;
mod periodic;
mod verify;
mod withdrawals;

use hole_common::version::ReleaseVersion;

use error::UpdateError;
use periodic::state_after;

pub use check::{check_for_update, UpdateCheck, UpdateInfo};
pub use consent::{
    build_apply_update, check_update_consent, check_update_dialog_body, cli_answer_confirms, cli_consent_decision,
    cli_withdrawn_warning, no_update_dialog, stale_offer_dialog_body, tray_consent_decision, withdrawn_dialog_body,
    CliConsent, TrayConsent, CONSENT_CLI_PROMPT, CONSENT_CLI_REFUSAL, CONSENT_DIALOG_BODY, CONSENT_DIALOG_TITLE,
    CONSENT_LOCKDOWN_RACED_OFF, STALE_OFFER_DIALOG_TITLE, WITHDRAWN_DIALOG_TITLE,
};
pub use download::download_asset;
pub use periodic::start_update_checker;
pub use verify::fetch_manifest;
pub use withdrawals::Withdrawal;

/// The macOS `.app` swap-target hint for `ApplyUpdate`, derived from the GUI's
/// own `current_exe` (`<bundle>/Contents/MacOS/hole`). The bridge re-validates it
/// against `CFBundleIdentifier == com.hole.app`, so a bad/undeterminable path is
/// rejected there as a destination precondition (400, distinct from the 422
/// payload-verify failure). Windows has no bundle and sends `None` (the SCM
/// install dir is canonical).
pub fn app_dest_hint() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let exe = std::env::current_exe().ok()?;
        hole_bridge::cutover::app_dest::resolve_app_dest_from_exe(&exe).map(|p| p.to_string_lossy().into_owned())
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// Tauri-managed state: what the latest successful check found.
pub struct UpdateState {
    /// Private: [`UpdateState::check_and_store`] is the only writer. Readers use `rx`.
    tx: tokio::sync::watch::Sender<UpdateCheck>,
    pub rx: tokio::sync::watch::Receiver<UpdateCheck>,
    /// Held from before a check starts until its result is stored, so checks run one at a time and their
    /// results are stored in the order the checks ran.
    check_lock: tokio::sync::Mutex<()>,
}

impl Default for UpdateState {
    fn default() -> Self {
        let (tx, rx) = tokio::sync::watch::channel(UpdateCheck::default());
        Self {
            tx,
            rx,
            check_lock: tokio::sync::Mutex::new(()),
        }
    }
}

/// A check and what storing it did.
pub struct StoredCheck {
    pub checked: Result<UpdateCheck, UpdateError>,
    /// Whether the stored state changed, so the caller knows to redraw.
    pub changed: bool,
}

impl UpdateState {
    /// Run `check` on a blocking thread and store its result as [`state_after`] says. Checks run one at a
    /// time, so an older result never replaces a newer one; the lock relies on the per-request bounds in
    /// `http::Bounds` to be released.
    pub async fn check_and_store(
        &self,
        check: impl FnOnce() -> Result<UpdateCheck, UpdateError> + Send + 'static,
    ) -> Result<StoredCheck, tokio::task::JoinError> {
        let _one_check_at_a_time = self.check_lock.lock().await;
        let checked = tokio::task::spawn_blocking(check).await?;
        let changed = self.tx.send_if_modified(|stored| {
            let next = state_after(stored, &checked);
            let changed = *stored != next;
            *stored = next;
            changed
        });
        Ok(StoredCheck { checked, changed })
    }
}

/// What an install does once it has checked again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaleOffer {
    /// The check still returns the offered version: install it.
    Install(UpdateInfo),
    /// The check no longer returns it: nothing is installed, and `now` is what the check found.
    Replaced { offered: ReleaseVersion, now: UpdateCheck },
}

/// Decide what installing `offered`, the version the person was shown, does, given a check made after
/// they answered. "Still returns it" means the same version.
pub fn recheck_offer(offered: &ReleaseVersion, checked: UpdateCheck) -> StaleOffer {
    match checked.offer {
        Some(ref offer) if offer.version == *offered => StaleOffer::Install(offer.clone()),
        _ => StaleOffer::Replaced {
            offered: offered.clone(),
            now: checked,
        },
    }
}

#[cfg(test)]
#[path = "update_tests.rs"]
mod update_tests;
