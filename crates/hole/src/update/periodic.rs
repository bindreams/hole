// Periodic background update checker.

use tauri::{AppHandle, Manager};
use tracing::{debug, info, warn};

use super::check::{check_for_update, UpdateCheck};
use super::error::UpdateError;
use super::UpdateState;

/// How long the checker waits between checks.
pub const UPDATE_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// What the stored state becomes after a check. A failed check keeps `stored`: an offer or a warning
/// already shown does not disappear because a later check could not reach GitHub.
pub fn state_after(stored: &UpdateCheck, checked: &Result<UpdateCheck, UpdateError>) -> UpdateCheck {
    match checked {
        Ok(check) => check.clone(),
        Err(_) => stored.clone(),
    }
}

/// Start the periodic update checker.
///
/// Checks immediately on launch, then every [`UPDATE_CHECK_INTERVAL`], for the life of the app. After
/// each check the stored state becomes [`state_after`] the result, and `on_changed` runs when that
/// changed it.
pub fn start_update_checker(app: AppHandle, on_changed: impl Fn(&AppHandle) + Send + 'static) {
    tauri::async_runtime::spawn(async move {
        loop {
            match app.state::<UpdateState>().check_and_store(check_for_update).await {
                Ok(stored) => {
                    match &stored.checked {
                        Ok(check) => match &check.offer {
                            Some(offer) => info!(version = %offer.version, "update available"),
                            None => debug!("no update available"),
                        },
                        Err(e) => warn!(error = e as &dyn std::error::Error, "update check failed"),
                    }
                    if stored.changed {
                        on_changed(&app);
                    }
                }
                Err(e) => warn!(error = &e as &dyn std::error::Error, "update check task panicked"),
            }

            tokio::time::sleep(UPDATE_CHECK_INTERVAL).await;
        }
    });
}

#[cfg(test)]
#[path = "periodic_tests.rs"]
mod periodic_tests;
