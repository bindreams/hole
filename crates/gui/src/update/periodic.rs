// Periodic background update checker.

use tauri::{AppHandle, Manager};
use tracing::{debug, info, warn};

use super::check::check_for_update;
use super::UpdateState;

/// Start the periodic update checker.
///
/// Checks immediately on launch, then every 24 hours. Once an update is found,
/// publishes it to `UpdateState` and calls `on_update_found`, then stops.
pub fn start_update_checker(app: AppHandle, on_update_found: impl Fn(&AppHandle, &super::UpdateInfo) + Send + 'static) {
    tauri::async_runtime::spawn(async move {
        loop {
            let result = tokio::task::spawn_blocking(check_for_update).await;

            match result {
                Ok(Ok(Some(update_info))) => {
                    info!(version = %update_info.version, "update available");

                    // Publish to state.
                    let state = app.state::<UpdateState>();
                    state.tx.send_replace(Some(update_info.clone()));

                    // Notify caller (e.g. to rebuild tray menu).
                    on_update_found(&app, &update_info);
                    return; // Stop checking — user can act on this update.
                }
                Ok(Ok(None)) => {
                    debug!("no update available");
                }
                Ok(Err(e)) => {
                    warn!(error = %e, "update check failed");
                }
                Err(e) => {
                    warn!(error = %e, "update check task panicked");
                }
            }

            tokio::time::sleep(std::time::Duration::from_secs(24 * 60 * 60)).await;
        }
    });
}

#[cfg(test)]
#[path = "periodic_tests.rs"]
mod periodic_tests;
