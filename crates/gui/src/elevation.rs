// GUI elevation flow for permission-denied errors.
//
// When the daemon rejects a connection due to insufficient permissions,
// this module shows a dialog and spawns a privileged helper to either
// grant permanent access (add user to hole group) or proxy a single command.

use crate::setup;
use base64::Engine;
use hole_common::protocol::DaemonRequest;
use tauri::AppHandle;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
use tracing::{error, info};

/// Show the elevation dialog flow and handle the user's choice.
///
/// Called when a user-initiated tray action fails with PermissionDenied.
/// Returns `true` if the action was successfully proxied via elevation.
pub async fn prompt_elevation(app: &AppHandle, request: DaemonRequest) -> bool {
    let b64_request = encode_request(&request);

    // Dialog 1: Offer permanent access
    let grant = app
        .dialog()
        .message(
            "You don't have permission to control the Hole daemon.\n\n\
             Grant yourself permanent access?\n\
             (Requires administrator privileges)",
        )
        .title("Hole — Permission Denied")
        .buttons(MessageDialogButtons::OkCancelCustom(
            "Grant Access".into(),
            "Not Now".into(),
        ))
        .blocking_show();

    if grant {
        // Grant access + proxy command in one elevated invocation
        return run_grant_access_elevated(app, &b64_request).await;
    }

    // Dialog 2: Offer one-time elevation
    let elevate = app
        .dialog()
        .message("Run this action with one-time elevation?")
        .title("Hole — One-Time Elevation")
        .buttons(MessageDialogButtons::OkCancelCustom("Elevate".into(), "Cancel".into()))
        .blocking_show();

    if elevate {
        return run_ipc_send_elevated(app, &b64_request).await;
    }

    false
}

/// Base64-encode a DaemonRequest for passing through CLI args.
pub fn encode_request(request: &DaemonRequest) -> String {
    let json = serde_json::to_vec(request).expect("DaemonRequest serialization cannot fail");
    base64::engine::general_purpose::STANDARD.encode(&json)
}

/// Spawn `hole daemon grant-access --then-send <b64>` elevated.
async fn run_grant_access_elevated(app: &AppHandle, b64_request: &str) -> bool {
    let exe = match setup::daemon_binary_path() {
        Ok(p) => p,
        Err(e) => {
            error!("cannot resolve binary path: {e}");
            return false;
        }
    };

    let b64_owned = b64_request.to_string();
    let result = tokio::task::spawn_blocking(move || {
        setup::run_elevated(&exe, &["daemon", "grant-access", "--then-send", &b64_owned])
    })
    .await;

    match result {
        Ok(Ok(status)) if status.success() => {
            info!("grant-access succeeded");
            true
        }
        Ok(Err(setup::SetupError::Cancelled)) => {
            info!("user cancelled elevation prompt");
            false
        }
        Ok(Ok(status)) => {
            let code = status.code().unwrap_or(-1);
            error!("grant-access exited with code {code}");
            app.dialog()
                .message(format!("Failed to grant access (exit code {code})."))
                .title("Elevation Error")
                .blocking_show();
            false
        }
        Ok(Err(e)) => {
            error!("elevation failed: {e}");
            app.dialog()
                .message(format!("Elevation failed: {e}"))
                .title("Elevation Error")
                .blocking_show();
            false
        }
        Err(e) => {
            error!("spawn_blocking panicked: {e}");
            false
        }
    }
}

/// Spawn `hole daemon ipc-send --base64 <b64>` elevated.
async fn run_ipc_send_elevated(_app: &AppHandle, b64_request: &str) -> bool {
    let exe = match setup::daemon_binary_path() {
        Ok(p) => p,
        Err(e) => {
            error!("cannot resolve binary path: {e}");
            return false;
        }
    };

    let b64_owned = b64_request.to_string();
    let result =
        tokio::task::spawn_blocking(move || setup::run_elevated(&exe, &["daemon", "ipc-send", "--base64", &b64_owned]))
            .await;

    match result {
        Ok(Ok(status)) if status.success() => {
            info!("ipc-send succeeded");
            true
        }
        Ok(Err(setup::SetupError::Cancelled)) => {
            info!("user cancelled elevation prompt");
            false
        }
        Ok(Ok(status)) => {
            let code = status.code().unwrap_or(-1);
            error!("ipc-send exited with code {code}");
            false
        }
        Ok(Err(e)) => {
            error!("elevation failed: {e}");
            false
        }
        Err(e) => {
            error!("spawn_blocking panicked: {e}");
            false
        }
    }
}

#[cfg(test)]
#[path = "elevation_tests.rs"]
mod elevation_tests;
