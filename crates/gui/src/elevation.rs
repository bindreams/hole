// GUI elevation flow for permission-denied errors.
//
// When the daemon rejects a connection due to insufficient permissions,
// this module shows a dialog and spawns a privileged helper to either
// grant permanent access (add user to hole group) or proxy a single command.
//
// Windows token limitation background:
//
// Windows process tokens are immutable snapshots of group memberships captured
// at logon time. There is no Win32 API to refresh a process's token to pick up
// new group memberships — `klist purge` and `nltest` only affect Kerberos/AD
// tickets, not local group tokens.
//
// When the user is first added to the `hole` group (either at install time or
// via `grant-access`), no running process will reflect that membership until
// the user logs out and back in. To provide immediate access, the elevated
// `grant-access` command adds the user's own SID directly to the daemon
// socket's DACL (a user's own SID is always present in their token). The
// per-user SID is cleaned up on daemon restart, when the group membership
// will have taken effect after re-login.

use crate::setup;
use crate::state::AppState;
use hole_common::protocol::DaemonRequest;
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
use tracing::{error, info, warn};

/// Show the elevation dialog flow and handle the user's choice.
///
/// Called when a user-initiated tray action fails with PermissionDenied.
/// Returns `true` if the action was successfully proxied via elevation.
///
/// If this is the first time PermissionDenied is encountered, shows a single
/// dialog explaining the situation and offering permanent access. On subsequent
/// encounters (`elevation_prompt_shown` is `true` in config), skips the dialog
/// and goes directly to a UAC prompt via `ipc-send`.
pub async fn prompt_elevation(app: &AppHandle, request: DaemonRequest) -> bool {
    let state = app.state::<AppState>();

    let already_shown = state.config.lock().unwrap().elevation_prompt_shown;

    if already_shown {
        // User has already seen the explanation — just UAC-elevate the command.
        return run_ipc_send_elevated(app, &request).await;
    }

    // First encounter: show the explanation dialog.
    let grant = app
        .dialog()
        .message(
            "Hole requires administrator permissions to enable the VPN.\n\n\
             Grant yourself permanent access?",
        )
        .title("Hole — Permission Required")
        .buttons(MessageDialogButtons::OkCancelCustom("Yes".into(), "No".into()))
        .blocking_show();

    // Mark dialog as shown BEFORE calling elevated processes — once the user
    // has seen the explanation, we don't show it again regardless of outcome.
    {
        let mut config = state.config.lock().unwrap();
        config.elevation_prompt_shown = true;
        if let Err(e) = config.save(&state.config_path) {
            warn!(error = %e, "failed to persist elevation_prompt_shown");
        }
    }

    if grant {
        // Grant permanent access + send the command in one elevated invocation
        // (single UAC prompt). Uses --then-send-file to combine both operations.
        return run_grant_access_elevated(app, &request).await;
    }

    // User declined permanent access — one-time elevated send
    run_ipc_send_elevated(app, &request).await
}

/// Base64-encode a DaemonRequest (test helper for the legacy `--base64` CLI flag).
#[cfg(test)]
pub fn encode_request(request: &DaemonRequest) -> String {
    use base64::Engine;
    let json = serde_json::to_vec(request).expect("DaemonRequest serialization cannot fail");
    base64::engine::general_purpose::STANDARD.encode(&json)
}

/// Write a DaemonRequest as JSON to a temp file with restrictive permissions.
///
/// Returns a [`TempPath`] that auto-deletes the file on drop. The file handle is
/// closed so the elevated subprocess can open it (required on Windows).
fn write_request_file(request: &DaemonRequest) -> std::io::Result<tempfile::TempPath> {
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new()?;
    serde_json::to_writer(&mut file, request).map_err(std::io::Error::other)?;
    file.flush()?;
    Ok(file.into_temp_path())
}

/// Read a DaemonRequest from a JSON file and delete it.
///
/// The file is deleted after reading as defense-in-depth (the writer's [`TempPath`]
/// also deletes on drop, but the writer process may crash before cleanup).
pub fn read_request_file(path: &std::path::Path) -> Result<DaemonRequest, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("failed to read request file {}: {e}", path.display()))?;
    let _ = std::fs::remove_file(path);
    serde_json::from_str(&content).map_err(|e| format!("invalid request JSON in {}: {e}", path.display()))
}

/// Spawn `hole daemon grant-access --then-send-file <path>` elevated.
///
/// Combines group membership grant, DACL update, and IPC command proxy in a single
/// elevated invocation (one UAC prompt).
async fn run_grant_access_elevated(app: &AppHandle, request: &DaemonRequest) -> bool {
    let exe = match setup::daemon_binary_path() {
        Ok(p) => p,
        Err(e) => {
            error!("cannot resolve binary path: {e}");
            return false;
        }
    };

    let request_file = match write_request_file(request) {
        Ok(f) => f,
        Err(e) => {
            error!("failed to write request file: {e}");
            return false;
        }
    };

    let file_path = request_file.to_string_lossy().to_string();
    let result = tokio::task::spawn_blocking(move || {
        let _keep_alive = request_file;
        setup::run_elevated(&exe, &["daemon", "grant-access", "--then-send-file", &file_path])
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

/// Spawn `hole daemon ipc-send --request-file <path>` elevated.
async fn run_ipc_send_elevated(_app: &AppHandle, request: &DaemonRequest) -> bool {
    let exe = match setup::daemon_binary_path() {
        Ok(p) => p,
        Err(e) => {
            error!("cannot resolve binary path: {e}");
            return false;
        }
    };

    let request_file = match write_request_file(request) {
        Ok(f) => f,
        Err(e) => {
            error!("failed to write request file: {e}");
            return false;
        }
    };

    let file_path = request_file.to_string_lossy().to_string();
    let result = tokio::task::spawn_blocking(move || {
        let _keep_alive = request_file;
        setup::run_elevated(&exe, &["daemon", "ipc-send", "--request-file", &file_path])
    })
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
