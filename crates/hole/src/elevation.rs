// GUI elevation flow for permission-denied errors.
//
// When the bridge rejects a connection due to insufficient permissions,
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
// `grant-access` command adds the user's own SID directly to the bridge
// socket's DACL (a user's own SID is always present in their token). The
// per-user SID is cleaned up on bridge restart, when the group membership
// will have taken effect after re-login.

use crate::setup;
use crate::state::AppState;
use hole_common::protocol::BridgeRequest;
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
use tracing::{error, info, warn};

/// Show the elevation dialog flow and handle the user's choice.
///
/// Called when a user-initiated tray action fails with PermissionDenied. Returns
/// an [`ElevationResult`] distinguishing success, a propagated bridge error, a
/// post-elevation transport failure, a cancelled prompt, and a launch failure.
///
/// If this is the first time PermissionDenied is encountered, shows a single
/// dialog explaining the situation and offering permanent access. On subsequent
/// encounters (`elevation_prompt_shown` is `true` in config), skips the dialog
/// and goes directly to a UAC prompt via `ipc-send`.
pub async fn prompt_elevation(app: &AppHandle, request: BridgeRequest) -> ElevationResult {
    let state = app.state::<AppState>();

    let already_shown = state.config.lock().unwrap().elevation_prompt_shown;

    if already_shown {
        // User has already seen the explanation — just UAC-elevate the command.
        return run_ipc_send_elevated(&request).await;
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
        if let Err(e) = state.config_store.save(&config) {
            warn!(error = %e, path = %state.config_store.path().display(), "failed to persist elevation_prompt_shown");
        }
    }

    if grant {
        // Grant permanent access + send the command in one elevated invocation
        // (single UAC prompt). Uses --then-send-file to combine both operations.
        return run_grant_access_elevated(&request).await;
    }

    // User declined permanent access — one-time elevated send
    run_ipc_send_elevated(&request).await
}

/// Base64-encode a BridgeRequest (test helper for the `--base64` CLI flag).
#[cfg(test)]
pub fn encode_request(request: &BridgeRequest) -> String {
    use base64::Engine;
    let json = serde_json::to_vec(request).expect("BridgeRequest serialization cannot fail");
    base64::engine::general_purpose::STANDARD.encode(&json)
}

/// Write a BridgeRequest as JSON to a temp file with restrictive permissions.
///
/// Returns a [`TempPath`] that auto-deletes the file on drop. The file handle is
/// closed so the elevated subprocess can open it (required on Windows).
fn write_request_file(request: &BridgeRequest) -> std::io::Result<tempfile::TempPath> {
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new()?;
    serde_json::to_writer(&mut file, request).map_err(std::io::Error::other)?;
    file.flush()?;
    Ok(file.into_temp_path())
}

/// Read a BridgeRequest from a JSON file and delete it.
///
/// The file is deleted after reading as defense-in-depth (the writer's [`TempPath`]
/// also deletes on drop, but the writer process may crash before cleanup).
pub fn read_request_file(path: &std::path::Path) -> Result<BridgeRequest, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("failed to read request file {}: {e}", path.display()))?;
    let _ = std::fs::remove_file(path);
    serde_json::from_str(&content).map_err(|e| format!("invalid request JSON in {}: {e}", path.display()))
}

/// Typed outcome of an elevated `ipc-send` / `grant-access --then-send-file`,
/// written by the elevated child to the `--result-file` and read back by the
/// parent — the only channel that survives UAC stripping Windows stdio. Internal
/// GUI/CLI type; never sent over the bridge wire.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ElevatedOutcome {
    /// Bridge accepted the request (Ack/Status/...) or a bridge-side
    /// cancelled/already-running Start: the confirming Status drives the tray.
    Success,
    /// Bridge was reached but rejected the request. Raw, toast-ready.
    BridgeError { message: String },
    /// Ran elevated but could not reach the bridge. Raw, toast-ready.
    Transport { detail: String },
}

/// Child-side: serialize the outcome (truncating the empty file the parent made).
pub fn write_result_file(path: &std::path::Path, outcome: &ElevatedOutcome) -> std::io::Result<()> {
    let json = serde_json::to_vec(outcome).map_err(std::io::Error::other)?;
    std::fs::write(path, json)
}

/// Parent-side: read the outcome and delete the file (defense-in-depth; the
/// parent's TempPath also deletes on drop).
pub fn read_result_file(path: &std::path::Path) -> std::io::Result<ElevatedOutcome> {
    let content = std::fs::read_to_string(path)?;
    let _ = std::fs::remove_file(path);
    serde_json::from_str(&content).map_err(std::io::Error::other)
}

/// Map the child's send result into the on-wire outcome. Classifies on the RAW
/// bridge message (cancel / already-running tokens are not real failures). The
/// message is carried verbatim: it is authored by the bridge running as a system
/// account (LocalSystem / root) with system-scoped paths, and `ProxyConfig`
/// carries no path field, so it cannot contain user PII (#475).
pub fn classify_elevated_send(result: &Result<hole_common::protocol::BridgeResponse, String>) -> ElevatedOutcome {
    use crate::state::{classify_start_error, StartErrorKind};
    use hole_common::protocol::BridgeResponse;
    match result {
        Ok(BridgeResponse::Error { message }) => match classify_start_error(message) {
            StartErrorKind::Cancelled | StartErrorKind::AlreadyRunning => ElevatedOutcome::Success,
            // NetworkBlocked carries a toast-ready message; the parent renders it
            // clean via `start_error_toast` (#580).
            StartErrorKind::NetworkBlocked | StartErrorKind::Other => ElevatedOutcome::BridgeError {
                message: message.clone(),
            },
        },
        Ok(_) => ElevatedOutcome::Success,
        Err(detail) => ElevatedOutcome::Transport { detail: detail.clone() },
    }
}

/// What the parent distinguishes after an elevated run. `BridgeError`/`Transport`
/// carry the raw, toast-ready bridge strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElevationResult {
    Success,
    BridgeError(String),
    Transport(String),
    Cancelled,
    LaunchFailure,
}

/// Map the elevated run into a result. The result file (when the child wrote one)
/// is authoritative over the exit code: the child exits 1 on any bridge error,
/// but the file says why. A missing/unreadable file falls back to the SetupError
/// axis — never to "denied".
pub fn elevation_result_from(
    run: Result<(), &crate::setup::SetupError>,
    file: Option<ElevatedOutcome>,
) -> ElevationResult {
    if let Some(outcome) = file {
        return match outcome {
            ElevatedOutcome::Success => ElevationResult::Success,
            ElevatedOutcome::BridgeError { message } => ElevationResult::BridgeError(message),
            ElevatedOutcome::Transport { detail } => ElevationResult::Transport(detail),
        };
    }
    match run {
        Ok(()) => ElevationResult::Success,
        Err(crate::setup::SetupError::Cancelled) => ElevationResult::Cancelled,
        Err(_) => ElevationResult::LaunchFailure,
    }
}

/// Parent-side: create an empty result file and close the handle so the elevated
/// child can open it (Windows). Auto-deletes on drop.
fn write_result_file_target() -> std::io::Result<tempfile::TempPath> {
    Ok(tempfile::NamedTempFile::new()?.into_temp_path())
}

/// Spawn `hole bridge <subcommand> <req_flag> <req> --result-file <res>` elevated
/// and map the run + result file into an `ElevationResult`. Both temp files stay
/// alive on this stack across the blocking call; the result is read before they
/// drop (the request file is kept alive only to outlive the child that reads it).
async fn run_elevated_send(request: &BridgeRequest, subcommand: &str, req_flag: &str) -> ElevationResult {
    let exe = match setup::bridge_binary_path() {
        Ok(p) => p,
        Err(e) => {
            error!("cannot resolve binary path: {e}");
            return ElevationResult::LaunchFailure;
        }
    };
    let request_file = match write_request_file(request) {
        Ok(f) => f,
        Err(e) => {
            error!("failed to write request file: {e}");
            return ElevationResult::LaunchFailure;
        }
    };
    let result_file = match write_result_file_target() {
        Ok(f) => f,
        Err(e) => {
            error!("failed to create result file: {e}");
            return ElevationResult::LaunchFailure;
        }
    };

    let request_path = request_file.to_string_lossy().to_string();
    let result_path = result_file.to_string_lossy().to_string();
    let sub_owned = subcommand.to_string();
    let flag_owned = req_flag.to_string();

    let join = tokio::task::spawn_blocking(move || {
        setup::run_elevated(
            &exe,
            &[
                "bridge",
                &sub_owned,
                &flag_owned,
                &request_path,
                "--result-file",
                &result_path,
            ],
        )
    })
    .await;

    let run_result: Result<(), setup::SetupError> = match join {
        Ok(r) => r,
        Err(e) => {
            error!("spawn_blocking panicked: {e}");
            return ElevationResult::LaunchFailure;
        }
    };
    match &run_result {
        Ok(()) => {}
        Err(setup::SetupError::Cancelled) => info!("user cancelled elevation prompt"),
        Err(e) => error!("elevated {subcommand} failed: {e}"),
    }

    // Read the child's answer before the TempPaths drop (request_file is kept
    // alive only to outlive the child that read it).
    let file = read_result_file(&result_file).ok();
    drop(request_file);
    elevation_result_from(run_result.as_ref().map(|_| ()), file)
}

/// Grant permanent access + proxy the command in one elevated invocation (one
/// UAC prompt): group membership grant, DACL update, and IPC command proxy.
async fn run_grant_access_elevated(request: &BridgeRequest) -> ElevationResult {
    run_elevated_send(request, "grant-access", "--then-send-file").await
}

/// Spawn `hole bridge ipc-send --request-file <path>` elevated.
async fn run_ipc_send_elevated(request: &BridgeRequest) -> ElevationResult {
    run_elevated_send(request, "ipc-send", "--request-file").await
}

#[cfg(test)]
#[path = "elevation_tests.rs"]
mod elevation_tests;
