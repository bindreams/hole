// Tauri IPC commands (frontend ↔ Rust).

use crate::bridge_client::ClientError;
use crate::state::AppState;
use hole_common::config::{AppConfig, ServerEntry, ValidationState};
use hole_common::import;
use hole_common::protocol::{
    BridgeRequest, BridgeResponse, ProxyConfig, ServerTestOutcome, LATENCY_VALIDATED_ON_CONNECT,
};
use std::io::Read;
use std::path::Path;
use tauri::{Emitter, State};
use time::OffsetDateTime;
use tracing::{debug, warn};

const MAX_IMPORT_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

#[tauri::command]
pub fn get_config(state: State<AppState>) -> AppConfig {
    state.config.lock().unwrap().clone()
}

#[tauri::command]
pub fn save_config(state: State<AppState>, mut config: AppConfig) -> Result<(), String> {
    let mut current = state.config.lock().unwrap();
    // The frontend doesn't know about elevation_prompt_shown — preserve the
    // in-memory value so a save from the Settings UI doesn't reset it.
    config.elevation_prompt_shown = current.elevation_prompt_shown;
    config.save(&state.config_path).map_err(|e| e.to_string())?;
    *current = config;
    Ok(())
}

/// Validate a file path, read it, and parse server entries from it.
fn validate_and_read_import(path: &Path) -> Result<Vec<ServerEntry>, String> {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case("json") => {}
        _ => return Err("only .json files can be imported".to_string()),
    }

    // Open once, then fstat the fd to avoid TOCTOU races.
    let mut file = std::fs::File::open(path).map_err(|e| {
        debug!("failed to open import file: {e}");
        "file not found or not accessible".to_string()
    })?;
    let metadata = file.metadata().map_err(|e| {
        debug!("failed to read file metadata: {e}");
        "file not found or not accessible".to_string()
    })?;
    if !metadata.is_file() {
        return Err("path is not a regular file".to_string());
    }
    if metadata.len() > MAX_IMPORT_FILE_SIZE {
        return Err("file is too large to import".to_string());
    }

    let mut json = String::new();
    file.read_to_string(&mut json).map_err(|e| {
        debug!("failed to read import file: {e}");
        "failed to read file".to_string()
    })?;
    import::import_servers(&json).map_err(|e| sanitize_import_error(&e))
}

/// Convert an ImportError to a user-facing message without leaking file content.
fn sanitize_import_error(err: &import::ImportError) -> String {
    match err {
        import::ImportError::MissingField(field) => {
            format!("missing required field: {field}")
        }
        // Parse and InvalidValue can contain fragments of file content.
        import::ImportError::Parse(_) | import::ImportError::InvalidValue(_) => {
            "file does not contain valid server configuration".to_string()
        }
    }
}

/// Select the first server if no valid server is currently selected.
///
/// Handles both `None` and stale selections (pointing to a server ID that no longer exists).
fn auto_select_first_server(config: &mut AppConfig) {
    let has_valid_selection = config
        .selected_server
        .as_ref()
        .is_some_and(|id| config.servers.iter().any(|s| &s.id == id));

    if !has_valid_selection {
        config.selected_server = config.servers.first().map(|s| s.id.clone());
    }
}

/// Import servers from a config file path. Reads the file and parses it.
///
/// Returns only the entries that were actually appended to the config —
/// duplicates of existing servers are silently dropped. The frontend uses
/// the returned IDs to auto-test *new* entries; returning phantom IDs for
/// deduped entries would produce silent "no server with id …" errors in
/// the auto-test loop.
#[tauri::command]
pub fn import_servers_from_file(state: State<AppState>, path: String) -> Result<Vec<ServerEntry>, String> {
    let parsed = validate_and_read_import(Path::new(&path))?;

    let mut config = state.config.lock().unwrap();
    let mut appended = Vec::new();
    for server in parsed {
        let already_exists = config.servers.iter().any(|s| {
            s.server == server.server
                && s.server_port == server.server_port
                && s.method == server.method
                && s.password == server.password
        });
        if !already_exists {
            config.servers.push(server.clone());
            appended.push(server);
        }
    }
    auto_select_first_server(&mut config);
    config.save(&state.config_path).map_err(|e| e.to_string())?;

    Ok(appended)
}

#[tauri::command]
pub async fn get_proxy_status(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    match state.bridge_send(BridgeRequest::Status).await {
        Ok(BridgeResponse::Status {
            running,
            uptime_secs,
            error,
        }) => Ok(serde_json::json!({
            "running": running,
            "uptime_secs": uptime_secs,
            "error": error,
        })),
        Ok(BridgeResponse::Error { message }) => {
            warn!(error = %message, "bridge returned error for status");
            Ok(serde_json::json!({
                "running": false,
                "uptime_secs": 0,
                "error": message,
            }))
        }
        Ok(_) => Ok(serde_json::json!({
            "running": false,
            "uptime_secs": 0,
            "error": "unexpected response from bridge",
        })),
        Err(e) => {
            // Bridge not running or unreachable — not an error for the frontend
            Ok(serde_json::json!({
                "running": false,
                "uptime_secs": 0,
                "error": format!("bridge unreachable: {e}"),
            }))
        }
    }
}

// Response mappers (extracted for testability) ========================================================================

fn map_metrics_response(result: Result<BridgeResponse, ClientError>) -> serde_json::Value {
    match result {
        Ok(BridgeResponse::Metrics {
            bytes_in,
            bytes_out,
            speed_in_bps,
            speed_out_bps,
            uptime_secs,
        }) => serde_json::json!({
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "speed_in_bps": speed_in_bps,
            "speed_out_bps": speed_out_bps,
            "uptime_secs": uptime_secs,
        }),
        _ => serde_json::json!({
            "bytes_in": 0,
            "bytes_out": 0,
            "speed_in_bps": 0,
            "speed_out_bps": 0,
            "uptime_secs": 0,
        }),
    }
}

fn map_diagnostics_response(result: Result<BridgeResponse, ClientError>) -> serde_json::Value {
    match result {
        Ok(BridgeResponse::Diagnostics {
            app,
            bridge,
            network,
            vpn_server,
            internet,
        }) => serde_json::json!({
            "app": app,
            "bridge": bridge,
            "network": network,
            "vpn_server": vpn_server,
            "internet": internet,
        }),
        _ => serde_json::json!({
            "app": "ok",
            "bridge": "unknown",
            "network": "unknown",
            "vpn_server": "unknown",
            "internet": "unknown",
        }),
    }
}

/// Try to extract a public IP response from the bridge result.
/// Returns `Some(json)` on success, `None` if fallback is needed.
fn map_public_ip_bridge_response(result: Result<BridgeResponse, ClientError>) -> Option<serde_json::Value> {
    match result {
        Ok(BridgeResponse::PublicIp { ip, country_code }) => {
            Some(serde_json::json!({ "ip": ip, "country_code": country_code }))
        }
        _ => None,
    }
}

// Tauri commands ======================================================================================================

#[tauri::command]
pub async fn get_metrics(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    Ok(map_metrics_response(state.bridge_send(BridgeRequest::Metrics).await))
}

#[tauri::command]
pub async fn get_diagnostics(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let bridge_result = state.bridge_send(BridgeRequest::Diagnostics).await;
    Ok(map_diagnostics_response(bridge_result))
}

/// Run a one-shot test against the server with the given `entry_id`. The
/// outcome is persisted on the corresponding `ServerEntry.validation` field
/// and a `validation-changed` event is emitted to the frontend so cards
/// rerender.
///
/// Per-entry serialization: a per-entry async lock is held for the entire
/// test duration. Two concurrent calls on the same entry are serialized so
/// that completion order — not start order — determines the persisted
/// result. Different entries do NOT contend.
#[tauri::command]
pub async fn test_server(state: State<'_, AppState>, entry_id: String) -> Result<ServerTestOutcome, String> {
    let entry_lock = state.entry_test_lock(&entry_id).await;
    let _guard = entry_lock.lock().await;

    // Snapshot the entry under the std::sync::Mutex (no `.await` held).
    let entry = {
        let cfg = state.config.lock().unwrap();
        cfg.servers
            .iter()
            .find(|s| s.id == entry_id)
            .cloned()
            .ok_or_else(|| format!("no server with id {entry_id}"))?
    };

    let outcome = match state.bridge_send(BridgeRequest::TestServer { entry }).await {
        Ok(BridgeResponse::TestServerResult { outcome }) => outcome,
        Ok(_) => ServerTestOutcome::InternalError {
            detail: "unexpected bridge response".into(),
        },
        Err(e) => ServerTestOutcome::InternalError {
            detail: format!("bridge unreachable: {e}"),
        },
    };

    // Persist. The per-entry async lock guarantees no other test_server on
    // the same entry is running, so this write is the freshest.
    {
        let mut cfg = state.config.lock().unwrap();
        if let Some(s) = cfg.servers.iter_mut().find(|s| s.id == entry_id) {
            s.validation = Some(ValidationState {
                tested_at: OffsetDateTime::now_utc(),
                outcome: outcome.clone(),
            });
            cfg.save(&state.config_path).map_err(|e| e.to_string())?;
        }
    }

    state
        .app_handle
        .emit("validation-changed", &entry_id)
        .map_err(|e| e.to_string())?;

    Ok(outcome)
}

/// Mark the given server as "validated by a successful proxy start" — used
/// when the GUI observes a Stopped → Running transition. If a real test
/// result is already on file (`Reachable { latency_ms != 0 }`), only the
/// timestamp is refreshed; otherwise a fresh sentinel
/// (`Reachable { latency_ms = LATENCY_VALIDATED_ON_CONNECT }`) is written.
///
/// Atomicity: the std::sync::Mutex around `config` is held for the entire
/// read-modify-write below. This cannot race with another sync command.
/// It CAN race with `test_server`'s persist (which is async): if
/// `test_server` is mid-flight when this fires, its later persist will
/// overwrite this sentinel with the real result — that's the right
/// priority.
#[tauri::command]
pub fn mark_validated_by_proxy_start(state: State<AppState>, entry_id: String) -> Result<(), String> {
    let mut cfg = state.config.lock().unwrap();
    if let Some(s) = cfg.servers.iter_mut().find(|s| s.id == entry_id) {
        let already_real_tested = matches!(
            &s.validation,
            Some(ValidationState {
                outcome: ServerTestOutcome::Reachable { latency_ms },
                ..
            }) if *latency_ms != LATENCY_VALIDATED_ON_CONNECT
        );

        if already_real_tested {
            if let Some(v) = s.validation.as_mut() {
                v.tested_at = OffsetDateTime::now_utc();
            }
        } else {
            s.validation = Some(ValidationState {
                tested_at: OffsetDateTime::now_utc(),
                outcome: ServerTestOutcome::Reachable {
                    latency_ms: LATENCY_VALIDATED_ON_CONNECT,
                },
            });
        }
        cfg.save(&state.config_path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub async fn get_public_ip(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    // Try bridge first (fetches through VPN when connected)
    if let Some(json) = map_public_ip_bridge_response(state.bridge_send(BridgeRequest::PublicIp).await) {
        return Ok(json);
    }

    // Bridge unreachable — fetch directly (shows ISP IP)
    // Uses ureq v3 API (Agent-based, NOT free functions)
    let result = tokio::task::spawn_blocking(|| {
        let agent = ureq::Agent::new_with_defaults();
        let body: serde_json::Value = agent
            .get("https://ipinfo.io/json")
            .call()
            .map_err(|e| format!("IP lookup failed: {e}"))?
            .body_mut()
            .read_json()
            .map_err(|e| format!("parse error: {e}"))?;
        Ok::<_, String>(serde_json::json!({
            "ip": body["ip"].as_str().unwrap_or("unknown"),
            "country_code": body["country"].as_str().unwrap_or("??"),
        }))
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?;

    result
}

/// Build a `ProxyConfig` from the currently selected server in app config.
pub fn build_proxy_config(config: &AppConfig) -> Option<ProxyConfig> {
    let selected_id = config.selected_server.as_ref()?;
    let entry = config.servers.iter().find(|s| &s.id == selected_id)?;
    Some(ProxyConfig {
        server: entry.clone(),
        local_port: config.local_port,
        filters: config.filters.clone(),
    })
}

#[cfg(test)]
#[path = "commands_tests.rs"]
mod commands_tests;
