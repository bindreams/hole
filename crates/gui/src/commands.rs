// Tauri IPC commands (frontend ↔ Rust).

use crate::state::AppState;
use hole_common::config::{AppConfig, ServerEntry};
use hole_common::import;
use hole_common::protocol::{DaemonRequest, DaemonResponse, ProxyConfig};
use std::io::Read;
use std::path::Path;
use tauri::State;
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
#[tauri::command]
pub fn import_servers_from_file(state: State<AppState>, path: String) -> Result<Vec<ServerEntry>, String> {
    let new_servers = validate_and_read_import(Path::new(&path))?;

    let mut config = state.config.lock().unwrap();
    for server in &new_servers {
        let already_exists = config.servers.iter().any(|s| {
            s.server == server.server
                && s.server_port == server.server_port
                && s.method == server.method
                && s.password == server.password
        });
        if !already_exists {
            config.servers.push(server.clone());
        }
    }
    auto_select_first_server(&mut config);
    config.save(&state.config_path).map_err(|e| e.to_string())?;

    Ok(new_servers)
}

#[tauri::command]
pub async fn get_proxy_status(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    match state.daemon_send(DaemonRequest::Status).await {
        Ok(DaemonResponse::Status {
            running,
            uptime_secs,
            error,
        }) => Ok(serde_json::json!({
            "running": running,
            "uptime_secs": uptime_secs,
            "error": error,
        })),
        Ok(DaemonResponse::Error { message }) => {
            warn!(error = %message, "daemon returned error for status");
            Ok(serde_json::json!({
                "running": false,
                "uptime_secs": 0,
                "error": message,
            }))
        }
        Ok(_) => Ok(serde_json::json!({
            "running": false,
            "uptime_secs": 0,
            "error": "unexpected response from daemon",
        })),
        Err(e) => {
            // Daemon not running or unreachable — not an error for the frontend
            Ok(serde_json::json!({
                "running": false,
                "uptime_secs": 0,
                "error": format!("daemon unreachable: {e}"),
            }))
        }
    }
}

/// Build a `ProxyConfig` from the currently selected server in app config.
pub fn build_proxy_config(config: &AppConfig) -> Option<ProxyConfig> {
    let selected_id = config.selected_server.as_ref()?;
    let entry = config.servers.iter().find(|s| &s.id == selected_id)?;
    Some(ProxyConfig {
        server: entry.clone(),
        local_port: config.local_port,
    })
}

#[cfg(test)]
#[path = "commands_tests.rs"]
mod commands_tests;
