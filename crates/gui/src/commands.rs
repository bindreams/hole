// Tauri IPC commands (frontend ↔ Rust).

use crate::state::AppState;
use hole_common::config::{AppConfig, ServerEntry};
use hole_common::import;
use hole_common::protocol::{DaemonRequest, DaemonResponse, ProxyConfig};
use tauri::State;
use tracing::warn;

#[tauri::command]
pub fn get_config(state: State<AppState>) -> AppConfig {
    state.config.lock().unwrap().clone()
}

#[tauri::command]
pub fn save_config(state: State<AppState>, config: AppConfig) -> Result<(), String> {
    config.save(&state.config_path).map_err(|e| e.to_string())?;
    *state.config.lock().unwrap() = config;
    Ok(())
}

/// Import servers from a config file path. Reads the file and parses it.
#[tauri::command]
pub fn import_servers_from_file(state: State<AppState>, path: String) -> Result<Vec<ServerEntry>, String> {
    let json = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let new_servers = import::import_servers(&json).map_err(|e| e.to_string())?;

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
        plugin_path: None,
    })
}

#[cfg(test)]
#[path = "commands_tests.rs"]
mod commands_tests;
