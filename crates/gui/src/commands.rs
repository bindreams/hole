// Tauri IPC commands (frontend ↔ Rust).

use crate::bridge_client::ClientError;
use crate::state::AppState;
use hole_common::config::{AppConfig, ServerEntry};
use hole_common::import;
use hole_common::protocol::{BridgeRequest, BridgeResponse, ProxyConfig};
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

// VPN server reachability probe =======================================================================================

/// Probe a configured server by attempting a TCP connect with a short
/// timeout. Returns `true` if the connection succeeds, `false` on any
/// failure (refused, timeout, DNS resolution failure, empty hostname).
///
/// We use a plain TCP connect rather than an HTTP HEAD because shadowsocks
/// servers do not necessarily speak HTTP — only v2ray-plugin in
/// WebSocket-over-HTTP mode would respond. TCP connect is the most general
/// reachability test and works for both plain shadowsocks and HTTP-fronted
/// configurations. tokio's `TcpStream::connect((&str, u16))` handles both
/// IPv4 and IPv6 (including bare IPv6 literals) via `ToSocketAddrs`.
async fn probe_vpn_server_reachable(host: String, port: u16) -> bool {
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};

    if host.is_empty() {
        debug!("vpn server probe skipped: empty hostname");
        return false;
    }
    debug!(host = %host, port, "probing vpn server reachability");

    let result = timeout(Duration::from_secs(2), TcpStream::connect((host.as_str(), port))).await;
    let reachable = matches!(result, Ok(Ok(_)));
    debug!(host = %host, port, reachable, "vpn server probe complete");
    reachable
}

/// Override `vpn_server` in `diag` based on a probe outcome.
///
/// Contract: this function only modifies `vpn_server` when the bridge said
/// "unknown". The bridge returns "unknown" precisely when the proxy is
/// Stopped — the bridge has no server config to probe and defers to the
/// GUI. When the bridge has authoritative knowledge ("ok" or "error"), the
/// caller's probe result is ignored.
fn merge_vpn_probe(mut diag: serde_json::Value, probe: bool) -> serde_json::Value {
    if diag.get("vpn_server").and_then(|v| v.as_str()) == Some("unknown") {
        diag["vpn_server"] = serde_json::json!(if probe { "ok" } else { "error" });
    }
    diag
}

/// Combine a bridge diagnostics result with a local VPN-server probe.
/// Thin wrapper around [`diagnose_with`] that injects the real probe.
async fn diagnose(bridge_result: Result<BridgeResponse, ClientError>, config: &AppConfig) -> serde_json::Value {
    diagnose_with(bridge_result, config, |host, port| {
        Box::pin(probe_vpn_server_reachable(host, port))
    })
    .await
}

/// Test seam for [`diagnose`]: accepts an injected async probe function so
/// unit tests can exercise the orchestration without depending on the
/// runner's network stack. The GHA windows-latest image drops inbound SYNs
/// to ephemeral loopback ports, which makes any real-socket "reachable"
/// fixture unusable there — injection is the only platform-agnostic way to
/// test the "probe says reachable → vpn_server=ok" path.
async fn diagnose_with<F>(
    bridge_result: Result<BridgeResponse, ClientError>,
    config: &AppConfig,
    probe: F,
) -> serde_json::Value
where
    F: FnOnce(String, u16) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>,
{
    let mut diag = map_diagnostics_response(bridge_result);
    if diag.get("vpn_server").and_then(|v| v.as_str()) == Some("unknown") {
        if let Some(pc) = build_proxy_config(config) {
            let reachable = probe(pc.server.server, pc.server.server_port).await;
            diag = merge_vpn_probe(diag, reachable);
        }
    }
    diag
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
    // Clone the config out from under the std::sync::Mutex BEFORE the await
    // so the guard does not cross an `.await` point.
    let config = state.config.lock().unwrap().clone();
    Ok(diagnose(bridge_result, &config).await)
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
    })
}

#[cfg(test)]
#[path = "commands_tests.rs"]
mod commands_tests;
