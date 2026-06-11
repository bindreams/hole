// Tauri IPC commands (frontend ↔ Rust).

use crate::bridge_client::ClientError;
use crate::state::AppState;
use hole_common::config::{AppConfig, ServerEntry, ValidationState};
use hole_common::import;
use hole_common::protocol::{
    BridgeRequest, BridgeResponse, ProxyConfig, ServerTestOutcome, LATENCY_VALIDATED_ON_CONNECT,
};
use serde::Serialize;
use std::io::Read;
use std::path::Path;
use tauri::{Emitter, State};
use time::OffsetDateTime;
use tracing::{debug, info, warn};

const MAX_IMPORT_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

// ImportFailure =======================================================================================================

/// Structured import failure surfaced to the frontend. Tagged enum
/// (serde `tag = "kind"`) so the JS side branches on the discriminator
/// to pick a user-friendly blocking dialog rather than parsing failure
/// mode out of a free-form error string. See the JS-side `friendlyDialog`
/// helper at `ui/import-failure.ts`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImportFailure {
    /// File-system layer: not found / not accessible / not a regular
    /// file / wrong extension / too large to import. The `detail` is
    /// pre-scrubbed of paths and safe to show verbatim.
    FileError { detail: String },
    /// JSON syntax error. No detail — `serde_json` parse errors echo
    /// fragments of file content, which we never surface to the user
    /// (the file might contain credentials). The full underlying error
    /// is logged via `warn!` for diagnosis.
    CorruptedJson,
    /// JSON parsed but required Shadowsocks fields are missing.
    /// `missing_field` names the first missing one (e.g.
    /// `"server (or 'address')"`) so the user sees which field shape
    /// Hole was looking for.
    UnrecognizedFormat { missing_field: String },
    /// The file specifies a plugin Hole doesn't bundle. `plugin` is the
    /// offending name; `supported` is the canonical list of bundled
    /// plugin names from `hole_common::plugin::KNOWN_PLUGINS`.
    UnsupportedPlugin { plugin: String, supported: Vec<String> },
    /// A field value was out-of-range (e.g. port > 65535) or malformed
    /// (e.g. plugin name with path separators). `detail` is safe to
    /// show — it never echoes file content (covered by tests in
    /// `import_tests.rs` and `commands_tests.rs`).
    InvalidValue { detail: String },
    /// Config save to disk failed. The wire form stays detail-free on
    /// purpose; the full `ConfigError` (whose Display is path- and
    /// content-free) plus the config path is recorded in `gui.log` via
    /// `warn!`.
    SaveFailed,
}

/// Convert an `ImportError` from the parser into the user-facing
/// `ImportFailure`. The categorization is the only thing this function
/// does — it's not a one-to-one map; for example,
/// `ImportError::Parse(_)` collapses to `CorruptedJson` (no detail) to
/// avoid leaking JSON parse-error messages (which can include fragments
/// of file content). The `supported` plugin list is fetched directly
/// from the single source of truth via
/// [`hole_common::plugin::user_visible_plugin_names`] — no comma-string
/// round-trip, and the non-user-visible `ex-ray` impl-detail entry is
/// filtered out (bindreams/hole#414).
fn to_import_failure(err: import::ImportError) -> ImportFailure {
    match err {
        import::ImportError::Parse(_) => ImportFailure::CorruptedJson,
        import::ImportError::MissingField(name) => ImportFailure::UnrecognizedFormat {
            missing_field: name.to_string(),
        },
        import::ImportError::UnsupportedPlugin { name } => ImportFailure::UnsupportedPlugin {
            plugin: name,
            // Only user-visible plugins — `ex-ray` is an impl detail of
            // `v2ray-plugin` and must not appear in the GUI's supported
            // list (bindreams/hole#414).
            supported: hole_common::plugin::user_visible_plugin_names()
                .map(String::from)
                .collect(),
        },
        import::ImportError::InvalidValue(detail) => ImportFailure::InvalidValue { detail },
    }
}

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
    config.save(&state.config_path).map_err(|e| {
        warn!(error = %e, path = %state.config_path.display(), "save_config: config save failed");
        e.to_string()
    })?;
    *current = config;
    Ok(())
}

/// Helper: wrap a static user-facing string in `ImportFailure::FileError`.
fn file_error(detail: impl Into<String>) -> ImportFailure {
    ImportFailure::FileError { detail: detail.into() }
}

/// Validate a file path, read it, and parse server entries from it.
///
/// Returns an `ImportFailure` — the file-system layer maps to
/// `FileError { detail }` (with already-scrubbed detail), and parser
/// errors flow through `to_import_failure`.
fn validate_and_read_import(path: &Path) -> Result<Vec<ServerEntry>, ImportFailure> {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case("json") => {}
        _ => return Err(file_error("only .json files can be imported")),
    }

    // Open once, then fstat the fd to avoid TOCTOU races.
    let mut file = std::fs::File::open(path).map_err(|e| {
        debug!("failed to open import file: {e}");
        file_error("file not found or not accessible")
    })?;
    let metadata = file.metadata().map_err(|e| {
        debug!("failed to read file metadata: {e}");
        file_error("file not found or not accessible")
    })?;
    if !metadata.is_file() {
        return Err(file_error("path is not a regular file"));
    }
    if metadata.len() > MAX_IMPORT_FILE_SIZE {
        return Err(file_error("file is too large to import (max 10 MB)"));
    }

    let mut json = String::new();
    file.read_to_string(&mut json).map_err(|e| {
        debug!("failed to read import file: {e}");
        file_error("failed to read file")
    })?;
    import::import_servers(&json).map_err(to_import_failure)
}

/// Append `parsed` server entries into `config`, deduplicating by
/// (server, port, method, password). Returns the actually-appended entries
/// and the count of dropped duplicates. Emits a single `info!` summary so
/// every import attempt leaves a trace in `gui.log`.
///
/// Pure helper — no Tauri `State`, no `AppHandle`, no `Mutex` — so it is
/// unit-testable without standing up a real Tauri app. The `#[tauri::command]`
/// wrapper [`import_servers_from_file`] holds the lock and persists the
/// resulting config; this helper does NOT save.
fn apply_import(config: &mut AppConfig, parsed: Vec<ServerEntry>) -> (Vec<ServerEntry>, usize) {
    let parsed_count = parsed.len();
    let existing_count = config.servers.len();

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
    let appended_count = appended.len();
    let deduped_count = parsed_count - appended_count;

    let selected_before = config.selected_server.clone();
    auto_select_first_server(config);
    let selected_after = config.selected_server.clone();
    let selection_initialized_from_none = selected_before.is_none() && selected_after.is_some();
    let selection_healed = selected_before.is_some() && selected_before != selected_after;

    info!(
        parsed = parsed_count,
        appended = appended_count,
        deduped = deduped_count,
        existing_before = existing_count,
        total_after = existing_count + appended_count,
        selection_initialized_from_none,
        selection_healed,
        "import_servers_from_file: apply summary"
    );

    (appended, deduped_count)
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
///
/// Logging: emits `info!` at entry and through [`apply_import`]'s summary;
/// emits `warn!` on validate/parse failure and on config-save failure. The
/// save-failure path returns `ImportFailure::SaveFailed` (no detail in the
/// wire form) — the structured wire variant is deliberately detail-free; the
/// full `ConfigError` (path- and content-free) plus the config path land in
/// `gui.log` via `warn!`.
#[tauri::command]
pub fn import_servers_from_file(state: State<AppState>, path: String) -> Result<Vec<ServerEntry>, ImportFailure> {
    info!(path = %path, "import_servers_from_file: start");
    let parsed = validate_and_read_import(Path::new(&path)).inspect_err(|e| {
        warn!(path = %path, error = ?e, "import_servers_from_file: validate/parse failed");
    })?;

    let mut config = state.config.lock().unwrap();
    let (appended, _deduped) = apply_import(&mut config, parsed);

    config.save(&state.config_path).map_err(|e| {
        warn!(error = %e, path = %state.config_path.display(), "import_servers_from_file: config save failed");
        ImportFailure::SaveFailed
    })?;

    Ok(appended)
}

#[tauri::command]
pub async fn get_proxy_status(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    match state.bridge_send(BridgeRequest::Status).await {
        Ok(BridgeResponse::Status {
            running,
            uptime_secs,
            error,
            invalid_filters,
            udp_proxy_available,
            ipv6_bypass_available,
        }) => Ok(serde_json::json!({
            "running": running,
            "uptime_secs": uptime_secs,
            "error": error,
            "invalid_filters": invalid_filters,
            "udp_proxy_available": udp_proxy_available,
            "ipv6_bypass_available": ipv6_bypass_available,
        })),
        Ok(BridgeResponse::Error { message }) => {
            warn!(error = %message, "bridge returned error for status");
            Ok(serde_json::json!({
                "running": false,
                "uptime_secs": 0,
                "error": message,
                "invalid_filters": [],
                "udp_proxy_available": true,
                "ipv6_bypass_available": true,
            }))
        }
        Ok(_) => Ok(serde_json::json!({
            "running": false,
            "uptime_secs": 0,
            "error": "unexpected response from bridge",
            "invalid_filters": [],
            "udp_proxy_available": true,
            "ipv6_bypass_available": true,
        })),
        Err(e) => {
            // Bridge not running or unreachable — not an error for the frontend
            Ok(serde_json::json!({
                "running": false,
                "uptime_secs": 0,
                "error": format!("bridge unreachable: {e}"),
                "invalid_filters": [],
                "udp_proxy_available": true,
                "ipv6_bypass_available": true,
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
            filter,
        }) => serde_json::json!({
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "speed_in_bps": speed_in_bps,
            "speed_out_bps": speed_out_bps,
            "uptime_secs": uptime_secs,
            "filter": filter,
        }),
        _ => serde_json::json!({
            "bytes_in": 0,
            "bytes_out": 0,
            "speed_in_bps": 0,
            "speed_out_bps": 0,
            "uptime_secs": 0,
            "filter": null,
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
            cfg.save(&state.config_path).map_err(|e| {
                warn!(error = %e, path = %state.config_path.display(), "test_server: persist validation failed");
                e.to_string()
            })?;
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
        cfg.save(&state.config_path).map_err(|e| {
            warn!(error = %e, path = %state.config_path.display(), "mark_validated_by_proxy_start: persist failed");
            e.to_string()
        })?;
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
    let result = tokio::task::spawn_blocking(|| {
        // ureq v3 API: Agent-based, not free functions.
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
///
/// Always requests [`TunnelMode::Full`]; `TunnelMode::SocksOnly` is reachable
/// via `hole proxy start --tunnel-mode socks-only` and direct IPC.
pub fn build_proxy_config(config: &AppConfig) -> Option<ProxyConfig> {
    let selected_id = config.selected_server.as_ref()?;
    let entry = config.servers.iter().find(|s| &s.id == selected_id)?;
    Some(ProxyConfig {
        server: entry.clone(),
        local_port: config.local_port,
        tunnel_mode: hole_common::protocol::TunnelMode::Full,
        filters: config.filters.clone(),
        dns: config.dns.clone(),
        proxy_socks5: config.proxy_socks5,
        proxy_http: config.proxy_http,
        local_port_http: config.local_port_http,
        diagnostic_plugin_tap: config.diagnostic_plugin_tap,
    })
}

/// Reload the proxy's filter rules from the current config. If the proxy
/// is not running, this is a no-op (changes apply on next start).
#[tauri::command]
pub async fn reload_proxy_filters(state: State<'_, AppState>) -> Result<(), String> {
    let config = {
        let app_config = state.config.lock().unwrap();
        if !app_config.enabled {
            return Ok(()); // Not running, changes apply on next start.
        }
        build_proxy_config(&app_config)
    };

    let Some(proxy_config) = config else {
        return Ok(()); // No server selected.
    };

    state
        .bridge_send(BridgeRequest::Reload { config: proxy_config })
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
#[path = "commands_tests.rs"]
mod commands_tests;
