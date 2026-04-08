// Application state management.

use crate::bridge_client::{BridgeClient, ClientError};
use hole_common::config::AppConfig;
use hole_common::protocol::{BridgeRequest, BridgeResponse};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::warn;

/// Shared application state managed by Tauri.
pub struct AppState {
    pub config_path: PathBuf,
    pub config: Mutex<AppConfig>,
    /// Tauri app handle, used by commands that need to emit events
    /// (currently `test_server` → `validation-changed`).
    pub app_handle: tauri::AppHandle,
    bridge: tokio::sync::Mutex<Option<BridgeClient>>,
    /// Per-entry test serialization. Acquired for the entire duration of a
    /// `test_server` call so a slower test cannot overwrite a faster newer
    /// one. Different entries do NOT contend.
    test_locks: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl AppState {
    pub fn new(config_path: PathBuf, app_handle: tauri::AppHandle) -> Self {
        let config = AppConfig::load(&config_path).unwrap_or_default();
        Self {
            config_path,
            config: Mutex::new(config),
            app_handle,
            bridge: tokio::sync::Mutex::new(None),
            test_locks: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Fetch (or create on first access) the per-entry async mutex used to
    /// serialize concurrent `test_server` calls on the same entry. The
    /// outer mutex around the HashMap is held only for the lookup; the
    /// inner per-entry mutex is what serializes the test runs.
    pub async fn entry_test_lock(&self, entry_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.test_locks.lock().await;
        locks
            .entry(entry_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Send a request to the bridge, lazily connecting on first use.
    /// On connection failure, clears the cached client so the next call reconnects.
    pub async fn bridge_send(&self, req: BridgeRequest) -> Result<BridgeResponse, ClientError> {
        let mut guard = self.bridge.lock().await;

        // Lazy connect
        if guard.is_none() {
            let socket_path = std::env::var("HOLE_BRIDGE_SOCKET")
                .ok()
                .map(PathBuf::from)
                .unwrap_or_else(hole_common::protocol::default_bridge_socket_path);
            let connect_result = BridgeClient::connect(&socket_path).await;

            match connect_result {
                Ok(client) => *guard = Some(client),
                Err(e) => {
                    warn!(error = %e, "failed to connect to bridge");
                    return Err(e);
                }
            }
        }

        // Send request
        match guard
            .as_mut()
            .expect("guaranteed Some after lazy-connect block")
            .send(req)
            .await
        {
            Ok(resp) => Ok(resp),
            Err(e) => {
                // Connection broken — clear so next call reconnects
                warn!(error = %e, "bridge communication error, will reconnect");
                *guard = None;
                Err(e)
            }
        }
    }
}
