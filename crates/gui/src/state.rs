// Application state management.

use crate::bridge_client::{BridgeClient, ClientError};
use hole_common::config::AppConfig;
use hole_common::protocol::{BridgeRequest, BridgeResponse};
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::warn;

/// Shared application state managed by Tauri.
pub struct AppState {
    pub config_path: PathBuf,
    pub config: Mutex<AppConfig>,
    bridge: tokio::sync::Mutex<Option<BridgeClient>>,
}

impl AppState {
    pub fn new(config_path: PathBuf) -> Self {
        let config = AppConfig::load(&config_path).unwrap_or_default();
        Self {
            config_path,
            config: Mutex::new(config),
            bridge: tokio::sync::Mutex::new(None),
        }
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
