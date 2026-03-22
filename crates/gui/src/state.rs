// Application state management.

use crate::daemon_client::{ClientError, DaemonClient};
use hole_common::config::AppConfig;
use hole_common::protocol::{DaemonRequest, DaemonResponse};
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::warn;

/// Shared application state managed by Tauri.
pub struct AppState {
    pub config_path: PathBuf,
    pub config: Mutex<AppConfig>,
    daemon: tokio::sync::Mutex<Option<DaemonClient>>,
}

impl AppState {
    pub fn new(config_path: PathBuf) -> Self {
        let config = AppConfig::load(&config_path).unwrap_or_default();
        Self {
            config_path,
            config: Mutex::new(config),
            daemon: tokio::sync::Mutex::new(None),
        }
    }

    /// Send a request to the daemon, lazily connecting on first use.
    /// On connection failure, clears the cached client so the next call reconnects.
    pub async fn daemon_send(&self, req: DaemonRequest) -> Result<DaemonResponse, ClientError> {
        let mut guard = self.daemon.lock().await;

        // Lazy connect
        if guard.is_none() {
            let socket_path = hole_common::protocol::default_daemon_socket_path();
            let connect_result = DaemonClient::connect(&socket_path).await;

            match connect_result {
                Ok(client) => *guard = Some(client),
                Err(e) => {
                    warn!(error = %e, "failed to connect to daemon");
                    return Err(e);
                }
            }
        }

        // Send request
        match guard.as_mut().unwrap().send(req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                // Connection broken — clear so next call reconnects
                warn!(error = %e, "daemon communication error, will reconnect");
                *guard = None;
                Err(e)
            }
        }
    }
}
