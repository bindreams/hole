//! Garter-based plugin lifecycle management.
//!
//! Replaces shadowsocks-service's built-in `PluginConfig` spawning with
//! Garter's `BinaryPlugin` + `ChainRunner`, giving us structured log
//! capture, SIP003u-compliant graceful shutdown, and future chain
//! composition support.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use super::ProxyError;

/// Timeout for the plugin readiness probe (TCP connect polling).
const READINESS_TIMEOUT: Duration = Duration::from_secs(30);

/// A running plugin chain managed by Garter.
///
/// Owns the tokio task running the chain and a cancellation token for
/// graceful shutdown. Drop cancels the token (SIP003u: SIGTERM on Unix,
/// CTRL_BREAK on Windows, 5s drain timeout) and aborts the task as a
/// safety net.
pub struct PluginChain {
    #[allow(dead_code)]
    handle: tokio::task::JoinHandle<garter::Result<()>>,
    cancel: CancellationToken,
    local_addr: SocketAddr,
}

impl std::fmt::Debug for PluginChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginChain")
            .field("local_addr", &self.local_addr)
            .field("cancelled", &self.cancel.is_cancelled())
            .finish()
    }
}

impl PluginChain {
    /// The confirmed local address where the plugin chain is listening.
    /// ss-service should connect here instead of the real server.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for PluginChain {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.handle.abort();
    }
}

/// Start a plugin chain with a single binary plugin.
///
/// 1. Allocates an ephemeral local port for the chain.
/// 2. Spawns the plugin via Garter's `BinaryPlugin` + `ChainRunner`.
/// 3. Waits for the plugin to become ready (TCP connect probe).
/// 4. Returns a `PluginChain` with the confirmed local address.
///
/// The plugin's stdout/stderr are captured by Garter as tracing events
/// (info/warn) — they flow through the ambient tracing subscriber
/// automatically.
pub async fn start_plugin_chain(
    plugin_path: &str,
    plugin_opts: Option<&str>,
    server_host: &str,
    server_port: u16,
) -> Result<PluginChain, ProxyError> {
    let plugin = garter::BinaryPlugin::new(plugin_path, plugin_opts);
    let cancel = CancellationToken::new();
    let (ready_tx, ready_rx) = oneshot::channel();

    // Allocate ephemeral port for the chain's local listener.
    let local_addr = garter::chain::allocate_ports(1)
        .map_err(|e| ProxyError::Plugin(format!("port allocation failed: {e}")))?
        .into_iter()
        .next()
        .expect("allocate_ports(1) returns exactly 1 port");

    let env = garter::PluginEnv {
        local_host: local_addr.ip(),
        local_port: local_addr.port(),
        remote_host: server_host.to_string(),
        remote_port: server_port,
        plugin_options: plugin_opts.map(String::from),
    };

    let runner = garter::ChainRunner::new()
        .add(Box::new(plugin))
        .cancel_token(cancel.clone())
        .on_ready(ready_tx);

    let handle = tokio::spawn(async move { runner.run(env).await });

    // Wait for the plugin to bind its local port.
    let local_addr = tokio::time::timeout(READINESS_TIMEOUT, ready_rx)
        .await
        .map_err(|_| ProxyError::Plugin("plugin did not become ready within 30s".into()))?
        .map_err(|_| ProxyError::Plugin("plugin exited before becoming ready".into()))?;

    Ok(PluginChain {
        handle,
        cancel,
        local_addr,
    })
}

#[cfg(test)]
#[path = "plugin_tests.rs"]
mod plugin_tests;
