use std::net::SocketAddr;

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::sitrep::{PluginReady, StartError};

/// A plugin in a SIP003u chain.
///
/// Each plugin accepts connections on a local address and forwards
/// (potentially transformed) traffic to a remote address. The plugin
/// owns its runtime: it binds listeners, manages connections, reports
/// readiness, and shuts down when the cancellation token fires.
#[async_trait::async_trait]
pub trait ChainPlugin: Send {
    /// Human-readable name for logging spans.
    fn name(&self) -> &str;

    /// Run the plugin. Blocks until shutdown or fatal error.
    ///
    /// - `local`: bind here, accept from previous stage (or SS client)
    /// - `remote`: forward here, to next stage (or SS server)
    /// - `shutdown`: fires when graceful shutdown is requested
    /// - `ready`: the plugin MUST send exactly one of:
    ///     - `Ok(PluginReady { .. })` once its listener is bound & accepting, OR
    ///     - `Err(StartError)` if it fails to start.
    ///
    ///   If the plugin returns from `run` without sending (e.g. it crashed
    ///   or exited early), dropping `ready` unsent signals the runner to
    ///   synthesize a process-exit failure. Send readiness BEFORE the
    ///   long-lived accept loop, not as the return value.
    async fn run(
        self: Box<Self>,
        local: SocketAddr,
        remote: SocketAddr,
        shutdown: CancellationToken,
        ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()>;
}
