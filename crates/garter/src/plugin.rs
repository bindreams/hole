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
///
/// A plugin is a description of a hop, not a running one: `run` may be called
/// again after it returned, sequentially, and a return leaves no listener,
/// child or task behind. The chain relies on this to restart one hop alone.
#[async_trait::async_trait]
pub trait ChainPlugin: Send + Sync {
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
    ///   long-lived accept loop, not as the return value. A plugin that hands
    ///   `ready` to a task of its own (a readiness probe) must stop and join
    ///   that task before `run` returns: a sender still held then is not read
    ///   as an exit before ready.
    ///
    /// A start failure (an `Err` sent on `ready`, or `ready` dropped unsent) ends the chain only when the runner
    /// listens for readiness, that is when [`ChainRunner::on_ready`](crate::ChainRunner::on_ready) is registered.
    /// The runner then cancels `shutdown` at once, so the plugin must return rather than keep running, and reports
    /// the failure to the caller after every plugin's `run` has returned, so output a plugin relays while it stops
    /// comes first; a plugin that ignores `shutdown` is waited for at most
    /// [`drain_timeout`](crate::ChainRunner::drain_timeout). Without `on_ready` the runner does not read `ready`: a
    /// plugin that sends `Err` and keeps running leaves the chain up, and only its return ends it.
    async fn run(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        shutdown: CancellationToken,
        ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()>;
}
