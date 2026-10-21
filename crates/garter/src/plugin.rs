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
    /// - `remote`: forward here, to next stage (or SS server). A chain runs a plugin only once the stage it forwards
    ///   to has reported ready.
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
    ///   that task before `run` returns: a sender still held then is read as an
    ///   exit before ready too.
    ///
    /// A start failure (an `Err` sent on `ready`, or `ready` dropped unsent) ends the chain. The runner cancels
    /// `shutdown` at once, so the plugin must return rather than keep running, and reports the failure to the
    /// caller, when [`ChainRunner::on_ready`](crate::ChainRunner::on_ready) is registered, after every plugin's `run`
    /// has returned, so output a plugin relays while it stops comes first; a plugin that ignores `shutdown` is
    /// waited for at most [`drain_timeout`](crate::ChainRunner::drain_timeout). [`ChainRunner::run`](crate::ChainRunner::run)
    /// then returns [`Error::StartFailed`](crate::Error::StartFailed), whatever `run` returned here, `Ok(())` included.
    ///
    /// The one start failure that does not end the chain is `StartError::BindConflict` from a hop the chain gave
    /// an intermediate port, whatever address it names (a tap reports its inner plugin's). The runner cancels that
    /// attempt's `shutdown`, waits for `run` to return, and calls `run` again on a fresh port, as often as it takes
    /// until the chain shuts down. A conflict on the public port is the caller's to retry, so it is reported like any
    /// other failure.
    async fn run(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        shutdown: CancellationToken,
        ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()>;
}
