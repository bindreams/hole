use std::net::SocketAddr;
use tokio_util::sync::CancellationToken;

/// A plugin in a SIP003u chain.
///
/// Each plugin accepts connections on a local address and forwards
/// (potentially transformed) traffic to a remote address. The plugin
/// owns its runtime: it binds listeners, manages connections, and
/// shuts down when the cancellation token fires.
#[async_trait::async_trait]
pub trait ChainPlugin: Send {
    /// Human-readable name for logging spans.
    fn name(&self) -> &str;

    /// Run the plugin. Blocks until shutdown or fatal error.
    ///
    /// - `local`: bind here, accept from previous stage (or SS client)
    /// - `remote`: forward here, to next stage (or SS server)
    /// - `shutdown`: fires when graceful shutdown is requested
    async fn run(
        self: Box<Self>,
        local: SocketAddr,
        remote: SocketAddr,
        shutdown: CancellationToken,
    ) -> crate::Result<()>;
}
