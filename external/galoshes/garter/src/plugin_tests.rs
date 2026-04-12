use crate::plugin::ChainPlugin;
use std::net::SocketAddr;
use tokio_util::sync::CancellationToken;

/// A no-op plugin that immediately returns Ok.
struct NoopPlugin;

#[async_trait::async_trait]
impl ChainPlugin for NoopPlugin {
    fn name(&self) -> &str {
        "noop"
    }

    async fn run(
        self: Box<Self>,
        _local: SocketAddr,
        _remote: SocketAddr,
        _shutdown: CancellationToken,
    ) -> crate::Result<()> {
        Ok(())
    }
}

#[skuld::test]
fn trait_is_object_safe() {
    // This compiles only if ChainPlugin is object-safe.
    let _: Box<dyn ChainPlugin> = Box::new(NoopPlugin);
}

#[skuld::test]
async fn noop_plugin_runs_and_returns() {
    let plugin: Box<dyn ChainPlugin> = Box::new(NoopPlugin);
    assert_eq!(plugin.name(), "noop");

    let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let remote: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let shutdown = CancellationToken::new();

    let result = plugin.run(local, remote, shutdown).await;
    assert!(result.is_ok());
}
