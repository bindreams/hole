// `CancellationToken::new` is the cancel-test harness root; module-level
// allow per the hole workspace clippy.toml's "Bridge cancellation contract"
// sanctioned-test-file exception.
#![allow(clippy::disallowed_methods)]

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
        _ready: tokio::sync::oneshot::Sender<Result<crate::sitrep::PluginReady, crate::sitrep::StartError>>,
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
    let (ready_tx, _ready_rx) = tokio::sync::oneshot::channel();

    let result = plugin.run(local, remote, shutdown, ready_tx).await;
    assert!(result.is_ok());
}
