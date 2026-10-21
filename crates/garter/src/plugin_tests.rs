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
        &self,
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

/// A plugin that counts its runs, reports ready on `local`, and returns once stopped.
struct CountingPlugin {
    runs: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl ChainPlugin for CountingPlugin {
    fn name(&self) -> &str {
        "counting"
    }

    async fn run(
        &self,
        local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
        ready: tokio::sync::oneshot::Sender<Result<crate::sitrep::PluginReady, crate::sitrep::StartError>>,
    ) -> crate::Result<()> {
        self.runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let _ = ready.send(Ok(crate::sitrep::PluginReady {
            listen: local,
            transports: crate::sitrep::Transports::TCP,
        }));
        shutdown.cancelled().await;
        Ok(())
    }
}

#[skuld::test]
async fn a_plugin_can_be_run_again_after_it_returned() {
    let plugin = std::sync::Arc::new(CountingPlugin {
        runs: std::sync::atomic::AtomicUsize::new(0),
    });
    let shared: std::sync::Arc<dyn ChainPlugin> = plugin.clone();
    let local: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let remote: SocketAddr = "127.0.0.1:2".parse().unwrap();

    for run in 1..=2 {
        let shutdown = CancellationToken::new();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn({
            let (shared, shutdown) = (shared.clone(), shutdown.clone());
            async move { shared.run(local, remote, shutdown, ready_tx).await }
        });

        let reported = ready_rx
            .await
            .unwrap_or_else(|_| panic!("run {run} dropped `ready` unsent"));
        assert_eq!(
            reported
                .unwrap_or_else(|e| panic!("run {run} failed to start: {e}"))
                .listen,
            local
        );
        shutdown.cancel();
        handle
            .await
            .unwrap()
            .unwrap_or_else(|e| panic!("run {run} returned an error: {e}"));
        assert_eq!(plugin.runs.load(std::sync::atomic::Ordering::SeqCst), run);
    }
}
