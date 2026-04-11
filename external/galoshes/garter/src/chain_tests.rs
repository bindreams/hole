use std::net::SocketAddr;

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::chain::{allocate_ports, ChainRunner};
use crate::plugin::ChainPlugin;

// Port allocation tests =====

#[skuld::test]
fn allocate_zero_ports() {
    let ports = allocate_ports(0).unwrap();
    assert!(ports.is_empty());
}

#[skuld::test]
fn allocate_one_port() {
    let ports = allocate_ports(1).unwrap();
    assert_eq!(ports.len(), 1);
    assert!(ports[0].port() > 0);
    assert_eq!(ports[0].ip(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
}

#[skuld::test]
fn allocate_multiple_ports_are_unique() {
    let ports = allocate_ports(5).unwrap();
    assert_eq!(ports.len(), 5);
    let unique: std::collections::HashSet<u16> = ports.iter().map(|a| a.port()).collect();
    assert_eq!(unique.len(), 5, "all allocated ports should be unique");
}

// Test helpers =====

fn test_env() -> crate::sip003::PluginEnv {
    crate::sip003::PluginEnv {
        local_host: "127.0.0.1".parse().unwrap(),
        local_port: 0, // will be overridden by allocate_ports
        remote_host: "127.0.0.1".into(),
        remote_port: 20000,
        plugin_options: None,
    }
}

/// Plugin that exits immediately with Ok(()).
struct InstantPlugin {
    name: String,
}

#[async_trait::async_trait]
impl ChainPlugin for InstantPlugin {
    fn name(&self) -> &str {
        &self.name
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

/// Plugin that binds a TCP listener and waits for shutdown.
struct ListeningPlugin {
    name: String,
}

#[async_trait::async_trait]
impl ChainPlugin for ListeningPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(
        self: Box<Self>,
        local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
    ) -> crate::Result<()> {
        let _listener = tokio::net::TcpListener::bind(local).await?;
        shutdown.cancelled().await;
        Ok(())
    }
}

/// Plugin that exits immediately with an error.
struct FailingPlugin;

#[async_trait::async_trait]
impl ChainPlugin for FailingPlugin {
    fn name(&self) -> &str {
        "failing"
    }

    async fn run(
        self: Box<Self>,
        _local: SocketAddr,
        _remote: SocketAddr,
        _shutdown: CancellationToken,
    ) -> crate::Result<()> {
        Err(crate::Error::PluginExit {
            name: "failing".into(),
            code: 1,
        })
    }
}

// ChainRunner basic tests =====

#[skuld::test]
async fn chain_runner_single_plugin() {
    let runner = ChainRunner::new().add(Box::new(InstantPlugin { name: "test".into() }));
    let mut env = test_env();
    env.local_port = 10000;
    let result = runner.run(env).await;
    assert!(result.is_ok());
}

#[skuld::test]
async fn chain_runner_multiple_plugins() {
    let runner = ChainRunner::new()
        .add(Box::new(InstantPlugin { name: "first".into() }))
        .add(Box::new(InstantPlugin { name: "second".into() }))
        .add(Box::new(InstantPlugin { name: "third".into() }));

    let mut env = test_env();
    env.local_port = 10000;
    let result = runner.run(env).await;
    assert!(result.is_ok());
}

// Readiness tests =====

#[skuld::test]
async fn on_ready_fires_with_local_addr() {
    let (tx, rx) = oneshot::channel();

    let runner = ChainRunner::new()
        .add(Box::new(ListeningPlugin {
            name: "listener".into(),
        }))
        .on_ready(tx);

    let mut env = test_env();
    // Use an ephemeral port so the plugin can actually bind.
    let addr = allocate_ports(1).unwrap().pop().unwrap();
    env.local_port = addr.port();

    let handle = tokio::spawn(runner.run(env));

    // rx should fire with the local address once the plugin is listening.
    let ready_addr = tokio::time::timeout(std::time::Duration::from_secs(5), rx)
        .await
        .expect("timed out waiting for readiness")
        .expect("ready_tx was dropped without sending");

    assert_eq!(ready_addr.port(), addr.port());

    // Clean up: abort the chain (it's waiting for shutdown).
    handle.abort();
}

#[skuld::test]
async fn on_ready_dropped_on_plugin_failure() {
    let (tx, rx) = oneshot::channel();

    let runner = ChainRunner::new().add(Box::new(FailingPlugin)).on_ready(tx);

    let mut env = test_env();
    env.local_port = 10000;

    let handle = tokio::spawn(runner.run(env));

    // The plugin fails immediately, so ready_tx is dropped → rx gets RecvError.
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), rx)
        .await
        .expect("timed out waiting for readiness result");

    assert!(
        result.is_err(),
        "rx should get RecvError when plugin fails before ready"
    );

    // The chain should have returned an error.
    let chain_result = handle.await.unwrap();
    assert!(chain_result.is_err());
}

// External cancellation tests =====

#[skuld::test]
async fn cancel_token_triggers_graceful_shutdown() {
    let cancel = CancellationToken::new();
    let (ready_tx, ready_rx) = oneshot::channel();

    let runner = ChainRunner::new()
        .add(Box::new(ListeningPlugin {
            name: "listener".into(),
        }))
        .cancel_token(cancel.clone())
        .on_ready(ready_tx);

    let mut env = test_env();
    let addr = allocate_ports(1).unwrap().pop().unwrap();
    env.local_port = addr.port();

    let handle = tokio::spawn(runner.run(env));

    // Wait for the plugin to actually bind (no sleep race).
    ready_rx.await.expect("plugin should become ready");

    // Cancel externally.
    cancel.cancel();

    // The chain should exit cleanly.
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
        .await
        .expect("timed out waiting for chain to exit")
        .unwrap();

    assert!(result.is_ok(), "chain should exit Ok on external cancellation");
}
