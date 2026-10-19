//! Integration test: wrap a real `mock-plugin` subprocess in a `TapPlugin`
//! and confirm bytes round-trip end-to-end. Exists as a smoke-level
//! check that TapPlugin's `inner.run()` handoff works against a
//! `BinaryPlugin` (subprocess) — the unit tests in
//! `crates/garter/src/tap_tests.rs` exercise the tap mechanics against
//! Rust `StubPlugin`s, which is faster but doesn't verify
//! Apache-2.0-process-boundary behavior.

// `CancellationToken::new` is the cancel-test harness root; module-level
// allow per the hole workspace clippy.toml's "Bridge cancellation contract"
// sanctioned-test-file exception.
#![allow(clippy::disallowed_methods)]

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use garter::{BinaryPlugin, ChainPlugin, TapPlugin};

mod common;
use common::mock_plugin_path;

#[skuld::test]
async fn tap_relays_data_through_binary_plugin_to_echo_server() {
    let mock_path = mock_plugin_path();

    // Multi-connection echo server. The tap's readiness probe connects to
    // mock-plugin, which dials the echo on accept, consuming one slot before
    // the real client — so the echo must loop.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        loop {
            match echo_listener.accept().await {
                Ok((stream, _)) => {
                    tokio::spawn(async move {
                        let (mut reader, mut writer) = tokio::io::split(stream);
                        let _ = tokio::io::copy(&mut reader, &mut writer).await;
                    });
                }
                Err(_) => return,
            }
        }
    });

    let chain_local: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    let inner: Box<dyn ChainPlugin> = Box::new(BinaryPlugin::new(&mock_path, None));
    let tap = Box::new(TapPlugin::wrap(inner));

    let shutdown = CancellationToken::new();
    let plugin_shutdown = shutdown.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let plugin_handle = tokio::spawn(async move { tap.run(chain_local, echo_addr, plugin_shutdown, ready_tx).await });

    let chain_local = match ready_rx.await {
        Ok(Ok(ready)) => ready.listen,
        other => panic!(
            "tap did not become ready: {other:?}; run() returned {:?}",
            plugin_handle.await
        ),
    };
    let mut client = TcpStream::connect(chain_local)
        .await
        .expect("connect to tap public listener");

    client.write_all(b"hello through tap+mock").await.unwrap();
    // A relay hop may split the echo, so a single `read` can return a prefix.
    let mut buf = [0u8; b"hello through tap+mock".len()];
    client.read_exact(&mut buf).await.expect("read from tap returned error");
    assert_eq!(&buf, b"hello through tap+mock");

    drop(client);
    echo_task.abort();
    shutdown.cancel();
    plugin_handle
        .await
        .expect("tap task panicked")
        .expect("tap returned error");
}

// Install the workspace test subscriber + panic hook. See
// `crates/test-observability/` and bindreams/hole#301.
hole_test_observability::register!();

fn main() {
    skuld::run_all();
}
