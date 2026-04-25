//! Integration test: wrap a real `mock-plugin` subprocess in a `TapPlugin`
//! and confirm bytes round-trip end-to-end. Exists as a smoke-level
//! check that TapPlugin's `inner.run()` handoff works against a
//! `BinaryPlugin` (subprocess) — the unit tests in
//! `crates/garter/src/tap_tests.rs` exercise the tap mechanics against
//! Rust `StubPlugin`s, which is faster but doesn't verify
//! Apache-2.0-process-boundary behavior.

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use garter::{BinaryPlugin, ChainPlugin, TapPlugin};

fn mock_plugin_path() -> PathBuf {
    let status = std::process::Command::new("cargo")
        .args(["build", "-p", "mock-plugin"])
        .status()
        .expect("failed to build mock-plugin");
    assert!(status.success(), "mock-plugin build failed");

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // crates/garter -> crates/
    path.pop(); // crates/ -> workspace root
    path.push("target");
    path.push(if cfg!(debug_assertions) { "debug" } else { "release" });
    path.push(if cfg!(windows) {
        "mock-plugin.exe"
    } else {
        "mock-plugin"
    });
    assert!(path.exists(), "mock-plugin not found at {}", path.display());
    path
}

#[skuld::test]
async fn tap_relays_data_through_binary_plugin_to_echo_server() {
    // Install a subscriber that prints to test stderr so mock-plugin's
    // own stderr (captured by BinaryPlugin and re-emitted as
    // tracing::warn) and the tap's info events are visible when this
    // test is debugged.
    let subscriber = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_test_writer()
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let _g = tracing::subscriber::set_default(subscriber);

    let mock_path = mock_plugin_path();

    // Multi-connection echo server. The TapPlugin's readiness probe
    // (TCP-connect to inner_local) is forwarded through mock-plugin to
    // the echo server, consuming an accept slot before the real client
    // connection arrives. So the echo server must loop to handle every
    // forwarded connection — otherwise the second one (the real client
    // payload) hangs forever.
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

    // Pick a public local for the tap.
    let pick_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let chain_local = pick_listener.local_addr().unwrap();
    drop(pick_listener);

    let inner: Box<dyn ChainPlugin> = Box::new(BinaryPlugin::new(&mock_path, None));
    let tap = Box::new(TapPlugin::wrap(inner));

    let shutdown = CancellationToken::new();
    let plugin_shutdown = shutdown.clone();
    let plugin_handle = tokio::spawn(async move { tap.run(chain_local, echo_addr, plugin_shutdown).await });

    // Wait for tap public listener to come up.
    let mut client = {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            match TcpStream::connect(chain_local).await {
                Ok(s) => break s,
                Err(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => panic!("tap did not start accepting within 10s: {e}"),
            }
        }
    };

    client.write_all(b"hello through tap+mock").await.unwrap();
    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"hello through tap+mock");

    drop(client);
    echo_task.abort();
    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), plugin_handle).await;
}

fn main() {
    skuld::run_all();
}
