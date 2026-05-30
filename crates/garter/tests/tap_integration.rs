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

use std::path::PathBuf;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use garter::test_utils::WaitableWriter;
use garter::tracing_test::set_default_in_current_thread;
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
    // Install a subscriber backed by `WaitableWriter` so the test can
    // park on the tap's "plugin tap: ready" event without polling.
    let writer = WaitableWriter::new();
    let ready_rx = writer.wait_for("plugin tap: ready");
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .finish();
    let _g = set_default_in_current_thread(subscriber);

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
    // This test synchronizes on the "plugin tap: ready" tracing event, not
    // the readiness channel; a throwaway oneshot satisfies the new param.
    let (ready_tx, _ready_rx) = tokio::sync::oneshot::channel();
    let plugin_handle = tokio::spawn(async move { tap.run(chain_local, echo_addr, plugin_shutdown, ready_tx).await });

    // Park until tap signals ready via the tracing event the
    // `WaitableWriter` is watching for. Deterministic, no polling.
    // See bindreams/hole#383.
    tokio::task::spawn_blocking(move || ready_rx.recv().expect("tap never signaled ready"))
        .await
        .unwrap();
    let mut client = TcpStream::connect(chain_local)
        .await
        .expect("connect to tap public listener");

    client.write_all(b"hello through tap+mock").await.unwrap();
    let mut buf = [0u8; 1024];
    let n = client.read(&mut buf).await.expect("read from tap returned error");
    assert_eq!(&buf[..n], b"hello through tap+mock");

    drop(client);
    echo_task.abort();
    shutdown.cancel();
    // Await the plugin task; if it hangs, the test framework's timeout
    // surfaces a clear "test took too long" failure.
    let _ = plugin_handle.await;
}

// Install the workspace test subscriber + panic hook. See
// `crates/test-observability/` and bindreams/hole#301.
hole_test_observability::register!();

fn main() {
    skuld::run_all();
}
