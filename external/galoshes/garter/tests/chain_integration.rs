use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use garter::{BinaryPlugin, ChainRunner, PluginEnv};

fn mock_plugin_path() -> PathBuf {
    // Build mock-plugin
    let status = std::process::Command::new("cargo")
        .args(["build", "-p", "mock-plugin"])
        .status()
        .expect("failed to build mock-plugin");
    assert!(status.success());

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // garter/ -> workspace root
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

/// Spin up an echo server and a chain of 2 mock plugins, send data through,
/// verify it arrives.
#[skuld::test]
async fn two_plugin_chain_relays_data() {
    let mock_path = mock_plugin_path();

    // Start an echo server as the final destination
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();

    let echo_task = tokio::spawn(async move {
        if let Ok((stream, _)) = echo_listener.accept().await {
            let (mut reader, mut writer) = tokio::io::split(stream);
            let _ = tokio::io::copy(&mut reader, &mut writer).await;
        }
    });

    // Allocate a port for the chain's local side
    let chain_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let chain_local = chain_listener.local_addr().unwrap();
    drop(chain_listener);

    // Build chain: mock-plugin-1 -> mock-plugin-2
    let runner = ChainRunner::new()
        .add(Box::new(BinaryPlugin::new(&mock_path, None)))
        .add(Box::new(BinaryPlugin::new(&mock_path, None)))
        .drain_timeout(Duration::from_secs(3));

    let env = PluginEnv {
        local_host: chain_local.ip(),
        local_port: chain_local.port(),
        remote_host: echo_addr.ip().to_string(),
        remote_port: echo_addr.port(),
        plugin_options: None,
    };

    let chain_task = tokio::spawn(async move { runner.run(env).await });

    // Wait for the chain to start accepting connections
    let mut client = {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match TcpStream::connect(chain_local).await {
                Ok(stream) => break stream,
                Err(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => panic!("chain did not start accepting within 5s: {e}"),
            }
        }
    };
    client.write_all(b"hello through chain").await.unwrap();

    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();

    assert_eq!(&buf[..n], b"hello through chain");

    // Shut down -- drop client and abort echo server
    drop(client);
    echo_task.abort();

    // Chain plugins loop on accept() indefinitely. When the runtime is
    // dropped (end of block_on), tasks are cancelled and kill_on_drop
    // terminates the child processes.
    let _ = tokio::time::timeout(Duration::from_secs(10), chain_task).await;
}

fn main() {
    skuld::run_all();
}
