// `CancellationToken::new` is the cancel-test harness root; module-level
// allow per the hole workspace clippy.toml's "Bridge cancellation contract"
// sanctioned-test-file exception.
#![allow(clippy::disallowed_methods)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use garter::{BinaryPlugin, ChainRunner, PluginEnv};

fn mock_plugin_path() -> PathBuf {
    // Build mock-plugin
    let status = std::process::Command::new("cargo")
        .args(["build", "-p", "mock-plugin"])
        .status()
        .expect("failed to build mock-plugin");
    assert!(status.success());

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

/// Spin up an echo server and a chain of 2 mock plugins, send data through,
/// verify it arrives.
///
/// Readiness is signaled by both plugins' sitrep `ready` events (both run in
/// `ExpectSitrep` mode); the client connects only after the aggregator collects
/// every `ready`, so the connect can never race ahead of a bound listener.
#[skuld::test]
async fn two_plugin_chain_relays_data() {
    let mock_path = mock_plugin_path();

    // Multi-connection echo server. Under `ExpectSitrep` no probe connects
    // through the chain, so a single accept would suffice — multi-accept is a
    // harmless margin mirroring the server-mode sister test.
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

    // Allocate a port for the chain's local side
    let chain_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let chain_local = chain_listener.local_addr().unwrap();
    drop(chain_listener);

    let (ready_tx, ready_rx) = oneshot::channel();

    // Build chain: mock-plugin-1 -> mock-plugin-2, both in ExpectSitrep
    // mode so readiness comes from each plugin's sitrep `ready` event.
    // `on_ready` fires `Ok(ChainReady)` once EVERY plugin has emitted
    // `ready`.
    let runner = ChainRunner::new()
        .add(Box::new(
            BinaryPlugin::new(&mock_path, None).readiness(garter::binary::ReadinessMode::ExpectSitrep),
        ))
        .add(Box::new(
            BinaryPlugin::new(&mock_path, None).readiness(garter::binary::ReadinessMode::ExpectSitrep),
        ))
        .on_ready(ready_tx)
        .drain_timeout(Duration::from_secs(3));

    let env = PluginEnv {
        local_host: chain_local.ip(),
        local_port: chain_local.port(),
        remote_host: echo_addr.ip().to_string(),
        remote_port: echo_addr.port(),
        plugin_options: None,
    };

    let chain_task = tokio::spawn(async move { runner.run(env).await });

    // Park until the chain signals ready. Deterministic, no poll-retry.
    // Connect to the authoritative bound address reported by the chain.
    let chain_ready = ready_rx
        .await
        .expect("chain never signaled ready")
        .expect("chain should be ready, not a start error");
    let mut client = TcpStream::connect(chain_ready.listen)
        .await
        .expect("connect to chain local");
    client.write_all(b"hello through chain").await.unwrap();

    let mut buf = [0u8; 1024];
    let n = client.read(&mut buf).await.expect("read from chain returned error");

    assert_eq!(&buf[..n], b"hello through chain");

    // Shut down -- drop client and abort echo server
    drop(client);
    echo_task.abort();

    // Plugins loop on accept() forever; abort the chain task to tear them down
    // (kill_on_drop reaps the children).
    chain_task.abort();
    let _ = chain_task.await;
}

/// Verify that pid_sink fires once per binary plugin with a valid PID.
#[skuld::test]
async fn pid_sink_fires_once_per_binary_plugin() {
    let mock_path = mock_plugin_path();
    let pids: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));

    let sink_pids = pids.clone();
    let sink: garter::PidSink = Arc::new(move |pid| {
        sink_pids.lock().unwrap().push(pid);
    });

    // Single-accept echo: this test only awaits `on_ready` and checks
    // pid counts — it does not send any client traffic. The plugins run
    // in the default `Probe` readiness mode, whose self-probe TCP-connects
    // to each plugin's OWN listener (not through the chain to the echo).
    // The sister test (`two_plugin_chain_relays_data`) does send real
    // client traffic.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((stream, _)) = echo_listener.accept().await {
            let (mut r, mut w) = tokio::io::split(stream);
            let _ = tokio::io::copy(&mut r, &mut w).await;
        }
    });

    let chain_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let chain_local = chain_listener.local_addr().unwrap();
    drop(chain_listener);

    let (ready_tx, ready_rx) = oneshot::channel();
    let cancel = tokio_util::sync::CancellationToken::new();

    let runner = ChainRunner::new()
        .add(Box::new(BinaryPlugin::new(&mock_path, None).pid_sink(sink.clone())))
        .add(Box::new(BinaryPlugin::new(&mock_path, None).pid_sink(sink.clone())))
        .on_ready(ready_tx)
        .cancel_token(cancel.clone())
        .drain_timeout(Duration::from_secs(3));

    let env = PluginEnv {
        local_host: chain_local.ip(),
        local_port: chain_local.port(),
        remote_host: echo_addr.ip().to_string(),
        remote_port: echo_addr.port(),
        plugin_options: None,
    };

    let handle = tokio::spawn(async move { runner.run(env).await });

    ready_rx
        .await
        .expect("ready_tx dropped")
        .expect("chain should become ready");

    {
        let recorded = pids.lock().unwrap();
        assert_eq!(recorded.len(), 2, "expected 2 PIDs, got {recorded:?}");
        assert_ne!(recorded[0], recorded[1], "PIDs should be different");
        assert!(recorded[0] > 0);
        assert!(recorded[1] > 0);
    }

    cancel.cancel();
    let _ = handle.await;
}

/// Server-mode counterpart to `two_plugin_chain_relays_data`. In server
/// mode, the chain runs in reverse: an external client connects to the
/// "public" port (SS_REMOTE), data flows through the chain in the
/// opposite direction to the "ssserver-stand-in" echo at SS_LOCAL.
/// Uses the existing `mock-plugin` binary because it is direction-symmetric
/// — bind `local`, connect to `remote` — and works for both modes once
/// `ChainRunner` wires the addresses correctly.
#[skuld::test]
async fn two_plugin_chain_server_mode_relays_data() {
    let mock_path = mock_plugin_path();

    // Echo plays the ssserver role -- runs at SS_LOCAL.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        loop {
            match echo_listener.accept().await {
                Ok((stream, _)) => {
                    tokio::spawn(async move {
                        let (mut r, mut w) = tokio::io::split(stream);
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                    });
                }
                Err(_) => return,
            }
        }
    });

    // Public-facing port (SS_REMOTE): in server mode the chain LISTENS here.
    let public_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_addr = public_listener.local_addr().unwrap();
    drop(public_listener);

    let (ready_tx, ready_rx) = oneshot::channel();

    let runner = ChainRunner::new()
        .mode(garter::Mode::Server)
        .add(Box::new(BinaryPlugin::new(&mock_path, None)))
        .add(Box::new(BinaryPlugin::new(&mock_path, None)))
        .on_ready(ready_tx)
        .drain_timeout(Duration::from_secs(3));

    let env = PluginEnv {
        local_host: echo_addr.ip(), // SS_LOCAL = ssserver-stand-in
        local_port: echo_addr.port(),
        remote_host: public_addr.ip().to_string(), // SS_REMOTE = public port
        remote_port: public_addr.port(),
        plugin_options: None,
    };

    let chain_task = tokio::spawn(async move { runner.run(env).await });

    // on_ready fires when the OUTER plugin has bound the public port.
    let chain_ready = ready_rx
        .await
        .expect("chain never signaled ready")
        .expect("chain should be ready, not a start error");
    assert_eq!(
        chain_ready.listen.port(),
        public_addr.port(),
        "on_ready in Server mode must report SS_REMOTE (the public port)"
    );

    // External client connects to the public port; data round-trips
    // through the chain to the echo and back.
    let mut client = TcpStream::connect(public_addr).await.expect("connect to public");
    client.write_all(b"hello server-mode chain").await.unwrap();

    let mut buf = [0u8; 1024];
    let n = client.read(&mut buf).await.expect("read failed");
    assert_eq!(&buf[..n], b"hello server-mode chain");

    drop(client);
    echo_task.abort();
    chain_task.abort();
    let _ = chain_task.await;
}

/// Tier-2 fallback: a plugin that emits NO sitrep handshake (a pre-sitrep
/// plain forwarder) still readies — readiness comes from the default
/// `Probe` self-probe TCP-connect, not from a sitrep `ready` event. Proves
/// the tier-2 path is live end-to-end (the chain reaches `Ok(ChainReady)`
/// AND relays a payload through to the echo).
#[skuld::test]
async fn tier2_plugin_without_sitrep_still_readies_via_probe() {
    let mock_path = mock_plugin_path();

    // Multi-accept echo. In `Probe` mode the self-probe TCP-connects to the
    // plugin's own listener (not through the chain), so a single accept would
    // suffice — multi-accept is a harmless margin.
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

    let chain_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let chain_local = chain_listener.local_addr().unwrap();
    drop(chain_listener);

    let (ready_tx, ready_rx) = oneshot::channel();

    // Single plugin, NO_SITREP so it emits nothing on stdout, default
    // `Probe` readiness (do NOT set ExpectSitrep) — readiness must come
    // from the self-probe.
    let runner = ChainRunner::new()
        .add(Box::new(
            BinaryPlugin::new(&mock_path, None).env("MOCK_PLUGIN_NO_SITREP", "1"),
        ))
        .on_ready(ready_tx)
        .drain_timeout(Duration::from_secs(3));

    let env = PluginEnv {
        local_host: chain_local.ip(),
        local_port: chain_local.port(),
        remote_host: echo_addr.ip().to_string(),
        remote_port: echo_addr.port(),
        plugin_options: None,
    };

    let chain_task = tokio::spawn(async move { runner.run(env).await });

    let chain_ready = ready_rx
        .await
        .expect("chain never signaled ready")
        .expect("chain should ready via tier-2 probe, not a start error");

    let mut client = TcpStream::connect(chain_ready.listen)
        .await
        .expect("connect to chain local");
    client.write_all(b"hello via probe").await.unwrap();
    let mut buf = [0u8; 1024];
    let n = client.read(&mut buf).await.expect("read from chain returned error");
    assert_eq!(&buf[..n], b"hello via probe");

    drop(client);
    echo_task.abort();
    chain_task.abort();
    let _ = chain_task.await;
}

/// A plugin that emits `fatal` then exits surfaces a typed
/// `StartError::Fatal` on the readiness channel, AND the chain `run()`
/// future returns `Err`. The plugin exits before serving, so no client
/// traffic is exchanged.
#[skuld::test]
async fn fatal_start_error_surfaces_typed() {
    let mock_path = mock_plugin_path();

    // No echo / client needed: the plugin exits before binding.
    let chain_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let chain_local = chain_listener.local_addr().unwrap();
    drop(chain_listener);

    let (ready_tx, ready_rx) = oneshot::channel();

    let runner = ChainRunner::new()
        .add(Box::new(
            BinaryPlugin::new(&mock_path, None)
                .readiness(garter::binary::ReadinessMode::ExpectSitrep)
                .env("MOCK_PLUGIN_FAIL", "fatal"),
        ))
        .on_ready(ready_tx)
        .drain_timeout(Duration::from_secs(3));

    let env = PluginEnv {
        local_host: chain_local.ip(),
        local_port: chain_local.port(),
        remote_host: "127.0.0.1".to_string(),
        remote_port: 9, // discard; never dialed (plugin exits first)
        plugin_options: None,
    };

    let chain_task = tokio::spawn(async move { runner.run(env).await });

    let outcome = ready_rx.await.expect("aggregator should send");
    assert!(
        matches!(outcome, Err(garter::StartError::Fatal { .. })),
        "expected StartError::Fatal, got {outcome:?}"
    );

    // The chain's lifecycle channel independently observes the nonzero exit.
    let run_result = chain_task.await.expect("chain task panicked");
    assert!(run_result.is_err(), "chain run() should return Err on fatal exit");
}

/// A plugin that emits `bind_conflict` then exits surfaces a typed
/// `StartError::BindConflict` with the host-native errno and the
/// allocated listen address.
#[skuld::test]
async fn bind_conflict_start_error_surfaces_typed() {
    let mock_path = mock_plugin_path();

    let chain_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let chain_local = chain_listener.local_addr().unwrap();
    drop(chain_listener);

    let (ready_tx, ready_rx) = oneshot::channel();

    let runner = ChainRunner::new()
        .add(Box::new(
            BinaryPlugin::new(&mock_path, None)
                .readiness(garter::binary::ReadinessMode::ExpectSitrep)
                .env("MOCK_PLUGIN_FAIL", "bind_conflict"),
        ))
        .on_ready(ready_tx)
        .drain_timeout(Duration::from_secs(3));

    let env = PluginEnv {
        local_host: chain_local.ip(),
        local_port: chain_local.port(),
        remote_host: "127.0.0.1".to_string(),
        remote_port: 9,
        plugin_options: None,
    };

    let chain_task = tokio::spawn(async move { runner.run(env).await });

    let outcome = ready_rx.await.expect("aggregator should send");
    match outcome {
        Err(garter::StartError::BindConflict { errno, addr }) => {
            // Host-native errno (10048 / 98 / 48) — assert nonzero rather
            // than a specific foreign constant.
            assert_ne!(errno, 0, "bind_conflict errno should be the host-native value");
            // mock-plugin emits `addr: local_addr`, which in a single-plugin
            // Client chain is the chain's local (public) port.
            assert_eq!(
                addr.port(),
                chain_local.port(),
                "bind_conflict addr should be the allocated chain local port"
            );
        }
        other => panic!("expected StartError::BindConflict, got {other:?}"),
    }

    chain_task.abort();
    let _ = chain_task.await;
}

/// A `ready` event that lists an empty transports set is a SITREP
/// protocol violation; the consumer rejects it as `StartError::Fatal`.
#[skuld::test]
async fn empty_transports_ready_surfaces_fatal() {
    let mock_path = mock_plugin_path();

    let chain_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let chain_local = chain_listener.local_addr().unwrap();
    drop(chain_listener);

    let (ready_tx, ready_rx) = oneshot::channel();

    let runner = ChainRunner::new()
        .add(Box::new(
            BinaryPlugin::new(&mock_path, None)
                .readiness(garter::binary::ReadinessMode::ExpectSitrep)
                .env("MOCK_PLUGIN_EMPTY_TRANSPORTS", "1"),
        ))
        .on_ready(ready_tx)
        .drain_timeout(Duration::from_secs(3));

    let env = PluginEnv {
        local_host: chain_local.ip(),
        local_port: chain_local.port(),
        remote_host: "127.0.0.1".to_string(),
        remote_port: 9,
        plugin_options: None,
    };

    let chain_task = tokio::spawn(async move { runner.run(env).await });

    let outcome = ready_rx.await.expect("aggregator should send");
    assert!(
        matches!(outcome, Err(garter::StartError::Fatal { .. })),
        "empty transports should surface StartError::Fatal, got {outcome:?}"
    );

    chain_task.abort();
    let _ = chain_task.await;
}

/// Version-skew fallback: a plugin advertises an unknown sitrep MAJOR
/// (`sitrep-2.0.0`) in its `hello`. The consumer's protocol gate hands
/// readiness to the tier-2 self-probe (and drains the rest of stdout to
/// EOF — the deadlock-fix path). The plugin still binds + emits `ready`
/// (which is ignored because the handshake never validated), so the
/// probe succeeds and the chain reaches `Ok(ChainReady)`. A client then
/// relays a payload through, proving the probe-fallback readiness is real
/// and not just a fired channel.
///
/// The `MOCK_PLUGIN_BAD_PROTOCOL` knob emits its ignored `ready` with
/// `transports: [tcp, udp]`, while the tier-2 TCP self-probe always
/// reports `transports: [tcp]` only. Asserting `TCP`-only on the
/// `ChainReady` discriminates the source and proves that the bad-major
/// `ready` was not honored.
#[skuld::test]
async fn version_skew_falls_back_to_probe() {
    let mock_path = mock_plugin_path();

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

    let chain_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let chain_local = chain_listener.local_addr().unwrap();
    drop(chain_listener);

    let (ready_tx, ready_rx) = oneshot::channel();

    let runner = ChainRunner::new()
        .add(Box::new(
            BinaryPlugin::new(&mock_path, None)
                .readiness(garter::binary::ReadinessMode::ExpectSitrep)
                .env("MOCK_PLUGIN_BAD_PROTOCOL", "1"),
        ))
        .on_ready(ready_tx)
        .drain_timeout(Duration::from_secs(3));

    let env = PluginEnv {
        local_host: chain_local.ip(),
        local_port: chain_local.port(),
        remote_host: echo_addr.ip().to_string(),
        remote_port: echo_addr.port(),
        plugin_options: None,
    };

    let chain_task = tokio::spawn(async move { runner.run(env).await });

    let chain_ready = ready_rx
        .await
        .expect("chain never signaled ready")
        .expect("unknown-major should fall back to probe, not a start error");

    // The probe-fallback readiness reports Transports::TCP (the tier-2
    // self-probe is TCP-connect only). If the consumer had WRONGLY honored
    // the unknown-major plugin's `ready` (which this knob emits with
    // [tcp,udp]), transports would include UDP. Asserting TCP-only proves
    // readiness came from the probe, not the ignored bad-major ready.
    assert_eq!(
        chain_ready.transports,
        garter::Transports::TCP,
        "version-skew readiness must come from the tier-2 TCP probe, not the ignored bad-major ready"
    );

    let mut client = TcpStream::connect(chain_ready.listen)
        .await
        .expect("connect to chain local");
    client.write_all(b"hello across version skew").await.unwrap();
    let mut buf = [0u8; 1024];
    let n = client.read(&mut buf).await.expect("read from chain returned error");
    assert_eq!(&buf[..n], b"hello across version skew");

    drop(client);
    echo_task.abort();
    chain_task.abort();
    let _ = chain_task.await;
}

// ReadinessMode::Auto tests ===========================================================================================

/// `Auto` readiness with a NON-sitrep, STDOUT-SILENT plugin: `MOCK_PLUGIN_NO_SITREP`
/// prints nothing on stdout and loops on accept() (stdout never closes). `Auto`
/// must ready it via the unconditional concurrent self-probe. (`ExpectSitrep`
/// would hang; a "classify on first stdout line" design would also hang — this
/// is the case that proves the probe is concurrent, not line-gated.)
#[skuld::test]
async fn auto_readies_silent_non_sitrep_plugin_via_probe() {
    let mock_path = mock_plugin_path();

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        loop {
            match echo_listener.accept().await {
                Ok((stream, _)) => {
                    tokio::spawn(async move {
                        let (mut r, mut w) = tokio::io::split(stream);
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                    });
                }
                Err(_) => return,
            }
        }
    });

    let chain_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let chain_local = chain_listener.local_addr().unwrap();
    drop(chain_listener);

    let (ready_tx, ready_rx) = oneshot::channel();
    let runner = ChainRunner::new()
        .add(Box::new(
            BinaryPlugin::new(&mock_path, None)
                .readiness(garter::binary::ReadinessMode::Auto)
                .env("MOCK_PLUGIN_NO_SITREP", "1"),
        ))
        .on_ready(ready_tx)
        .drain_timeout(Duration::from_secs(3));
    let env = PluginEnv {
        local_host: chain_local.ip(),
        local_port: chain_local.port(),
        remote_host: echo_addr.ip().to_string(),
        remote_port: echo_addr.port(),
        plugin_options: None,
    };
    let chain_task = tokio::spawn(async move { runner.run(env).await });

    let chain_ready = ready_rx
        .await
        .expect("chain never signaled ready")
        .expect("Auto must ready a silent non-sitrep plugin via the probe");
    // The probe is TCP-connect only.
    assert_eq!(chain_ready.transports, garter::Transports::TCP);
    let mut client = TcpStream::connect(chain_ready.listen).await.expect("connect");
    client.write_all(b"hello auto probe").await.unwrap();
    let mut buf = [0u8; 1024];
    let n = client.read(&mut buf).await.expect("read");
    assert_eq!(&buf[..n], b"hello auto probe");

    drop(client);
    echo_task.abort();
    chain_task.abort();
    let _ = chain_task.await;
}

/// `Auto` readiness with a sitrep plugin: the chain readies and relays. (Does
/// not assert WHICH path won — sitrep vs probe on success is a best-effort
/// race; both report the same listen address.)
#[skuld::test]
async fn auto_readies_sitrep_plugin() {
    let mock_path = mock_plugin_path();

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        loop {
            match echo_listener.accept().await {
                Ok((stream, _)) => {
                    tokio::spawn(async move {
                        let (mut r, mut w) = tokio::io::split(stream);
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                    });
                }
                Err(_) => return,
            }
        }
    });

    let chain_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let chain_local = chain_listener.local_addr().unwrap();
    drop(chain_listener);

    let (ready_tx, ready_rx) = oneshot::channel();
    let runner = ChainRunner::new()
        .add(Box::new(
            BinaryPlugin::new(&mock_path, None).readiness(garter::binary::ReadinessMode::Auto),
        ))
        .on_ready(ready_tx)
        .drain_timeout(Duration::from_secs(3));
    let env = PluginEnv {
        local_host: chain_local.ip(),
        local_port: chain_local.port(),
        remote_host: echo_addr.ip().to_string(),
        remote_port: echo_addr.port(),
        plugin_options: None,
    };
    let chain_task = tokio::spawn(async move { runner.run(env).await });

    let chain_ready = ready_rx
        .await
        .expect("chain never signaled ready")
        .expect("Auto should ready a sitrep plugin");
    let mut client = TcpStream::connect(chain_ready.listen).await.expect("connect");
    client.write_all(b"hello auto sitrep").await.unwrap();
    let mut buf = [0u8; 1024];
    let n = client.read(&mut buf).await.expect("read");
    assert_eq!(&buf[..n], b"hello auto sitrep");

    drop(client);
    echo_task.abort();
    chain_task.abort();
    let _ = chain_task.await;
}

/// `Auto` surfaces a typed `BindConflict` (the launcher's retry signal). This
/// is DETERMINISTIC under Auto: on a bind conflict the port never binds, so the
/// concurrent probe can never connect — only the sitrep `bind_conflict` fires.
#[skuld::test]
async fn auto_surfaces_bind_conflict() {
    let mock_path = mock_plugin_path();

    let chain_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let chain_local = chain_listener.local_addr().unwrap();
    drop(chain_listener);

    let (ready_tx, ready_rx) = oneshot::channel();
    let runner = ChainRunner::new()
        .add(Box::new(
            BinaryPlugin::new(&mock_path, None)
                .readiness(garter::binary::ReadinessMode::Auto)
                .env("MOCK_PLUGIN_FAIL", "bind_conflict"),
        ))
        .on_ready(ready_tx)
        .drain_timeout(Duration::from_secs(3));
    let env = PluginEnv {
        local_host: chain_local.ip(),
        local_port: chain_local.port(),
        remote_host: "127.0.0.1".to_string(),
        remote_port: 9,
        plugin_options: None,
    };
    let chain_task = tokio::spawn(async move { runner.run(env).await });

    let outcome = ready_rx.await.expect("aggregator should send");
    assert!(
        matches!(outcome, Err(garter::StartError::BindConflict { .. })),
        "Auto must surface BindConflict, got {outcome:?}"
    );

    chain_task.abort();
    let _ = chain_task.await;
}

/// `Auto` surfaces a typed `Fatal` (a plugin that emits `fatal` then exits).
/// Deterministic: the plugin exits before binding, so the probe can never connect.
#[skuld::test]
async fn auto_surfaces_fatal() {
    let mock_path = mock_plugin_path();

    let chain_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let chain_local = chain_listener.local_addr().unwrap();
    drop(chain_listener);

    let (ready_tx, ready_rx) = oneshot::channel();
    let runner = ChainRunner::new()
        .add(Box::new(
            BinaryPlugin::new(&mock_path, None)
                .readiness(garter::binary::ReadinessMode::Auto)
                .env("MOCK_PLUGIN_FAIL", "fatal"),
        ))
        .on_ready(ready_tx)
        .drain_timeout(Duration::from_secs(3));
    let env = PluginEnv {
        local_host: chain_local.ip(),
        local_port: chain_local.port(),
        remote_host: "127.0.0.1".to_string(),
        remote_port: 9,
        plugin_options: None,
    };
    let chain_task = tokio::spawn(async move { runner.run(env).await });

    let outcome = ready_rx.await.expect("aggregator should send");
    assert!(
        matches!(outcome, Err(garter::StartError::Fatal { .. })),
        "Auto must surface Fatal, got {outcome:?}"
    );

    chain_task.abort();
    let _ = chain_task.await;
}

// Install the workspace test subscriber + panic hook. See
// `crates/test-observability/` and bindreams/hole#301.
hole_test_observability::register!();

fn main() {
    skuld::run_all();
}
