//! TapPlugin behavioral tests.
//!
//! Tests use stub `ChainPlugin` impls (defined locally per scenario) that
//! bind a TCP listener on `local` and exercise a specific failure mode
//! the tap should classify. The tap forwards inbound connections via an
//! internal port to the stub, so the tests assert on the structured
//! tracing fields the tap emits on close: `bytes_to_plugin`,
//! `bytes_from_plugin`, `ttfb_ms`, `close_kind`.
//!
//! Subscriber capture goes through
//! [`crate::tracing_test::set_default_in_current_thread`], which enforces
//! the current-thread tokio runtime invariant — see
//! [bindreams/hole#302](https://github.com/bindreams/hole/issues/302).
//! `#[skuld::test] async fn` builds a current-thread runtime by default.
//!
//! `run_with_tap` takes the tap's public address from the `ready` channel
//! (port 0); a start failure panics with `run()`'s result.
//!
//! Three waits remain unbounded in-process: the "tap closed" line,
//! `client_body`, and the `plugin_handle.await` after `shutdown.cancel()`
//! (the only park of
//! `shutdown_cancels_in_flight_connection_without_panic`). Each waits on a
//! task this test spawns and controls, not an out-of-process op, so
//! CONTRIBUTING.md's no-synchronizing-via-time rule does not sanction a
//! per-await `tokio::time::timeout` (that exception is scoped to a remote or
//! child-process op that might never succeed). The close wait is raced
//! against the plugin task, so a tap that exits first fails the test. The
//! rest are bounded at the nextest-config level: `.config/nextest.toml`'s
//! override names every test in this file that calls `run_with_tap` or
//! `shutdown_cancels_in_flight_connection_without_panic` -- the same
//! `slow-timeout`/`terminate-after` mechanism as the `tun-engine` driver
//! tests, for the identical reason: the waits have no happens-before edge to
//! bound them any other way.

// `CancellationToken::new` is the cancel-test harness root; module-level
// allow per the hole workspace clippy.toml's "Bridge cancellation contract"
// sanctioned-test-file exception.
#![allow(clippy::disallowed_methods)]

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::counting::CountingStream;
use crate::plugin::ChainPlugin;
use crate::tap::TapPlugin;
use crate::test_utils::WaitableWriter;
use crate::tracing_test::set_default_in_current_thread;

// Subscriber capture ==================================================================================================

fn make_subscriber() -> (impl tracing::Subscriber + Send + Sync, WaitableWriter) {
    let writer = WaitableWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .with_target(true)
        .finish();
    (subscriber, writer)
}

// Stubs ===============================================================================================================

/// Test plugin that binds `local` and runs one of several behaviors per
/// accepted TCP connection.
struct StubPlugin {
    behavior: Behavior,
}

#[derive(Clone, Copy)]
enum Behavior {
    /// Read N bytes, echo them back, then close.
    Echo { read_bytes: usize },
    /// Accept and immediately drop the connection (no bytes either way).
    SilentDrop,
    /// Set SO_LINGER=0 and drop — sends RST instead of FIN. Cross-platform via socket2.
    Reset,
    /// Read N bytes, sleep, close without writing (the #248 shape).
    SilentAfterRead { read_bytes: usize, delay: Duration },
}

#[async_trait::async_trait]
impl ChainPlugin for StubPlugin {
    fn name(&self) -> &str {
        "stub"
    }

    async fn run(
        self: Box<Self>,
        local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
        ready: tokio::sync::oneshot::Sender<Result<crate::sitrep::PluginReady, crate::sitrep::StartError>>,
    ) -> crate::Result<()> {
        let listener = TcpListener::bind(local)
            .await
            .map_err(|e| crate::Error::Chain(format!("stub bind {local}: {e}")))?;
        let actual = listener.local_addr().unwrap_or(local);
        let _ = ready.send(Ok(crate::sitrep::PluginReady {
            listen: actual,
            transports: crate::sitrep::Transports::TCP,
        }));
        let behavior = self.behavior;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return Ok(()),
                accept = listener.accept() => match accept {
                    Ok((stream, _peer)) => {
                        tokio::spawn(handle_stub_conn(stream, behavior));
                    }
                    Err(_) => return Ok(()),
                }
            }
        }
    }
}

async fn handle_stub_conn(mut stream: TcpStream, behavior: Behavior) {
    match behavior {
        Behavior::Echo { read_bytes } => {
            let mut buf = vec![0u8; read_bytes];
            if stream.read_exact(&mut buf).await.is_ok() {
                let _ = stream.write_all(&buf).await;
                let _ = stream.flush().await;
                let _ = stream.shutdown().await;
            }
        }
        Behavior::SilentDrop => {
            drop(stream);
        }
        Behavior::Reset => {
            // SO_LINGER=0 + drop → RST. Use socket2 to flip the option.
            let std_stream: std::net::TcpStream = stream.into_std().expect("into_std");
            let socket = socket2::Socket::from(std_stream);
            let _ = socket.set_linger(Some(Duration::ZERO));
            drop(socket);
        }
        Behavior::SilentAfterRead { read_bytes, delay } => {
            let mut buf = vec![0u8; read_bytes];
            if stream.read_exact(&mut buf).await.is_ok() {
                tokio::time::sleep(delay).await;
                drop(stream);
            }
        }
    }
}

fn unused_remote() -> SocketAddr {
    // The stubs ignore `remote`; any valid address works.
    "127.0.0.1:1".parse().unwrap()
}

// Test runner =========================================================================================================

/// Run a test scenario: spawn the tap-wrapped plugin, run `client_body`,
/// then cancel shutdown and await the plugin to exit. Returns the
/// captured subscriber output.
async fn run_with_tap<F, Fut>(behavior: Behavior, client_body: F) -> String
where
    F: FnOnce(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let (subscriber, writer) = make_subscriber();
    let _g = set_default_in_current_thread(subscriber);

    let remote = unused_remote();
    let shutdown = CancellationToken::new();
    let inner = Box::new(StubPlugin { behavior }) as Box<dyn ChainPlugin>;
    let tap = Box::new(TapPlugin::wrap(inner));

    let closed_rx = writer.wait_for("plugin tap: closed");

    // Port 0: the tap reports the address it bound via `ready`.
    let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let plugin_shutdown = shutdown.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let mut plugin_handle = tokio::spawn(async move { tap.run(local, remote, plugin_shutdown, ready_tx).await });

    // Every exit path of `run` either sends on `ready` or drops it, so this
    // resolves on a start failure too.
    let local = match ready_rx.await {
        Ok(Ok(ready)) => ready.listen,
        other => panic!(
            "tap did not become ready: {other:?}; run() returned {:?}\nlog:\n{}",
            plugin_handle.await,
            writer.snapshot()
        ),
    };

    client_body(local).await;

    // The close line comes from a task inside the tap.
    let closed = tokio::task::spawn_blocking(move || closed_rx.recv());
    tokio::select! {
        r = closed => r.unwrap().expect("tap never logged close"),
        j = &mut plugin_handle => panic!("tap exited before logging close: {j:?}\nlog:\n{}", writer.snapshot()),
    }

    shutdown.cancel();
    plugin_handle
        .await
        .expect("tap task panicked")
        .expect("tap returned error");

    writer.snapshot()
}

// Tests ===============================================================================================================

#[skuld::test]
async fn echo_records_round_trip_byte_counts_and_ttfb() {
    let captured = run_with_tap(Behavior::Echo { read_bytes: 5 }, |local| async move {
        let mut s = TcpStream::connect(local).await.unwrap();
        s.write_all(b"hello").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        let _ = s.shutdown().await;
    })
    .await;

    assert!(
        captured.contains("plugin tap: accepted"),
        "missing accept line:\n{captured}"
    );
    assert!(
        captured.contains("plugin tap: closed"),
        "missing close line:\n{captured}"
    );
    assert!(
        captured.contains("bytes_to_plugin=5"),
        "want bytes_to_plugin=5:\n{captured}"
    );
    assert!(
        captured.contains("bytes_from_plugin=5"),
        "want bytes_from_plugin=5:\n{captured}"
    );
    assert!(
        captured.contains("close_kind=graceful"),
        "want close_kind=graceful:\n{captured}"
    );
    assert!(
        captured.contains("ttfb_ms=Some("),
        "ttfb_ms must be Some(_) when bytes flowed back:\n{captured}"
    );
}

#[skuld::test]
async fn silent_drop_records_zero_bytes_and_no_ttfb() {
    let captured = run_with_tap(Behavior::SilentDrop, |local| async move {
        let mut s = TcpStream::connect(local).await.unwrap();
        // No writes — let the stub close on us.
        let mut buf = [0u8; 1];
        let _ = s.read(&mut buf).await; // returns 0 (EOF)
    })
    .await;

    assert!(
        captured.contains("plugin tap: closed"),
        "missing close line:\n{captured}"
    );
    assert!(
        captured.contains("bytes_to_plugin=0") && captured.contains("bytes_from_plugin=0"),
        "expected zero byte counts:\n{captured}"
    );
    assert!(
        captured.contains("ttfb_ms=None"),
        "ttfb_ms must be None when no upstream bytes ever read:\n{captured}"
    );
}

#[skuld::test]
async fn silent_after_read_matches_248_shape() {
    // The #248 shape: client writes some bytes, upstream reads them,
    // upstream NEVER replies, then closes. Tap must record bytes_to=N,
    // bytes_from=0, ttfb=None.
    let captured = run_with_tap(
        Behavior::SilentAfterRead {
            read_bytes: 16,
            delay: Duration::from_millis(50),
        },
        |local| async move {
            let mut s = TcpStream::connect(local).await.unwrap();
            s.write_all(b"silent-after-rd1").await.unwrap();
            s.flush().await.unwrap();
            let mut buf = [0u8; 1];
            let _ = s.read(&mut buf).await; // returns 0 once stub drops
        },
    )
    .await;

    assert!(
        captured.contains("plugin tap: closed"),
        "missing close line:\n{captured}"
    );
    assert!(
        captured.contains("bytes_to_plugin=16"),
        "want bytes_to_plugin=16:\n{captured}"
    );
    assert!(
        captured.contains("bytes_from_plugin=0"),
        "want bytes_from_plugin=0:\n{captured}"
    );
    assert!(
        captured.contains("ttfb_ms=None"),
        "ttfb_ms must be None for the #248 silent-then-FIN shape:\n{captured}"
    );
}

#[skuld::test]
async fn rst_close_classified_as_rst_with_os_errno() {
    let captured = run_with_tap(Behavior::Reset, |local| async move {
        let mut s = TcpStream::connect(local).await.unwrap();
        // Touch the connection so the kernel actually accepts it before
        // SO_LINGER+drop fires the RST.
        let _ = s.write_all(b"x").await;
        let _ = s.flush().await;
        // Drain whatever the kernel surfaces (likely ConnectionReset).
        let mut buf = [0u8; 1];
        let _ = s.read(&mut buf).await;
    })
    .await;

    assert!(
        captured.contains("plugin tap: closed"),
        "missing close line:\n{captured}"
    );
    let close_ok = captured.contains("close_kind=rst") || captured.contains("close_kind=broken_pipe");
    assert!(
        close_ok,
        "expected close_kind=rst (or broken_pipe on platforms that surface RST as such):\n{captured}"
    );
    // os_errno is platform-dependent; just assert it's recorded as Some(_).
    assert!(
        captured.contains("os_errno=Some("),
        "os_errno must be Some(_) for RST-class close:\n{captured}"
    );
}

#[skuld::test]
async fn shutdown_cancels_in_flight_connection_without_panic() {
    let (subscriber, _writer) = make_subscriber();
    let _g = set_default_in_current_thread(subscriber);

    let remote = unused_remote();
    let shutdown = CancellationToken::new();

    // Echo plugin so the connection stays open while client holds it.
    let inner = Box::new(StubPlugin {
        behavior: Behavior::Echo { read_bytes: 4096 },
    }) as Box<dyn ChainPlugin>;
    let tap = Box::new(TapPlugin::wrap(inner));

    let plugin_shutdown = shutdown.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let plugin_handle = tokio::spawn(async move { tap.run(local, remote, plugin_shutdown, ready_tx).await });

    let local = match ready_rx.await {
        Ok(Ok(ready)) => ready.listen,
        other => panic!(
            "tap did not become ready: {other:?}; run() returned {:?}",
            plugin_handle.await
        ),
    };

    // Open a connection that the echo plugin will hold (waiting on
    // read_exact for 4096 bytes — we send only 1).
    let _client = TcpStream::connect(local).await.unwrap();

    // Cancel shutdown and await the plugin exit.
    shutdown.cancel();
    plugin_handle
        .await
        .expect("plugin task panicked")
        .expect("plugin returned error");
}

#[skuld::test]
async fn cross_check_inbound_and_upstream_counters_match() {
    // Sanity invariant: on a clean roundtrip, inbound.read == upstream.written
    // and inbound.written == upstream.read. Catches future tap regressions
    // where one direction's counter wires up wrong.
    let captured = run_with_tap(Behavior::Echo { read_bytes: 7 }, |local| async move {
        let mut s = TcpStream::connect(local).await.unwrap();
        s.write_all(b"abcdefg").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 7];
        s.read_exact(&mut buf).await.unwrap();
        let _ = s.shutdown().await;
    })
    .await;

    assert!(captured.contains("bytes_to_plugin=7"), "to_plugin=7:\n{captured}");
    assert!(captured.contains("bytes_from_plugin=7"), "from_plugin=7:\n{captured}");
    assert!(captured.contains("bytes_inbound_read=7"), "inbound_read=7:\n{captured}");
    assert!(
        captured.contains("bytes_inbound_written=7"),
        "inbound_written=7:\n{captured}"
    );
}

// CountingStream sanity (delegated to its own test module, kept here as a smoke check).
#[skuld::test]
async fn counting_stream_smoke() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        s.write_all(b"abc").await.unwrap();
        s.flush().await.unwrap();
    });
    let raw = TcpStream::connect(addr).await.unwrap();
    let mut counted = CountingStream::new(raw);
    let counters = counted.counters();
    let mut buf = [0u8; 3];
    counted.read_exact(&mut buf).await.unwrap();
    assert_eq!(counters.read(), 3);
    server.await.unwrap();
}
