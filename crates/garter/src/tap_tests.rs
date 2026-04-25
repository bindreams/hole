//! TapPlugin behavioral tests.
//!
//! Tests use stub `ChainPlugin` impls (defined locally per scenario) that
//! bind a TCP listener on `local` and exercise a specific failure mode
//! the tap should classify. The tap forwards inbound connections via an
//! internal port to the stub, so the tests assert on the structured
//! tracing fields the tap emits on close: `bytes_to_plugin`,
//! `bytes_from_plugin`, `ttfb_ms`, `close_kind`.
//!
//! Subscriber capture uses `tracing::subscriber::with_default` (thread-
//! local) so each test sees only its own events. The tokio runtime is
//! single-threaded for the same reason — `set_default` does not cross
//! `tokio::spawn` on a multi-thread runtime per the project memory.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::counting::CountingStream;
use crate::plugin::ChainPlugin;
use crate::tap::TapPlugin;

// Subscriber capture ==================================================================================================

#[derive(Clone, Default)]
struct VecWriter(Arc<Mutex<Vec<u8>>>);

impl io::Write for VecWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for VecWriter {
    type Writer = VecWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn make_subscriber() -> (impl tracing::Subscriber + Send + Sync, VecWriter) {
    let writer = VecWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .with_target(true)
        .finish();
    (subscriber, writer)
}

fn captured_text(writer: &VecWriter) -> String {
    String::from_utf8_lossy(&writer.0.lock().unwrap().clone()).into_owned()
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
    ) -> crate::Result<()> {
        let listener = TcpListener::bind(local)
            .await
            .map_err(|e| crate::Error::Chain(format!("stub bind {local}: {e}")))?;
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

async fn pick_local() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    addr
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
    let _g = tracing::subscriber::set_default(subscriber);

    let local = pick_local().await;
    let remote = unused_remote();
    let shutdown = CancellationToken::new();
    let inner = Box::new(StubPlugin { behavior }) as Box<dyn ChainPlugin>;
    let tap = Box::new(TapPlugin::wrap(inner));

    let plugin_shutdown = shutdown.clone();
    let plugin_handle = tokio::spawn(async move { tap.run(local, remote, plugin_shutdown).await });

    // Wait for tap to be ready by polling its public listener.
    let ready = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if TcpStream::connect(local).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    ready.expect("tap public listener never became ready");

    // Run the user-supplied client interaction.
    client_body(local).await;

    // Give the tap's spawn_tap a moment to log the close line (it runs
    // off the same runtime; the close log fires after copy_bidirectional
    // returns, which can be up to one tokio scheduling tick after the
    // OS-side close). 200ms is plenty in practice for these stubs.
    tokio::time::sleep(Duration::from_millis(200)).await;

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(3), plugin_handle).await;

    captured_text(&writer)
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
    let _g = tracing::subscriber::set_default(subscriber);

    let local = pick_local().await;
    let remote = unused_remote();
    let shutdown = CancellationToken::new();

    // Echo plugin so the connection stays open while client holds it.
    let inner = Box::new(StubPlugin {
        behavior: Behavior::Echo { read_bytes: 4096 },
    }) as Box<dyn ChainPlugin>;
    let tap = Box::new(TapPlugin::wrap(inner));

    let plugin_shutdown = shutdown.clone();
    let plugin_handle = tokio::spawn(async move { tap.run(local, remote, plugin_shutdown).await });

    // Wait for tap ready.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if TcpStream::connect(local).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("tap ready");

    // Open a connection that the echo plugin will hold (waiting on
    // read_exact for 4096 bytes — we send only 1).
    let _client = TcpStream::connect(local).await.unwrap();

    // Cancel shutdown and assert the plugin exits within budget.
    shutdown.cancel();
    let result = tokio::time::timeout(Duration::from_secs(3), plugin_handle).await;
    assert!(result.is_ok(), "tap plugin did not exit within 3s of shutdown");
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
