//! Long-lived HTTP/1.0 sentinel for the e2e proxy tests.
//!
//! [`HttpTarget`] owns its own tokio runtime and acts as "the public internet"
//! for the `DistHarness`-backed bridge tests. It binds either the host's
//! primary IPv4 (so TUN routing actually catches the traffic) or `[::1]` (for
//! the IPv6 axis).
//!
//! The single-shot [`plugin_e2e::sentinel::start_fake_sentinel`] is the
//! plugin-side counterpart (used by `server_test_tests` and the relocated
//! plugin suites); it lives in the shared `plugin-e2e` harness.

use crate::test_support::net_discovery::detect_primary_ipv4;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// What address family / interface the [`HttpTarget`] binds to.
pub(crate) enum TargetBind {
    /// Host's primary non-loopback IPv4 address (discovered via
    /// `default_net` + UDP-connect fallback). Required for TUN tests because
    /// loopback short-circuits routing on both Windows and macOS.
    Ipv4Primary,
    /// `[::1]` IPv6 loopback. IPv6 axis test only.
    Ipv6Loopback,
}

/// Long-lived HTTP/1.0 sentinel that owns its own tokio runtime. Drop sends
/// a graceful shutdown signal and tears down the runtime.
///
/// The body the server returns is [`SENTINEL_BODY`]. Tests assert against
/// the canonical const directly rather than reading a struct field.
pub(crate) struct HttpTarget {
    pub addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    _runtime: tokio::runtime::Runtime,
}

impl Drop for HttpTarget {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        // _runtime drops next, shutting down all spawned tasks.
    }
}

/// The body the HTTP target sends back. Tests assert against this.
pub(crate) const SENTINEL_BODY: &[u8] = b"HOLE-OK\n";
const SENTINEL_RESPONSE: &[u8] = b"HTTP/1.0 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nHOLE-OK\n";

/// Spawn an HTTP/1.0 sentinel server.
///
/// The server uses raw `tokio::TcpListener` rather than hyper because the
/// only response we ever send is a fixed 8-byte sentinel — pulling in a
/// router crate would be overkill. Each accepted connection reads the
/// request line (and any extra bytes already in the kernel buffer), writes
/// the canned response, and closes the socket.
pub(crate) fn start_http_target(bind: TargetBind) -> HttpTarget {
    let runtime = tokio::runtime::Runtime::new().expect("create http_target runtime");

    // Bind synchronously inside block_on so we know the listener address
    // before returning.
    let (listener, addr) = runtime.block_on(async move {
        match bind {
            TargetBind::Ipv4Primary => {
                let primary = detect_primary_ipv4().expect("detect primary IPv4");
                // Bind on 0.0.0.0:0 so we don't need a capability to bind a
                // specific interface IP — but report the primary IP + the
                // chosen port to the caller, since that's what the e2e tests
                // need to send traffic to.
                let listener = TcpListener::bind("0.0.0.0:0").await.expect("bind 0.0.0.0:0");
                let port = listener.local_addr().unwrap().port();
                let addr = SocketAddr::from((primary, port));
                (listener, addr)
            }
            TargetBind::Ipv6Loopback => {
                let listener = TcpListener::bind("[::1]:0").await.expect("bind [::1]:0");
                let addr = listener.local_addr().unwrap();
                (listener, addr)
            }
        }
    });

    let (tx, mut rx) = oneshot::channel();
    runtime.spawn(async move {
        loop {
            tokio::select! {
                _ = &mut rx => return,
                accept = listener.accept() => {
                    if let Ok((sock, _)) = accept {
                        tokio::spawn(handle_connection(sock));
                    }
                }
            }
        }
    });

    HttpTarget {
        addr,
        shutdown: Some(tx),
        _runtime: runtime,
    }
}

async fn handle_connection(mut sock: TcpStream) {
    // Drain request bytes — we don't parse the request, but we want to
    // avoid an RST race when we close. Cap the drain at 4 KiB which fits
    // any sane HTTP request line + headers our test clients will send.
    let mut buf = [0u8; 4096];
    // Best-effort: don't block forever if the client never sends anything.
    let _ = tokio::time::timeout(Duration::from_millis(500), sock.read(&mut buf)).await;
    let _ = sock.write_all(SENTINEL_RESPONSE).await;
    let _ = sock.shutdown().await;
}
