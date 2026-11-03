//! Long-lived HTTP/1.0 sentinel for the e2e proxy tests.
//!
//! [`HttpTarget`] owns its own tokio runtime and acts as "the public internet"
//! for the `DistHarness`-backed bridge tests. It binds the host's primary IPv4,
//! `127.0.0.1`, or `[::1]` (for the IPv6 axis).
//!
//! None of these addresses reaches `hole-tun`. A target here is what proves
//! host-local networking survives while Full mode is up; for tunnel transit the
//! destination has to be one the host does not hold — see
//! [`crate::test_support::net_discovery::UNOWNED_DSTS`].
//!
//! The single-shot [`plugin_e2e::sentinel::start_fake_sentinel`] is the
//! plugin-side counterpart (used by `server_test_tests` and the relocated
//! plugin suites); it lives in the shared `plugin-e2e` harness.

use crate::test_support::net_discovery::wait_for_primary_ipv4;
use crate::test_support::socks5_client::http_response_body;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// What address family / interface the [`HttpTarget`] binds to.
pub(crate) enum TargetBind {
    /// Host's primary non-loopback IPv4 address (the source the kernel picks
    /// for off-link traffic). The address that stays reachable while Full mode
    /// is up — see `net_discovery`'s module doc for why. Loopback
    /// short-circuits routing the same way.
    Ipv4Primary,
    /// `127.0.0.1`. For SOCKS-only tests: the primary IPv4 can be briefly
    /// unusable on a CI runner whose network is settling.
    Ipv4Loopback,
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
    accepted: Arc<AtomicUsize>,
    shutdown: Option<oneshot::Sender<()>>,
    _runtime: tokio::runtime::Runtime,
}

/// The target's accepted-connection count at one instant, from [`HttpTarget::mark`].
#[derive(Clone, Copy)]
pub(crate) struct AcceptedMark(usize);

impl HttpTarget {
    /// Snapshot the accepted-connection count. Take it before sending the request: the target is
    /// shared by every test in the process, so the cumulative count says nothing about one roundtrip.
    pub(crate) fn mark(&self) -> AcceptedMark {
        AcceptedMark(self.accepted.load(Ordering::Relaxed))
    }

    /// Connections accepted since `since`. Zero after a failed roundtrip means the request never
    /// reached the target; nonzero means it did and the failure is on the way back. Another test
    /// connecting to the same target meanwhile is counted too.
    fn accepted_since(&self, since: AcceptedMark) -> usize {
        self.accepted.load(Ordering::Relaxed).saturating_sub(since.0)
    }

    /// Check `result`, the outcome of a client roundtrip (`what`) to this target begun after
    /// `since`. An `Err` panics with how many connections the target accepted since; an `Ok` goes
    /// through [`Self::assert_sentinel_response`].
    #[track_caller]
    pub(crate) fn assert_sentinel_roundtrip(&self, since: AcceptedMark, what: &str, result: std::io::Result<Vec<u8>>) {
        match result {
            Ok(response) => self.assert_sentinel_response(since, &response),
            Err(e) => panic!(
                "{what} failed: {e}; target {} accepted {} connection(s) since the request",
                self.addr,
                self.accepted_since(since),
            ),
        }
    }

    /// Assert `response` is this target's sentinel reply to a request sent after `since`. On
    /// failure the message carries the response length and bytes and how many connections the
    /// target accepted since, which together say which hop failed.
    #[track_caller]
    pub(crate) fn assert_sentinel_response(&self, since: AcceptedMark, response: &[u8]) {
        let accepted = self.accepted_since(since);
        let Some(body) = http_response_body(response) else {
            panic!(
                "HTTP response has no header terminator: {} byte(s) {:?}; target {} accepted {accepted} connection(s)",
                response.len(),
                String::from_utf8_lossy(response),
                self.addr,
            );
        };
        assert_eq!(
            body,
            SENTINEL_BODY,
            "expected sentinel body; response is {} byte(s) {:?}; target {} accepted {accepted} connection(s)",
            response.len(),
            String::from_utf8_lossy(response),
            self.addr,
        );
    }
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
                let primary = wait_for_primary_ipv4().expect("detect primary IPv4");
                // Bind on 0.0.0.0:0 so we don't need a capability to bind a
                // specific interface IP — but report the primary IP + the
                // chosen port to the caller, since that's what the e2e tests
                // need to send traffic to.
                let listener = TcpListener::bind("0.0.0.0:0").await.expect("bind 0.0.0.0:0");
                let port = listener.local_addr().unwrap().port();
                let addr = SocketAddr::from((primary, port));
                (listener, addr)
            }
            TargetBind::Ipv4Loopback => {
                let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind 127.0.0.1:0");
                let addr = listener.local_addr().unwrap();
                (listener, addr)
            }
            TargetBind::Ipv6Loopback => {
                let listener = TcpListener::bind("[::1]:0").await.expect("bind [::1]:0");
                let addr = listener.local_addr().unwrap();
                (listener, addr)
            }
        }
    });

    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_by_task = Arc::clone(&accepted);
    let (tx, mut rx) = oneshot::channel();
    runtime.spawn(async move {
        loop {
            tokio::select! {
                _ = &mut rx => return,
                accept = listener.accept() => {
                    if let Ok((sock, _)) = accept {
                        accepted_by_task.fetch_add(1, Ordering::Relaxed);
                        tokio::spawn(handle_connection(sock));
                    }
                }
            }
        }
    });

    HttpTarget {
        addr,
        accepted,
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
