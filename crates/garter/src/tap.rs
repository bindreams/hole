//! [`TapPlugin`] — counting decorator over any [`ChainPlugin`].
//!
//! Inserts an instrumented loopback hop between `local` (the chain-public
//! address shadowsocks-service connects to) and an internal port the
//! inner plugin actually binds. For each accepted TCP connection the tap
//! emits an `info!` line on `accept` and a structured `info!` line on
//! `close` with byte counters (toward and from the inner plugin),
//! time-to-first-upstream-byte, and a Win32+POSIX-aware `close_kind`
//! taxonomy.
//!
//! Designed for diagnostic mode — the extra loopback round-trip per byte
//! is fine for an on-demand tap but inappropriate as default. Bridge gates
//! it behind `HOLE_BRIDGE_PLUGIN_TAP=1`.
//!
//! Lifecycle:
//! 1. Allocate an internal port for the inner plugin via probe-and-drop
//!    on `(ip, 0)`. Wrap in a small bind-race retry loop in case Windows
//!    excluded-port-range tables would refuse the second bind.
//! 2. Spawn the inner plugin's `run` future in a task, configured to bind
//!    that internal port.
//! 3. Wait for the inner plugin to actually accept TCP via
//!    [`crate::chain::poll_ready`] (same backoff schedule [`ChainRunner`]
//!    uses for its own readiness probe). Bounded at 30s; on timeout the
//!    inner task is aborted and `Error::Chain` propagates.
//! 4. Bind the tap's public listener on `local` (only after step 3 — the
//!    bind has to be observable to `ChainRunner::poll_ready` only when
//!    the data plane is actually wired through).
//! 5. Accept loop in a `JoinSet`; per-connection forwarder calls
//!    `tokio::io::copy_bidirectional` with [`CountingStream`] wrappers.
//! 6. On shutdown: abort all in-flight forwarders, await the inner task,
//!    propagate its exit status as ours.
//!
//! License: this module is part of `garter` (Apache-2.0). The bridge
//! (GPL-3.0-or-later) imports it; one-way Apache → GPL compatibility
//! per the workspace `NOTICES.md`.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::counting::CountingStream;
use crate::plugin::ChainPlugin;

/// Process-wide monotonic id assigned to each tap connection. Logged as
/// `tap_conn_id` so log readers can correlate the `accepted` and
/// `closed` lines for a single connection.
static NEXT_TAP_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// Maximum time we wait for the inner plugin to bind its internal port
/// before the tap gives up. Mirrors [`crate::chain::ChainRunner`]'s 30s
/// readiness budget for the outermost listener.
const INNER_READY_TIMEOUT: Duration = Duration::from_secs(30);

/// Budget for retrying the inner-plugin connect on transient
/// `ECONNREFUSED`. Absorbs the (small) residual race between
/// [`poll_ready`](crate::chain::poll_ready) returning and a brand-new
/// inbound flow opening before the inner accept loop has spun up
/// per-connection state.
const INNER_CONNECT_RETRY_BUDGET: Duration = Duration::from_millis(250);

/// Maximum attempts to allocate an internal port. One round of
/// alloc-then-bind is usually enough on Linux/macOS; on Windows the
/// excluded-port-range table can flake briefly, so up to N retries.
const INNER_PORT_ALLOC_ATTEMPTS: u32 = 4;

/// Decorator that wraps any [`ChainPlugin`] in a counting loopback hop.
///
/// `wrap(inner)` produces a new plugin whose `run` performs the lifecycle
/// described in the module docs. The inner plugin is moved by value;
/// `pid_sink` and other configuration on `BinaryPlugin` are preserved
/// (the tap delegates to `inner.run`).
pub struct TapPlugin {
    inner: Box<dyn ChainPlugin>,
}

impl TapPlugin {
    pub fn wrap(inner: Box<dyn ChainPlugin>) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl ChainPlugin for TapPlugin {
    fn name(&self) -> &str {
        self.inner.name()
    }

    async fn run(
        self: Box<Self>,
        local: SocketAddr,
        remote: SocketAddr,
        shutdown: CancellationToken,
    ) -> crate::Result<()> {
        let plugin_name = self.inner.name().to_string();

        // 1. Allocate inner port (probe-and-drop, with bind-race retry).
        let inner_local = allocate_inner_port(local.ip())
            .map_err(|e| crate::Error::Chain(format!("tap[{plugin_name}]: alloc inner port: {e}")))?;

        // 2. Spawn the inner plugin against `inner_local`.
        let inner_shutdown = shutdown.clone();
        let mut inner_handle = tokio::spawn(self.inner.run(inner_local, remote, inner_shutdown));

        // 3. Wait for the inner plugin to bind the inner port. Race
        //    against the inner task itself so an early plugin failure
        //    doesn't leave us blocked on a port that will never bind.
        let ready_token = shutdown.clone();
        let ready_outcome = tokio::select! {
            ready = tokio::time::timeout(INNER_READY_TIMEOUT, crate::chain::poll_ready(inner_local, ready_token)) => {
                Some(ready)
            }
            join = &mut inner_handle => {
                // Inner exited before binding — propagate its result. No
                // tap listener was ever opened, so nothing to clean up.
                return match join {
                    Ok(result) => result,
                    Err(je) => Err(crate::Error::Chain(format!("tap[{plugin_name}]: inner task: {je}"))),
                };
            }
        };
        match ready_outcome {
            Some(Ok(Some(_))) => {}
            Some(Ok(None)) => {
                // Shutdown fired before inner was ready. Wait for inner to
                // unwind and propagate its result.
                return drain_inner(plugin_name.as_str(), inner_handle).await;
            }
            Some(Err(_)) => {
                inner_handle.abort();
                let _ = inner_handle.await;
                return Err(crate::Error::Chain(format!(
                    "tap[{plugin_name}]: inner plugin did not bind {inner_local} within {INNER_READY_TIMEOUT:?}"
                )));
            }
            None => unreachable!(),
        }

        // 4. Bind the public-facing tap listener.
        let listener = TcpListener::bind(local)
            .await
            .map_err(|e| crate::Error::Chain(format!("tap[{plugin_name}]: bind {local}: {e}")))?;
        tracing::info!(
            plugin = %plugin_name,
            %local,
            %inner_local,
            "plugin tap: ready"
        );

        // 5. Accept loop. Per-connection forwarders go into a JoinSet so
        //    shutdown can abort them; we never leak a forwarder past the
        //    plugin's lifetime.
        let mut connections: JoinSet<()> = JoinSet::new();
        loop {
            // Use boolean state to drive control flow because tokio::select!
            // arms cannot embed `break`/`return` cleanly across multi-arm
            // match blocks (parser disambiguation gets unhappy). We set
            // intent here, drop out of select, then act.
            enum Step {
                Continue,
                Break,
                InnerExited(std::result::Result<crate::Result<()>, tokio::task::JoinError>),
            }
            let step = tokio::select! {
                _ = shutdown.cancelled() => Step::Break,
                accept = listener.accept() => match accept {
                    Ok((inbound, peer)) => {
                        let inbound_token = shutdown.clone();
                        connections.spawn(async move {
                            handle_tap_connection(inbound, peer, inner_local, inbound_token).await;
                        });
                        Step::Continue
                    }
                    Err(e) => {
                        // accept() failure on a previously-bound listener
                        // is unusual (FD exhaustion / kernel error) — log
                        // and break so the inner plugin can exit cleanly.
                        tracing::warn!(plugin = %plugin_name, error = %e, "plugin tap: accept failed");
                        Step::Break
                    }
                },
                // Inner exiting on its own (clean or error) is a terminal
                // condition for the chain; surface its result.
                join = &mut inner_handle => Step::InnerExited(join),
            };
            match step {
                Step::Continue => continue,
                Step::Break => break,
                Step::InnerExited(join) => {
                    drop(listener);
                    connections.abort_all();
                    while connections.join_next().await.is_some() {}
                    return match join {
                        Ok(result) => result,
                        Err(je) => Err(crate::Error::Chain(format!("tap[{plugin_name}]: inner task: {je}"))),
                    };
                }
            }
        }

        // 6. Shutdown path: drop listener, abort forwarders, await inner.
        drop(listener);
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        drain_inner(plugin_name.as_str(), inner_handle).await
    }
}

async fn drain_inner(plugin_name: &str, inner_handle: tokio::task::JoinHandle<crate::Result<()>>) -> crate::Result<()> {
    match inner_handle.await {
        Ok(result) => result,
        Err(je) if je.is_cancelled() => Ok(()),
        Err(je) => Err(crate::Error::Chain(format!("tap[{plugin_name}]: inner task: {je}"))),
    }
}

/// Probe-and-drop a free TCP port on `(ip, 0)`. Retries on
/// `AddrInUse` / `PermissionDenied` (the Windows excluded-port-range
/// flake) up to [`INNER_PORT_ALLOC_ATTEMPTS`] times.
fn allocate_inner_port(ip: IpAddr) -> io::Result<SocketAddr> {
    let mut last_err: Option<io::Error> = None;
    for _ in 0..INNER_PORT_ALLOC_ATTEMPTS {
        match std::net::TcpListener::bind(SocketAddr::new(ip, 0)).and_then(|l| l.local_addr()) {
            Ok(addr) => return Ok(addr),
            Err(e) => match e.kind() {
                io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable => {
                    last_err = Some(e);
                    continue;
                }
                _ => return Err(e),
            },
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::other("alloc_inner_port: no error captured")))
}

async fn handle_tap_connection(
    inbound: TcpStream,
    peer: SocketAddr,
    inner_local: SocketAddr,
    shutdown: CancellationToken,
) {
    let conn_id = NEXT_TAP_CONN_ID.fetch_add(1, Ordering::Relaxed);
    let started = Instant::now();
    tracing::info!(tap_conn_id = conn_id, %peer, %inner_local, "plugin tap: accepted");

    let upstream = match retry_connect_inner(inner_local, INNER_CONNECT_RETRY_BUDGET, &shutdown).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                tap_conn_id = conn_id,
                error = %e,
                "plugin tap: inner connect failed"
            );
            return;
        }
    };

    let mut inbound = CountingStream::new(inbound);
    let mut upstream = CountingStream::new(upstream);
    let inbound_counters = inbound.counters();
    let upstream_counters = upstream.counters();

    let close_err: Option<io::Error> = tokio::select! {
        result = tokio::io::copy_bidirectional(&mut inbound, &mut upstream) => result.err(),
        _ = shutdown.cancelled() => None,
    };

    let elapsed_ms = started.elapsed().as_millis() as u64;
    let bytes_to_plugin = upstream_counters.written();
    let bytes_from_plugin = upstream_counters.read();
    let ttfb_ms = upstream_counters
        .first_read_at()
        .map(|t| t.duration_since(started).as_millis() as u64);
    let close_kind = classify_close(close_err.as_ref());
    let os_errno = close_err.as_ref().and_then(|e| e.raw_os_error());

    tracing::info!(
        tap_conn_id = conn_id,
        %peer,
        elapsed_ms,
        ttfb_ms = ?ttfb_ms,
        bytes_to_plugin,
        bytes_from_plugin,
        // Sanity-check fields: inbound.read should equal upstream.written
        // and inbound.written should equal upstream.read on a clean copy.
        // Logged separately so a future tap regression surfaces as a
        // counter mismatch in the field shape.
        bytes_inbound_read = inbound_counters.read(),
        bytes_inbound_written = inbound_counters.written(),
        close_kind = %close_kind,
        os_errno = ?os_errno,
        "plugin tap: closed"
    );
}

async fn retry_connect_inner(
    addr: SocketAddr,
    budget: Duration,
    shutdown: &CancellationToken,
) -> io::Result<TcpStream> {
    let deadline = Instant::now() + budget;
    let mut delay = Duration::from_millis(5);
    let max_delay = Duration::from_millis(50);
    loop {
        tokio::select! {
            result = TcpStream::connect(addr) => match result {
                Ok(s) => return Ok(s),
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused && Instant::now() < deadline => {
                    // fall through to backoff
                }
                Err(e) => return Err(e),
            },
            _ = shutdown.cancelled() => {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "tap: shutdown during inner connect"));
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(delay) => {
                delay = (delay * 2).min(max_delay);
            }
            _ = shutdown.cancelled() => {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "tap: shutdown during inner connect"));
            }
        }
    }
}

/// Map a connection-close error onto a small enumeration friendly to
/// log readers. Covers both Windows (`WSAE*`) and POSIX errnos plus the
/// portable `io::ErrorKind` variants `tokio::io::copy_bidirectional`
/// surfaces. `None` means the bidirectional copy returned `Ok` (graceful
/// FIN both directions) or shutdown cancelled the relay.
fn classify_close(err: Option<&io::Error>) -> &'static str {
    let Some(e) = err else { return "graceful" };
    if let Some(errno) = e.raw_os_error() {
        return match errno {
            // Windows
            10054 => "rst",       // WSAECONNRESET
            10053 => "abort",     // WSAECONNABORTED
            10052 => "net_reset", // WSAENETRESET
            10058 => "shutdown",  // WSAESHUTDOWN
            10060 => "timeout",   // WSAETIMEDOUT
            // POSIX
            104 => "rst",        // ECONNRESET
            103 => "abort",      // ECONNABORTED
            110 => "timeout",    // ETIMEDOUT
            32 => "broken_pipe", // EPIPE
            _ => fallback_kind(e),
        };
    }
    fallback_kind(e)
}

fn fallback_kind(e: &io::Error) -> &'static str {
    match e.kind() {
        io::ErrorKind::UnexpectedEof => "eof",
        io::ErrorKind::TimedOut => "timeout",
        io::ErrorKind::BrokenPipe => "broken_pipe",
        io::ErrorKind::ConnectionReset => "rst",
        io::ErrorKind::ConnectionAborted => "abort",
        _ => "other",
    }
}
