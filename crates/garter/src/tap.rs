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
//! it behind either the persistent `diagnostic_plugin_tap` config flag or
//! the dev-only `HOLE_BRIDGE_PLUGIN_TAP=1` env var.
//!
//! Lifecycle:
//! 1. Allocate an internal port for the inner plugin via probe-and-drop
//!    on `(ip, 0)`, never the public port. A port the OS refuses for a
//!    transient reason (the Windows excluded-port-range flake) or hands back
//!    as the public port is picked again, with no attempt cap.
//! 2. Spawn the inner plugin's `run` future in a task, configured to bind
//!    that internal port.
//! 3. Wait for the inner plugin's own readiness report, racing the inner
//!    task's `JoinHandle` so an early inner failure unblocks us. The report
//!    is the only readiness signal: a TCP probe cannot tell the inner from
//!    another process that took the probed port. A typed failure the inner
//!    reports (`BindConflict` when another process took the internal port,
//!    `Fatal`) becomes the tap's own, so the caller sees the same retryable
//!    or terminal class. Only an inner that speaks sitrep reports a typed
//!    failure, so only it gets the stolen-inner-port retry: an inner that exits
//!    without reporting says nothing about why, and its exit is `Fatal`.
//!    Bounded at 30s; on timeout the inner task is aborted and `Error::Chain`
//!    propagates.
//! 4. Bind the tap's public listener on `local` (only after step 3, so the
//!    public bind happens only once the data plane is actually wired
//!    through), then report the tap's OWN readiness on the `ready` channel
//!    passed to [`ChainPlugin::run`] — the chain aggregator awaits that.
//! 5. Accept loop in a `JoinSet`; per-connection forwarder calls
//!    `tokio::io::copy_bidirectional` with [`CountingStream`] wrappers. A forwarder
//!    retries a refused connect to the inner until it connects, hits another
//!    error, or is aborted (shutdown, or the inner task ending). An inner that
//!    stays alive with its listener gone breaks the sitrep contract (it must
//!    exit); its forwarders then retry until it does.
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
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::counting::CountingStream;
use crate::plugin::ChainPlugin;
use crate::sitrep::{PluginReady, StartError, Transports};

/// Process-wide monotonic id assigned to each tap connection. Logged as
/// `tap_conn_id` so log readers can correlate the `accepted` and
/// `closed` lines for a single connection.
static NEXT_TAP_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// Maximum time we wait for the inner plugin to bind its internal port
/// before the tap gives up. Mirrors [`crate::chain::ChainRunner`]'s 30s
/// readiness budget for the outermost listener.
const INNER_READY_TIMEOUT: Duration = Duration::from_secs(30);

/// Decorator that wraps any [`ChainPlugin`] in a counting loopback hop.
///
/// `wrap(inner)` produces a new plugin whose `run` performs the lifecycle
/// described in the module docs. The inner plugin is moved by value;
/// `pid_sink` and other configuration on `BinaryPlugin` are preserved
/// (the tap delegates to `inner.run`).
///
/// A bind conflict on the inner port is retryable ([`StartError::BindConflict`])
/// only when the inner plugin reports it, which takes sitrep
/// ([`ReadinessMode::ExpectSitrep`](crate::binary::ReadinessMode::ExpectSitrep)
/// or `Auto`). An inner that does not speak sitrep exits untyped, and the tap
/// reports that exit as [`StartError::Fatal`]. With `Probe` readiness a process
/// that took the inner port can also answer the probe: the inner then reports
/// ready and dies on its own failed bind.
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
        ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        let plugin_name = self.inner.name().to_string();

        // 1. Allocate inner port (probe-and-drop, with bind-race retry).
        let inner_local = match allocate_inner_port(local.ip(), local.port()).await {
            Ok(addr) => addr,
            Err(e) => {
                let _ = ready.send(Err(StartError::Fatal {
                    detail: format!("tap[{plugin_name}]: alloc inner port: {e}"),
                    errno: e.raw_os_error(),
                }));
                return Err(crate::Error::Chain(format!(
                    "tap[{plugin_name}]: alloc inner port: {e}"
                )));
            }
        };

        // 2. Spawn the inner plugin against `inner_local`.
        let inner_shutdown = shutdown.clone();
        let (inner_ready_tx, mut inner_ready_rx) = oneshot::channel();
        let mut inner_handle = tokio::spawn(self.inner.run(inner_local, remote, inner_shutdown, inner_ready_tx));

        // 3. Wait for the inner plugin's readiness report, racing the inner
        //    task itself so an early plugin failure doesn't leave us blocked.
        //    `biased`: a report already delivered outranks the exit that
        //    follows it.
        // sync-exception(external-event, CLAUDE.md class 2): INNER_READY_TIMEOUT is the
        // failure bound for an inner plugin (often a child process) that may never ready;
        // it is surfaced to the caller, not used to sync code we control.
        let reported = tokio::select! {
            biased;
            r = tokio::time::timeout(INNER_READY_TIMEOUT, &mut inner_ready_rx) => r,
            join = &mut inner_handle => {
                // The inner exited. A typed report sent just before the exit
                // is still in the channel; nothing more can arrive after it.
                let typed = inner_ready_rx.try_recv().ok().and_then(Result::err);
                report_start_failure(&plugin_name, ready, typed);
                return join_result(&plugin_name, join);
            }
            () = shutdown.cancelled() => {
                // Drop `ready` unsent (RecvError, matching the "shutdown
                // before ready" semantics). Wait for inner to unwind and propagate.
                return drain_inner(plugin_name.as_str(), inner_handle).await;
            }
        };
        match reported {
            Ok(Ok(Ok(_))) => {}
            // A typed failure the inner reported while still running: the
            // caller sees its class.
            Ok(Ok(Err(e))) => {
                inner_handle.abort();
                let _ = inner_handle.await;
                let detail = format!("tap[{plugin_name}]: inner failed to start: {e}");
                report_start_failure(&plugin_name, ready, Some(e));
                return Err(crate::Error::Chain(detail));
            }
            // The inner dropped `ready` unsent: it is exiting or already exited.
            Ok(Err(_dropped)) => {
                if shutdown.is_cancelled() {
                    return drain_inner(plugin_name.as_str(), inner_handle).await;
                }
                let join = inner_handle.await;
                report_start_failure(&plugin_name, ready, None);
                return join_result(&plugin_name, join);
            }
            Err(_elapsed) => {
                inner_handle.abort();
                let _ = inner_handle.await;
                let detail = format!(
                    "tap[{plugin_name}]: inner plugin did not bind {inner_local} within {INNER_READY_TIMEOUT:?}"
                );
                let _ = ready.send(Err(StartError::Fatal {
                    detail: detail.clone(),
                    errno: None,
                }));
                return Err(crate::Error::Chain(detail));
            }
        }

        // 4. Bind the public-facing tap listener.
        let listener = match TcpListener::bind(local).await {
            Ok(l) => l,
            Err(e) => {
                let _ = ready.send(Err(StartError::BindConflict {
                    // `BindConflict.errno` is a raw OS error (0 if unknown,
                    // per sitrep); `io::Error::raw_os_error` is `Option<i32>`.
                    errno: e.raw_os_error().unwrap_or(0),
                    addr: local,
                }));
                inner_handle.abort();
                let _ = inner_handle.await;
                return Err(crate::Error::Chain(format!("tap[{plugin_name}]: bind {local}: {e}")));
            }
        };
        let listen_addr = listener.local_addr().unwrap_or(local);
        tracing::info!(
            plugin = %plugin_name,
            %local,
            %inner_local,
            "plugin tap: ready"
        );
        // The tap proxies TCP only; report readiness on the public listener.
        let _ = ready.send(Ok(PluginReady {
            listen: listen_addr,
            transports: Transports::TCP,
        }));

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

/// Report an inner start failure on the tap's own `ready`: the inner's typed
/// error when it sent one, else `Fatal` (an exit carries no cause).
fn report_start_failure(
    plugin_name: &str,
    ready: oneshot::Sender<Result<PluginReady, StartError>>,
    typed: Option<StartError>,
) {
    let err = typed.unwrap_or_else(|| StartError::Fatal {
        detail: format!("tap[{plugin_name}]: inner exited before becoming ready"),
        errno: None,
    });
    let _ = ready.send(Err(err));
}

fn join_result(plugin_name: &str, join: Result<crate::Result<()>, tokio::task::JoinError>) -> crate::Result<()> {
    match join {
        Ok(result) => result,
        Err(je) => Err(crate::Error::Chain(format!("tap[{plugin_name}]: inner task: {je}"))),
    }
}

async fn drain_inner(plugin_name: &str, inner_handle: tokio::task::JoinHandle<crate::Result<()>>) -> crate::Result<()> {
    match inner_handle.await {
        Ok(result) => result,
        Err(je) if je.is_cancelled() => Ok(()),
        Err(je) => Err(crate::Error::Chain(format!("tap[{plugin_name}]: inner task: {je}"))),
    }
}

/// Probe-and-drop a free TCP port on `(ip, 0)` that is not `public_port`.
async fn allocate_inner_port(ip: IpAddr, public_port: u16) -> io::Result<SocketAddr> {
    allocate_inner_port_with(public_port, || {
        std::net::TcpListener::bind(SocketAddr::new(ip, 0)).and_then(|l| l.local_addr())
    })
    .await
}

/// [`allocate_inner_port`] over a caller-supplied probe, so a test can script
/// the sequence of ports and errors the OS would return.
///
/// Picks again, with no attempt cap, when the probe returns `public_port` (the
/// OS may hand back a port the caller just freed) or an error of the
/// ephemeral-bind race class (`AddrInUse` / `PermissionDenied` /
/// `AddrNotAvailable`: the Windows excluded-port-range flake). Any other error
/// is returned.
pub(crate) async fn allocate_inner_port_with(
    public_port: u16,
    mut probe: impl FnMut() -> io::Result<SocketAddr>,
) -> io::Result<SocketAddr> {
    loop {
        match probe() {
            Ok(addr) if addr.port() != public_port => return Ok(addr),
            Ok(_) => {}
            Err(e) if is_bind_race(&e) => {}
            Err(e) => return Err(e),
        }
        tokio::task::yield_now().await;
    }
}

/// Mirrors `util::retry::is_bind_race` (garter is published and cannot depend
/// on the unpublished `util`).
fn is_bind_race(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
    )
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

    let upstream = match retry_connect_inner(inner_local, &shutdown).await {
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

/// Connects to the inner plugin, retrying every `ECONNREFUSED`.
///
/// A refusal is not proof the inner will never accept (Windows reports a full
/// listen backlog as a refusal, after the SYN retransmissions), so only a real
/// condition ends the loop: a connection, any other error, or `shutdown`. The
/// inner exiting ends it too, from outside: the accept loop aborts every
/// forwarder, this one included, when the inner task finishes. The backoff
/// paces the loop and proves nothing.
async fn retry_connect_inner(addr: SocketAddr, shutdown: &CancellationToken) -> io::Result<TcpStream> {
    retry_connect_with(|| TcpStream::connect(addr), shutdown).await
}

/// [`retry_connect_inner`] over a caller-supplied connect, so a test can script
/// the refusals the OS would return.
pub(crate) async fn retry_connect_with<T, Fut>(
    mut connect: impl FnMut() -> Fut,
    shutdown: &CancellationToken,
) -> io::Result<T>
where
    Fut: std::future::Future<Output = io::Result<T>>,
{
    let mut delay = Duration::from_millis(5);
    let max_delay = Duration::from_millis(50);
    loop {
        tokio::select! {
            result = connect() => match result {
                Ok(s) => return Ok(s),
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {}
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
