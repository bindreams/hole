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
//!    on `(ip, 0)`, never a port the tap knows is taken: the public port or
//!    `remote`'s (the next hop's, bound later). A port the OS hands back as one
//!    of those, or refuses as a bind race (`AddrInUse`, `PermissionDenied`,
//!    `AddrNotAvailable`: the Windows excluded-port-range classes), is picked
//!    again with no attempt cap, paced by a backoff and ended by `shutdown`; a
//!    race that fails the same way twice running is warned about once. Any other
//!    error fails the start. A mapped IPv6 `local` is used as its IPv4 form
//!    throughout: probed, bound and reported so.
//! 2. Spawn the inner plugin's `run` future in a task, configured to bind
//!    that internal port.
//! 3. Wait for the inner plugin's own readiness report, racing the inner
//!    task's `JoinHandle` so an early inner failure unblocks us. The report
//!    is the only readiness signal: a TCP probe cannot tell the inner from
//!    another process that took the probed port. The report's `listen` must be
//!    the address the inner was given (sitrep: a host must validate `listen`
//!    before connecting): the same port and ip, a mapped IPv6 form counting as
//!    its IPv4 address, and under a wildcard ip any ip of that family, since the
//!    inner listens on all of them. Else the start is `Fatal`. Forwarders connect
//!    to the given address (its loopback for a wildcard), never to the reported
//!    one. A typed failure the inner
//!    reports (`BindConflict` when another process took the internal port,
//!    `Fatal`) becomes the tap's own, so the caller sees the same retryable
//!    or terminal class. Bounded at 30s, covering an inner that drops its
//!    readiness sender but keeps running. Every failed start from here on (that
//!    timeout, a listener outside the given address, a failure the inner reports
//!    while running, the step-4 bind) cancels the inner's token, a child of
//!    `shutdown`, and waits for the inner task before reporting: the output it is
//!    still relaying is drained first. The chain is still starting, so no
//!    `drain_timeout` runs: the wait has a bound of its own, a `BinaryPlugin`
//!    inner's whole take-down plus a second, which an inner that honours its
//!    token never reaches. On expiry the tap
//!    warns, naming the plugin, and aborts the inner. How the inner ended is
//!    logged (an exit status at debug, a panic at warn) and otherwise dropped:
//!    the failure being reported is the tap's, unless the inner delivered a typed
//!    start failure by the time it stopped (a `BinaryPlugin` delivers one it
//!    decided at the end of its take-down): that is reported instead. The
//!    readiness bound and a shutdown before readiness read it so; the latter then
//!    also fails `run` instead of only dropping `ready`. The other failed starts
//!    here follow a report the inner has already made, its one readiness message.
//!    A start failure the tap has
//!    reported is also its `run` error, so a runner with no `on_ready` sees the
//!    chain fail. `Error::Chain` propagates.
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
//!    propagate its exit status as ours. If the accept loop fails instead, the
//!    tap stops the inner as in step 3 and fails with an error naming the
//!    accept failure. The inner task is aborted if the tap is dropped (the
//!    chain's `drain_timeout` aborts it), so it never outlives the tap.
//!
//! License: this module is part of `garter` (Apache-2.0). The bridge
//! (GPL-3.0-or-later) imports it; one-way Apache → GPL compatibility
//! per the workspace `NOTICES.md`.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

use crate::backoff::Backoff;
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

/// Failure bound on the wait for the inner to return after the tap cancelled its token to report a failed start. An
/// inner must return once its token fires, so this expires only on an inner that does not: the tap then warns and
/// aborts it. It outlasts a [`BinaryPlugin`](crate::BinaryPlugin) inner's own take-down, so that one is never cut off.
pub(crate) const INNER_STOP_BOUND: Duration =
    Duration::from_secs(crate::binary::TAKEDOWN_BOUND.as_secs() + crate::binary::TAKEDOWN_TAIL.as_secs());

/// Decorator that wraps any [`ChainPlugin`] in a counting loopback hop.
///
/// `wrap(inner)` produces a new plugin whose `run` performs the lifecycle
/// described in the module docs. The inner plugin is shared with each run;
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
    inner: Arc<dyn ChainPlugin>,
    // The three seams below are taken by the first run that reads them: a later run uses the real probe, connect and
    // accept.
    /// Replaces the OS probe in the inner-port pick, so a test can script the
    /// ports and errors the OS would return.
    #[cfg(test)]
    probe: Mutex<Option<Probe>>,
    /// Replaces the forwarders' TCP connect, so a test can script the refusals the OS would return.
    #[cfg(test)]
    connector: Mutex<Option<Connector>>,
    /// Fails the accept loop's first accept, as the OS does on fd exhaustion.
    #[cfg(test)]
    accept_failure: Mutex<Option<io::Error>>,
}

/// One attempt to find a free port: the address a probe bound, or its error.
pub(crate) type Probe = Box<dyn FnMut() -> io::Result<SocketAddr> + Send>;

/// Opens a forwarder's connection to the inner.
pub(crate) type Connector =
    Arc<dyn Fn(SocketAddr) -> Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>> + Send + Sync>;

fn tcp_connector() -> Connector {
    Arc::new(|addr| Box::pin(TcpStream::connect(addr)))
}

impl TapPlugin {
    pub fn wrap(inner: Box<dyn ChainPlugin>) -> Self {
        Self {
            inner: Arc::from(inner),
            #[cfg(test)]
            probe: Mutex::new(None),
            #[cfg(test)]
            connector: Mutex::new(None),
            #[cfg(test)]
            accept_failure: Mutex::new(None),
        }
    }

    /// The accept failure a test scripted, if any.
    fn take_accept_failure(&self) -> Option<io::Error> {
        #[cfg(test)]
        return self.accept_failure.lock().unwrap().take();
        #[cfg(not(test))]
        None
    }

    /// The scripted probe a test installed, if any.
    fn take_probe(&self) -> Option<Probe> {
        #[cfg(test)]
        return self.probe.lock().unwrap().take();
        #[cfg(not(test))]
        None
    }

    /// The connector a test installed, else the real TCP connect.
    fn take_connector(&self) -> Connector {
        #[cfg(test)]
        if let Some(connector) = self.connector.lock().unwrap().take() {
            return connector;
        }
        tcp_connector()
    }

    #[cfg(test)]
    pub(crate) fn wrap_with_probe(inner: Box<dyn ChainPlugin>, probe: Probe) -> Self {
        Self {
            probe: Mutex::new(Some(probe)),
            ..Self::wrap(inner)
        }
    }

    #[cfg(test)]
    pub(crate) fn wrap_with_connector(inner: Box<dyn ChainPlugin>, connector: Connector) -> Self {
        Self {
            connector: Mutex::new(Some(connector)),
            ..Self::wrap(inner)
        }
    }

    #[cfg(test)]
    pub(crate) fn wrap_with_accept_failure(inner: Box<dyn ChainPlugin>, failure: io::Error) -> Self {
        Self {
            accept_failure: Mutex::new(Some(failure)),
            ..Self::wrap(inner)
        }
    }
}

#[async_trait::async_trait]
impl ChainPlugin for TapPlugin {
    fn name(&self) -> &str {
        self.inner.name()
    }

    async fn run(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        shutdown: CancellationToken,
        ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        let plugin_name = self.inner.name().to_string();
        // Windows refuses to bind a mapped IPv6 address, so `local` is its IPv4 form throughout.
        let local = SocketAddr::new(local.ip().to_canonical(), local.port());

        // 1. Allocate inner port (probe-and-drop, with bind-race retry).
        let probe = self.take_probe().unwrap_or_else(|| os_probe(local.ip()));
        let connector = self.take_connector();
        let mut scripted_accept_failure = self.take_accept_failure();
        let inner_local = match allocate_inner_port_with(
            &plugin_name,
            local.ip(),
            &[local.port(), remote.port()],
            probe,
            &shutdown,
        )
        .await
        {
            Ok(Some(addr)) => addr,
            // Shutdown before ready: drop `ready` unsent, as the readiness wait does.
            Ok(None) => return Ok(()),
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
        // The inner's own token, a child of `shutdown`: a failed start stops the inner through it and waits.
        let inner_stop = shutdown.child_token();
        let inner_shutdown = inner_stop.clone();
        let (inner_ready_tx, mut inner_ready_rx) = oneshot::channel();
        let inner = self.inner.clone();
        let mut inner_handle = AbortOnDropHandle::new(tokio::spawn(async move {
            inner.run(inner_local, remote, inner_shutdown, inner_ready_tx).await
        }));

        // 3. Wait for the inner plugin's readiness report, racing the inner
        //    task itself so an early plugin failure doesn't leave us blocked.
        //    `biased`: a report already delivered outranks the exit that
        //    follows it.
        // INNER_READY_TIMEOUT is a failure bound on an inner that may never ready, surfaced to the caller.
        let ready_deadline = tokio::time::Instant::now() + INNER_READY_TIMEOUT;
        let reported = tokio::select! {
            biased;
            r = tokio::time::timeout_at(ready_deadline, &mut inner_ready_rx) => r,
            join = &mut inner_handle => {
                // The inner exited. A typed report sent just before the exit is still in the channel.
                report_start_failure(&plugin_name, ready, delivered_start_failure(&mut inner_ready_rx));
                return failed_start_result(&plugin_name, join);
            }
            () = shutdown.cancelled() => {
                // Wait for inner to unwind and propagate. `ready` goes unsent (RecvError, matching the "shutdown
                // before ready" semantics) unless the inner delivers a typed start failure while it unwinds.
                return drain_after_shutdown(plugin_name.as_str(), ready, &mut inner_ready_rx, inner_handle).await;
            }
        };
        let inner_target = match reported {
            // The port must be the one the inner was given: any other could be
            // the tap's own listener (a self-connect cascade) or another service.
            Ok(Ok(Ok(report))) if reports_the_given_address(report.listen, inner_local) => connect_target(inner_local),
            // The inner reported a listener outside the address it was given.
            Ok(Ok(Ok(report))) => {
                stop_inner(&plugin_name, &inner_stop, inner_handle).await;
                let detail = format!(
                    "tap[{plugin_name}]: inner reported its listener at {}, not the address {} it was given",
                    report.listen, inner_local
                );
                let _ = ready.send(Err(StartError::Fatal {
                    detail: detail.clone(),
                    errno: None,
                }));
                return Err(crate::Error::Chain(detail));
            }
            // A typed failure the inner reported while still running: the
            // caller sees its class.
            Ok(Ok(Err(e))) => {
                stop_inner(&plugin_name, &inner_stop, inner_handle).await;
                return Err(report_inner_failure(&plugin_name, ready, e));
            }
            // The inner dropped `ready` unsent: it is exiting, or it will never report. The
            // readiness budget keeps running while it winds down.
            Ok(Err(_dropped)) => {
                tracing::debug!(plugin = %plugin_name, "plugin tap: the inner dropped its readiness sender");
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => return drain_inner(plugin_name.as_str(), inner_handle).await,
                    join = &mut inner_handle => {
                        report_start_failure(&plugin_name, ready, None);
                        return failed_start_result(&plugin_name, join);
                    }
                    () = tokio::time::sleep_until(ready_deadline) => {
                        return inner_not_ready(
                            &plugin_name,
                            inner_local,
                            ready,
                            &inner_stop,
                            &mut inner_ready_rx,
                            inner_handle,
                        )
                        .await;
                    }
                }
            }
            Err(_elapsed) => {
                return inner_not_ready(
                    &plugin_name,
                    inner_local,
                    ready,
                    &inner_stop,
                    &mut inner_ready_rx,
                    inner_handle,
                )
                .await
            }
        };

        // 4. Bind the public-facing tap listener.
        let listener = match TcpListener::bind(local).await {
            Ok(l) => l,
            Err(e) => {
                stop_inner(&plugin_name, &inner_stop, inner_handle).await;
                let _ = ready.send(Err(StartError::BindConflict {
                    // `BindConflict.errno` is a raw OS error (0 if unknown,
                    // per sitrep); `io::Error::raw_os_error` is `Option<i32>`.
                    errno: e.raw_os_error().unwrap_or(0),
                    addr: local,
                }));
                return Err(crate::Error::Chain(format!("tap[{plugin_name}]: bind {local}: {e}")));
            }
        };
        let listen_addr = listener.local_addr().unwrap_or(local);
        tracing::info!(
            plugin = %plugin_name,
            %local,
            %inner_target,
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
                AcceptFailed(io::Error),
                InnerExited(std::result::Result<crate::Result<()>, tokio::task::JoinError>),
            }
            let step = tokio::select! {
                _ = shutdown.cancelled() => Step::Break,
                accept = accept_next(&listener, &mut scripted_accept_failure) => match accept {
                    Ok((inbound, peer)) => {
                        let inbound_token = shutdown.clone();
                        let connector = connector.clone();
                        connections.spawn(async move {
                            handle_tap_connection(inbound, peer, inner_target, connector, inbound_token).await;
                        });
                        Step::Continue
                    }
                    // accept() failure on a previously-bound listener is unusual (FD
                    // exhaustion / kernel error): the tap can serve nothing more.
                    Err(e) => Step::AcceptFailed(e),
                },
                // Inner exiting on its own (clean or error) is a terminal
                // condition for the chain; surface its result.
                join = &mut inner_handle => Step::InnerExited(join),
            };
            match step {
                Step::Continue => continue,
                Step::Break => break,
                Step::AcceptFailed(e) => {
                    tracing::warn!(plugin = %plugin_name, error = %e, "plugin tap: accept failed");
                    drop(listener);
                    connections.abort_all();
                    while connections.join_next().await.is_some() {}
                    stop_inner(&plugin_name, &inner_stop, inner_handle).await;
                    return Err(crate::Error::Chain(format!(
                        "tap[{plugin_name}]: accept on {listen_addr} failed: {e}"
                    )));
                }
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

/// The next connection, or the failure a test scripted in its place.
async fn accept_next(
    listener: &TcpListener,
    scripted_failure: &mut Option<io::Error>,
) -> io::Result<(TcpStream, SocketAddr)> {
    match scripted_failure.take() {
        Some(failure) => Err(failure),
        None => listener.accept().await,
    }
}

/// Stops a still-running inner through its own token and waits for it, so the output it is still
/// relaying reaches the log before the caller hears of the failure.
///
/// The wait is bounded by [`INNER_STOP_BOUND`], a failure bound on external code: an inner must return once
/// its token fires, and one that does not is warned about by name and aborted. The chain is still starting, so
/// no `drain_timeout` runs to end it. The failure being reported is the tap's; how the inner ended is only logged.
async fn stop_inner(
    plugin_name: &str,
    inner_stop: &CancellationToken,
    mut inner_handle: AbortOnDropHandle<crate::Result<()>>,
) {
    inner_stop.cancel();
    let joined = match tokio::time::timeout(INNER_STOP_BOUND, &mut inner_handle).await {
        Ok(joined) => joined,
        Err(_bound_expired) => {
            tracing::warn!(
                plugin = %plugin_name,
                "plugin tap: the inner did not stop within {INNER_STOP_BOUND:?} of being asked to; aborting it"
            );
            inner_handle.abort();
            inner_handle.await
        }
    };
    match joined {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::debug!(
            plugin = %plugin_name,
            "plugin tap: the inner ended with {e} while the start failure was being reported"
        ),
        Err(je) if je.is_cancelled() => {}
        Err(je) => tracing::warn!(
            plugin = %plugin_name,
            "plugin tap: the inner task panicked while it was being stopped: {je}"
        ),
    }
}

/// The typed start failure the inner has delivered into `inner_ready_rx`, if any. Read it once the inner has ended or
/// been stopped, never earlier: an inner such as a `BinaryPlugin` delivers a failure it decided only at the end of its
/// take-down, and the tap's own failure must not replace it. An already-consumed receiver holds nothing.
fn delivered_start_failure(
    inner_ready_rx: &mut oneshot::Receiver<Result<PluginReady, StartError>>,
) -> Option<StartError> {
    inner_ready_rx.try_recv().ok().and_then(Result::err)
}

/// Reports the typed failure the inner delivered as the tap's own, and returns the tap's `run` error for it.
fn report_inner_failure(
    plugin_name: &str,
    ready: oneshot::Sender<Result<PluginReady, StartError>>,
    typed: StartError,
) -> crate::Error {
    let detail = format!("tap[{plugin_name}]: inner failed to start: {typed}");
    report_start_failure(plugin_name, ready, Some(typed));
    crate::Error::Chain(detail)
}

/// Ends a start whose inner did not report within [`INNER_READY_TIMEOUT`]: stops the inner and reports `Fatal`, unless
/// the inner delivered a typed failure while it stopped, which is reported instead.
async fn inner_not_ready(
    plugin_name: &str,
    inner_local: SocketAddr,
    ready: oneshot::Sender<Result<PluginReady, StartError>>,
    inner_stop: &CancellationToken,
    inner_ready_rx: &mut oneshot::Receiver<Result<PluginReady, StartError>>,
    inner_handle: AbortOnDropHandle<crate::Result<()>>,
) -> crate::Result<()> {
    stop_inner(plugin_name, inner_stop, inner_handle).await;
    if let Some(typed) = delivered_start_failure(inner_ready_rx) {
        return Err(report_inner_failure(plugin_name, ready, typed));
    }
    let detail = format!("tap[{plugin_name}]: inner plugin did not bind {inner_local} within {INNER_READY_TIMEOUT:?}");
    let _ = ready.send(Err(StartError::Fatal {
        detail: detail.clone(),
        errno: None,
    }));
    Err(crate::Error::Chain(detail))
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

/// [`join_result`] for an inner that ended before it was ready, after the tap reported the start failure on `ready`:
/// an inner that ended `Ok` still failed the start, so the tap's `run` is an error too.
fn failed_start_result(
    plugin_name: &str,
    join: Result<crate::Result<()>, tokio::task::JoinError>,
) -> crate::Result<()> {
    match join_result(plugin_name, join) {
        Ok(()) => Err(crate::Error::Chain(format!(
            "tap[{plugin_name}]: inner exited before becoming ready"
        ))),
        failed => failed,
    }
}

/// [`drain_inner`] for a shutdown before the inner readied. A typed start failure the inner delivers while it unwinds
/// (a `BinaryPlugin` delivers a failure it decided at the end of its take-down) is forwarded on `ready` and fails the
/// tap, as for an inner that exited on its own.
async fn drain_after_shutdown(
    plugin_name: &str,
    ready: oneshot::Sender<Result<PluginReady, StartError>>,
    inner_ready_rx: &mut oneshot::Receiver<Result<PluginReady, StartError>>,
    inner_handle: AbortOnDropHandle<crate::Result<()>>,
) -> crate::Result<()> {
    let join = inner_handle.await;
    if let Some(typed) = delivered_start_failure(inner_ready_rx) {
        report_start_failure(plugin_name, ready, Some(typed));
        return failed_start_result(plugin_name, join);
    }
    match join {
        Err(je) if je.is_cancelled() => Ok(()),
        join => join_result(plugin_name, join),
    }
}

async fn drain_inner(plugin_name: &str, inner_handle: AbortOnDropHandle<crate::Result<()>>) -> crate::Result<()> {
    match inner_handle.await {
        Ok(result) => result,
        Err(je) if je.is_cancelled() => Ok(()),
        Err(je) => Err(crate::Error::Chain(format!("tap[{plugin_name}]: inner task: {je}"))),
    }
}

/// Whether the inner reported the address it was given. A wildcard given ip
/// accepts any reported ip of its family (the inner listens on all of them);
/// a mapped IPv6 address equals its IPv4 form.
pub(crate) fn reports_the_given_address(reported: SocketAddr, given: SocketAddr) -> bool {
    let (reported_ip, given_ip) = (reported.ip().to_canonical(), given.ip().to_canonical());
    reported.port() == given.port()
        && (reported_ip == given_ip || (given_ip.is_unspecified() && reported_ip.is_ipv4() == given_ip.is_ipv4()))
}

/// Where forwarders connect: the given address, or its family's loopback when
/// the given ip is a wildcard, never an address the inner chose.
pub(crate) fn connect_target(given: SocketAddr) -> SocketAddr {
    match given.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), given.port())
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), given.port())
        }
        _ => given,
    }
}

/// Probe-and-drop a free TCP port on `(ip, 0)`.
fn os_probe(ip: IpAddr) -> Probe {
    Box::new(move || std::net::TcpListener::bind(SocketAddr::new(ip, 0)).and_then(|l| l.local_addr()))
}

/// Picks a port from `probe` that is not in `taken`.
///
/// Retries a taken port or a bind race ([`is_port_race`]) with no attempt cap,
/// paced by a backoff; any other error is returned. `Ok(None)`: `shutdown`
/// fired first.
///
/// Each swallowed error is logged at debug. A race that fails the same way
/// twice in a row is warned about once, naming `plugin` and `ip`: such a cause
/// is probably not a race (an address the host does not own never binds).
pub(crate) async fn allocate_inner_port_with(
    plugin: &str,
    ip: IpAddr,
    taken: &[u16],
    mut probe: impl FnMut() -> io::Result<SocketAddr>,
    shutdown: &CancellationToken,
) -> io::Result<Option<SocketAddr>> {
    let mut backoff = retry_backoff();
    let mut last_race = None;
    let mut warned = false;
    loop {
        match probe() {
            Ok(addr) if !taken.contains(&addr.port()) => return Ok(Some(addr)),
            Ok(_) => last_race = None,
            Err(e) if is_port_race(&e) => {
                let cause = (e.kind(), e.raw_os_error());
                tracing::debug!(
                    %plugin, %ip, kind = ?cause.0, errno = ?cause.1,
                    "plugin tap: inner port probe failed, picking again"
                );
                if last_race == Some(cause) && !warned {
                    warned = true;
                    tracing::warn!(
                        %plugin, %ip, kind = ?cause.0, errno = ?cause.1,
                        "plugin tap: probing {ip} for the inner port keeps failing the same way; it is retried until shutdown"
                    );
                }
                last_race = Some(cause);
            }
            Err(e) => return Err(e),
        }
        if !backoff.pause(shutdown).await {
            return Ok(None);
        }
    }
}

/// Whether a failed `bind((ip, 0))` is a race that a later pick can win.
///
/// The same classes as `util::retry::is_bind_race`, which garter (published)
/// cannot depend on: on Windows a `bind(:0)` fails with `PermissionDenied` or
/// `AddrNotAvailable` when the excluded-port-range tables disagree about the
/// port it was handed. An address the host does not own fails the same way on
/// every pick, so such a start never readies; `shutdown` ends it.
pub(crate) fn is_port_race(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
    )
}

/// The pause between retries of the tap's own loops: 5ms doubling to a 50ms cap.
fn retry_backoff() -> Backoff {
    Backoff::new(Duration::from_millis(5), Duration::from_millis(50))
}

async fn handle_tap_connection(
    inbound: TcpStream,
    peer: SocketAddr,
    inner_target: SocketAddr,
    connector: Connector,
    shutdown: CancellationToken,
) {
    let conn_id = NEXT_TAP_CONN_ID.fetch_add(1, Ordering::Relaxed);
    let started = Instant::now();
    tracing::info!(tap_conn_id = conn_id, %peer, %inner_target, "plugin tap: accepted");

    let upstream = match retry_connect_inner(conn_id, inner_target, &connector, &shutdown).await {
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
async fn retry_connect_inner(
    conn_id: u64,
    addr: SocketAddr,
    connector: &Connector,
    shutdown: &CancellationToken,
) -> io::Result<TcpStream> {
    retry_connect_with(conn_id, addr, || connector(addr), shutdown).await
}

/// [`retry_connect_inner`] over a caller-supplied connect, so a test can script
/// the refusals the OS would return.
///
/// Logs each refusal at debug, and warns once, when the backoff first reaches
/// its longest pause, that the inner has refused for a while.
pub(crate) async fn retry_connect_with<T, Fut>(
    conn_id: u64,
    addr: SocketAddr,
    mut connect: impl FnMut() -> Fut,
    shutdown: &CancellationToken,
) -> io::Result<T>
where
    Fut: std::future::Future<Output = io::Result<T>>,
{
    let mut backoff = retry_backoff();
    let mut warned = false;
    loop {
        tokio::select! {
            result = connect() => match result {
                Ok(s) => return Ok(s),
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                    tracing::debug!(tap_conn_id = conn_id, %addr, "plugin tap: inner connect refused, retrying");
                }
                Err(e) => return Err(e),
            },
            _ = shutdown.cancelled() => {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "tap: shutdown during inner connect"));
            }
        }

        if !backoff.pause(shutdown).await {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "tap: shutdown during inner connect",
            ));
        }
        if backoff.at_max() && !warned {
            warned = true;
            tracing::warn!(
                tap_conn_id = conn_id,
                %addr,
                "plugin tap: inner still refusing connections, retrying until it accepts or exits"
            );
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
