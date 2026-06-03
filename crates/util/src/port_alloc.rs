//! Ephemeral port allocation with multi-transport verification and retry
//! around Windows-specific bind races (WSAEACCES from independent TCP/UDP
//! excluded-port-range tables, WSAEADDRINUSE from `SO_EXCLUSIVEADDRUSE`
//! wildcard holders, WSAEADDRNOTAVAIL from the same reservation layer).
//!
//! [`bind_ephemeral`] is the canonical entry point. It allocates an
//! ephemeral port AND runs a caller-supplied bind closure against that
//! port in the same loop iteration, retrying the whole (allocate, bind)
//! cycle on [`is_bind_race`] errors. The retry is unbounded — the only
//! terminations are success or a non-bind-race error. There is no
//! "attempts budget"; the OS allocator covers ~28K ephemeral ports and
//! a fixed retry cap would either mask real saturation (if too high) or
//! flake on transient excluded-range pressure (if too low). See
//! bindreams/hole#300.
//!
//! Consumers across the workspace route through `bind_ephemeral`:
//!
//! * `hole-bridge`'s `LocalDnsServer::bind` — UDP+TCP on the same ephemeral
//!   loopback port.
//! * `hole-bridge`'s `proxy::plugin::start_plugin_chain` — SIP003 plugin port
//!   (TCP or TCP+UDP per the plugin binary's
//!   `hole_common::plugin::plugin_alloc_protocols`).
//! * `plugin-e2e`'s `ssserver::start_real_ss_server*` — in-process shadowsocks
//!   server fixtures.
//!
//! Direct [`free_port`] callers must explicitly justify why the
//! `bind_ephemeral` closure shape doesn't fit, suppressing the
//! `disallowed_methods` clippy lint (see workspace `clippy.toml`). The one
//! current case is `hole-bridge`'s
//! `test_support::port_alloc::allocate_ephemeral_port`, which hands the port
//! across a process boundary via JSON config.
//!
//! The OS kernel has no "free for both TCP and UDP" primitive; we probe
//! one transport via `bind(:0)`, then verify the remaining transports
//! with `ensure_port_free`. Any bind race at either step triggers a
//! fresh iteration with a freshly-allocated candidate port.

use std::io;
use std::net::{IpAddr, SocketAddr};

use tokio::net::{TcpListener, UdpSocket};
use tokio::task::yield_now;
use tracing::{debug, info};

use crate::retry::is_bind_race;

bitflags::bitflags! {
    /// Set of IP transports a port must be simultaneously free for.
    /// Callers compose with `|` (e.g. `Protocols::TCP | Protocols::UDP`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Protocols: u8 {
        const TCP = 0b01;
        const UDP = 0b10;
    }
}

impl std::fmt::Display for Protocols {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        let mut write = |s: &str| -> std::fmt::Result {
            if !first {
                f.write_str(" | ")?;
            }
            first = false;
            f.write_str(s)
        };
        if self.contains(Self::TCP) {
            write("TCP")?;
        }
        if self.contains(Self::UDP) {
            write("UDP")?;
        }
        if first {
            f.write_str("-")?;
        }
        Ok(())
    }
}

/// Find a port on `ip` that was free for every transport in `protocols`
/// at the moment this function returned. Retries unboundedly on transient
/// bind races (see [`is_bind_race`]); yields to the runtime between
/// iterations. Terminates only on success or a non-bind-race error.
///
/// The returned port number carries no reservation — callers must bind
/// it immediately, and even then are subject to TOCTOU against other
/// processes racing for the same ephemeral port. For in-process binders
/// prefer [`bind_ephemeral`], which folds the caller's bind into the
/// same retry loop and has no divorced-port-number TOCTOU window.
///
/// Rejects `Protocols::empty()` with `ErrorKind::InvalidInput` — "find
/// me a free port on no transports" has no meaning.
pub async fn free_port(ip: IpAddr, protocols: Protocols) -> io::Result<u16> {
    if protocols.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "free_port requires a non-empty Protocols set",
        ));
    }

    // TCP first when available — arbitrary ordering; if a caller needs
    // UDP-only the fallback picks UDP.
    let primary = if protocols.contains(Protocols::TCP) {
        Protocols::TCP
    } else {
        Protocols::UDP
    };
    let rest = protocols.difference(primary);

    let mut attempt: u64 = 1;
    loop {
        match free_port_once(ip, primary, rest).await {
            Ok(port) => {
                debug!(
                    target: "util::port_alloc",
                    ip = %ip,
                    port = port,
                    protocols = %protocols,
                    attempts = attempt,
                    "free_port ok"
                );
                return Ok(port);
            }
            Err(e) if is_bind_race(&e) => {
                emit_retry_log(attempt, ip, protocols, &e, "free_port retry");
                attempt = attempt.saturating_add(1);
                yield_now().await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Single iteration of [`free_port`]'s loop: probe the primary transport
/// (gets a port from the OS), then verify the remaining transports.
/// Returns the port on success or the first race/error encountered.
async fn free_port_once(ip: IpAddr, primary: Protocols, rest: Protocols) -> io::Result<u16> {
    let port = probe_bind(SocketAddr::new(ip, 0), primary).await?;
    if !rest.is_empty() {
        ensure_port_free(SocketAddr::new(ip, port), rest).await?;
    }
    Ok(port)
}

/// Probe whether `addr.port()` is free for every transport in
/// `protocols`. Binds one socket per transport, drops each immediately.
/// Returns `Ok(())` on success or the first failure's `io::Error`.
/// No retry — this is a pure probe.
///
/// `Protocols::empty()` returns `Ok(())` (vacuously: "the port is free
/// for no transports" is trivially true).
pub async fn ensure_port_free(addr: SocketAddr, protocols: Protocols) -> io::Result<()> {
    for transport in [Protocols::TCP, Protocols::UDP] {
        if protocols.contains(transport) {
            probe_bind(addr, transport).await?;
        }
    }
    Ok(())
}

/// Bind one socket of the given single transport on `addr`, read
/// `local_addr().port()`, drop. `addr.port() == 0` asks the OS for an
/// ephemeral port; otherwise `addr.port()` is used as-is. Returns the
/// actually-bound port on success.
async fn probe_bind(addr: SocketAddr, transport: Protocols) -> io::Result<u16> {
    debug_assert!(
        transport == Protocols::TCP || transport == Protocols::UDP,
        "probe_bind requires a single transport, got {transport}"
    );
    let result = if transport == Protocols::TCP {
        TcpListener::bind(addr).await.and_then(|l| l.local_addr())
    } else {
        UdpSocket::bind(addr).await.and_then(|s| s.local_addr())
    };
    match &result {
        Ok(bound) => debug!(
            target: "util::port_alloc",
            ip = %addr.ip(),
            port = bound.port(),
            transport = %transport,
            result = "ok",
            "probe_bind"
        ),
        Err(e) => debug!(
            target: "util::port_alloc",
            ip = %addr.ip(),
            port = addr.port(),
            transport = %transport,
            result = "err",
            kind = ?e.kind(),
            code = ?e.raw_os_error(),
            error = %e,
            "probe_bind"
        ),
    }
    result.map(|a| a.port())
}

/// Run `op(port)` against a freshly-allocated port on `ip` that is
/// verified free for every transport in `protocols`. Retries the whole
/// (allocate, bind) cycle on [`is_bind_race`] errors. Unbounded — the
/// only terminations are success or a non-bind-race error. Yields to
/// the runtime between iterations.
///
/// **Scope.** `bind_ephemeral` only retries `is_bind_race` errors that
/// surface from `op` as `io::Error`. Out-of-process binders (e.g. plugin
/// subprocesses that bind the port themselves) report bind failures
/// through other channels (oneshot timeout, exit code, stderr); those
/// are not classified as bind races. The in-process probe step (running
/// before `op` each iteration) is therefore the only `is_bind_race`
/// signal at plugin-subprocess sites — it catches the Windows
/// excluded-range disagreement class before the subprocess spawn. The
/// residual TOCTOU between probe-drop and subprocess-bind is tracked in
/// bindreams/hole#304.
///
/// `op` is `Fn` rather than `FnMut`: each retry re-invokes it
/// independently and per-call state should be created inside the
/// closure rather than carried across attempts.
///
/// Logging: per-iteration `debug!`; `info!` at adaptive milestones (10,
/// 20, 50, 100, 200, 500, 1000, then every 1000 attempts). Total log
/// volume is O(log n) regardless of how long the loop runs. No
/// exhaustion warn — there is no exhaustion.
pub async fn bind_ephemeral<T, F, Fut>(ip: IpAddr, protocols: Protocols, op: F) -> io::Result<(u16, T)>
where
    F: Fn(u16) -> Fut,
    Fut: std::future::Future<Output = io::Result<T>>,
{
    if protocols.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bind_ephemeral requires a non-empty Protocols set",
        ));
    }

    let primary = if protocols.contains(Protocols::TCP) {
        Protocols::TCP
    } else {
        Protocols::UDP
    };
    let rest = protocols.difference(primary);

    let mut attempt: u64 = 1;
    loop {
        match bind_ephemeral_once(ip, primary, rest, &op).await {
            Ok((port, value)) => {
                debug!(
                    target: "util::port_alloc",
                    ip = %ip,
                    port = port,
                    protocols = %protocols,
                    attempts = attempt,
                    "bind_ephemeral ok"
                );
                return Ok((port, value));
            }
            Err(e) if is_bind_race(&e) => {
                emit_retry_log(attempt, ip, protocols, &e, "bind_ephemeral retry");
                attempt = attempt.saturating_add(1);
                yield_now().await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Single iteration of [`bind_ephemeral`]'s loop: probe primary, verify
/// rest, run `op`. Returns `(port, op_result)` on success or the first
/// error from any step.
async fn bind_ephemeral_once<T, F, Fut>(ip: IpAddr, primary: Protocols, rest: Protocols, op: &F) -> io::Result<(u16, T)>
where
    F: Fn(u16) -> Fut,
    Fut: std::future::Future<Output = io::Result<T>>,
{
    let port = probe_bind(SocketAddr::new(ip, 0), primary).await?;
    if !rest.is_empty() {
        ensure_port_free(SocketAddr::new(ip, port), rest).await?;
    }
    let value = op(port).await?;
    Ok((port, value))
}

/// Adaptive retry logging: `debug!` per iteration, plus `info!` at
/// milestones so a stuck loop is visible at the default `info` level
/// without flooding logs on the common happy path.
///
/// `debug!` volume is O(n) (one per iteration) — operators debugging a
/// stuck loop with `HOLE_BRIDGE_LOG=util::port_alloc=debug`
/// should expect proportional volume. `info!` volume is O(log n) by
/// construction via [`is_log_milestone`], so default-log-level
/// observability stays bounded regardless of loop length.
///
/// Milestones: 10, 20, 50, 100, 200, 500, 1000, then every 1000.
fn emit_retry_log(attempt: u64, ip: IpAddr, protocols: Protocols, err: &io::Error, msg: &'static str) {
    // The first attempt is the happy path entry; we only enter this
    // function on retries (attempt >= 1 after a failure), so the
    // smallest value we ever see is 1.
    debug!(
        target: "util::port_alloc",
        attempt = attempt,
        ip = %ip,
        protocols = %protocols,
        error = %err,
        "{}", msg
    );
    if is_log_milestone(attempt) {
        info!(
            target: "util::port_alloc",
            attempt = attempt,
            ip = %ip,
            protocols = %protocols,
            error = %err,
            "{} (milestone)", msg
        );
    }
}

/// True at attempt counts where the retry loop emits an `info!` so a
/// stuck loop becomes visible at the default `hole_bridge=info` log
/// level. Total `info!` volume is O(log n) regardless of loop length.
fn is_log_milestone(attempt: u64) -> bool {
    matches!(attempt, 10 | 20 | 50 | 100 | 200 | 500 | 1000) || (attempt > 1000 && attempt.is_multiple_of(1000))
}

#[cfg(test)]
#[path = "port_alloc_tests.rs"]
mod port_alloc_tests;
