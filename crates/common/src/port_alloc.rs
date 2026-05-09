//! Ephemeral port allocation with multi-transport verification and retry
//! around Windows-specific bind races (WSAEACCES from independent TCP/UDP
//! excluded-port-range tables, WSAEADDRINUSE from `SO_EXCLUSIVEADDRUSE`
//! wildcard holders, WSAEADDRNOTAVAIL from the same reservation layer).
//!
//! [`bind_with_retry`] is the canonical entry point: it composes
//! [`free_port`] (which probes once per transport with internal retry
//! on probe-side races) with a caller-supplied bind closure, and retries
//! the whole (allocate, bind) cycle on [`is_bind_race`] errors that
//! surface from the closure. This absorbs the residual TOCTOU between
//! `free_port`'s probe-drop and the real owner's bind.
//!
//! Three consumers in the bridge route through `bind_with_retry`:
//!
//! * [`crate::dns::server::LocalDnsServer::bind`][0] (via hole-bridge) —
//!   UDP+TCP on the same ephemeral loopback port.
//! * `proxy::plugin::start_plugin_chain` — SIP003 plugin port (TCP or
//!   TCP+UDP depending on plugin's `udp_supported` bit).
//! * `test_support::ssserver::start_real_ss_server*` — in-process
//!   shadowsocks server fixtures.
//!
//! Direct `free_port` callers must explicitly justify why the
//! `bind_with_retry` closure shape doesn't fit, suppressing the
//! `disallowed_methods` clippy lint (see workspace `clippy.toml`). The
//! one current case is `test_support::port_alloc::allocate_ephemeral_port`,
//! which hands the port across a process boundary via JSON config.
//!
//! [0]: https://github.com/bindreams/hole/blob/main/crates/bridge/src/dns/server.rs
//!
//! The OS kernel has no "free for both TCP and UDP" primitive; we probe
//! one transport via `bind(:0)`, then verify the remaining transports
//! with `ensure_port_free`. Any bind race at either step triggers a
//! retry with a freshly-allocated candidate port.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;

use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, info, warn};

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

/// Maximum attempts `free_port` will make before propagating the last
/// transient-bind-race error. Five balances "cover the reasonable number
/// of bad picks even on a heavily-reserved Windows machine" against
/// "fail fast enough to not mask a real saturation bug." Galoshes#21
/// uses 3; we pick 5 because our multi-protocol probe has two OS
/// lookups per attempt (TCP + UDP) vs garter's single TCP probe.
const MAX_BIND_ATTEMPTS: NonZeroU32 = NonZeroU32::new(5).unwrap();

/// Find a port on `ip` that was free for every transport in `protocols`
/// at the moment this function returned. Retries internally on transient
/// bind races (see [`is_bind_race`]) up to [`MAX_BIND_ATTEMPTS`]. On
/// exhaustion returns the last underlying `io::Error`.
///
/// The returned port number carries no reservation — callers must bind
/// it immediately, and even then are subject to TOCTOU against other
/// processes racing for the same ephemeral port. For cross-test
/// serialization within the hole-bridge test suite, the `PORT_ALLOC`
/// skuld label still applies.
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

    let n = MAX_BIND_ATTEMPTS.get();
    let mut last_err: Option<io::Error> = None;
    let mut last_port: Option<u16> = None;

    // TCP first when available — arbitrary ordering; if a caller needs
    // UDP-only the fallback picks UDP.
    let primary = if protocols.contains(Protocols::TCP) {
        Protocols::TCP
    } else {
        Protocols::UDP
    };
    let rest = protocols.difference(primary);

    for attempt in 0..n {
        if attempt > 0 {
            info!(
                target: "hole_common::port_alloc",
                attempt = attempt,
                max_attempts = n,
                ip = %ip,
                protocols = %protocols,
                last_port = last_port.unwrap_or(0),
                reason = "bind_race",
                "free_port_retry"
            );
        }
        let port = match probe_bind(SocketAddr::new(ip, 0), primary).await {
            Ok(p) => p,
            Err(e) if is_bind_race(&e) && attempt + 1 < n => {
                last_port = None;
                last_err = Some(e);
                continue;
            }
            Err(e) => {
                warn!(
                    target: "hole_common::port_alloc",
                    ip = %ip,
                    protocols = %protocols,
                    attempts = attempt + 1,
                    error = %e,
                    "free_port exhausted"
                );
                return Err(e);
            }
        };
        last_port = Some(port);
        if rest.is_empty() {
            debug!(
                target: "hole_common::port_alloc",
                ip = %ip,
                port = port,
                protocols = %protocols,
                attempts = attempt + 1,
                "free_port ok"
            );
            return Ok(port);
        }
        match ensure_port_free(SocketAddr::new(ip, port), rest).await {
            Ok(()) => {
                debug!(
                    target: "hole_common::port_alloc",
                    ip = %ip,
                    port = port,
                    protocols = %protocols,
                    attempts = attempt + 1,
                    "free_port ok"
                );
                return Ok(port);
            }
            Err(e) if is_bind_race(&e) && attempt + 1 < n => {
                last_err = Some(e);
            }
            Err(e) => {
                warn!(
                    target: "hole_common::port_alloc",
                    ip = %ip,
                    protocols = %protocols,
                    attempts = attempt + 1,
                    error = %e,
                    "free_port exhausted"
                );
                return Err(e);
            }
        }
    }
    let err = last_err.expect("NonZeroU32 guarantees at least one attempt recorded an error");
    warn!(
        target: "hole_common::port_alloc",
        ip = %ip,
        protocols = %protocols,
        attempts = n,
        error = %err,
        "free_port exhausted"
    );
    Err(err)
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
            target: "hole_common::port_alloc",
            ip = %addr.ip(),
            port = bound.port(),
            transport = %transport,
            result = "ok",
            "probe_bind"
        ),
        Err(e) => debug!(
            target: "hole_common::port_alloc",
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

/// Default outer-retry budget for [`bind_with_retry`]. Five matches the
/// inner [`MAX_BIND_ATTEMPTS`] budget — worst-case 25 attempts. Each
/// attempt is fast for in-process binders (one OS bind + drop). Callers
/// that pay per-attempt subprocess startup cost should pass a smaller
/// budget explicitly.
pub const BIND_RETRY_ATTEMPTS: NonZeroU32 = NonZeroU32::new(5).unwrap();

/// Run `op(port)` against a freshly-allocated port on `ip` that is
/// verified free for every transport in `protocols`. Retries the whole
/// (allocate, bind) cycle on [`is_bind_race`] errors up to `attempts`.
/// Returns the bound port and `op`'s value on success.
///
/// **Scope.** `bind_with_retry` only retries `is_bind_race` errors that
/// surface from `op` as `io::Error`. Out-of-process binders (e.g. plugin
/// subprocesses that bind the port themselves) report bind failures
/// through other channels (oneshot timeout, exit code, stderr); those
/// are not retried here. Use `bind_with_retry` for structural consistency
/// at every ephemeral-bind site, but expect the retry to be load-bearing
/// only for in-process binders.
///
/// `op` is `Fn` rather than `FnMut`: each retry re-invokes it
/// independently and per-call state should be created inside the
/// closure rather than carried across attempts.
///
/// Logging mirrors [`free_port`]: outer retries emit `info!`, exhaustion
/// emits `warn!`, target `hole_common::port_alloc`.
pub async fn bind_with_retry<T, F, Fut>(
    ip: IpAddr,
    protocols: Protocols,
    attempts: NonZeroU32,
    op: F,
) -> io::Result<(u16, T)>
where
    F: Fn(u16) -> Fut,
    Fut: std::future::Future<Output = io::Result<T>>,
{
    let n = attempts.get();
    let mut last_err: Option<io::Error> = None;
    for attempt in 0..n {
        if attempt > 0 {
            info!(
                target: "hole_common::port_alloc",
                attempt = attempt,
                max_attempts = n,
                ip = %ip,
                protocols = %protocols,
                "bind_with_retry retry"
            );
        }
        // bind_with_retry IS the canonical caller of free_port — the
        // disallowed_methods lint rule applies to higher-level callers
        // that should be using this wrapper. See workspace `clippy.toml`.
        #[allow(clippy::disallowed_methods)]
        let port = free_port(ip, protocols).await?;
        match op(port).await {
            Ok(value) => return Ok((port, value)),
            Err(e) if is_bind_race(&e) && attempt + 1 < n => {
                last_err = Some(e);
            }
            Err(e) => {
                // Two cases reach this arm: (a) the final retry's
                // bind-race exhausted the budget, (b) any attempt
                // returned a non-bind-race error. Only (a) is "retry
                // exhausted"; (b) is immediate propagation.
                if is_bind_race(&e) && attempt + 1 == n {
                    warn!(
                        target: "hole_common::port_alloc",
                        attempts = n,
                        ip = %ip,
                        protocols = %protocols,
                        error = %e,
                        "bind_with_retry exhausted"
                    );
                }
                return Err(e);
            }
        }
    }
    let err = last_err.expect("NonZeroU32 guarantees at least one attempt recorded an error");
    warn!(
        target: "hole_common::port_alloc",
        attempts = n,
        ip = %ip,
        protocols = %protocols,
        error = %err,
        "bind_with_retry exhausted"
    );
    Err(err)
}

#[cfg(test)]
#[path = "port_alloc_tests.rs"]
mod port_alloc_tests;
