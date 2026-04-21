//! Ephemeral port allocation with multi-transport verification and retry
//! around Windows-specific bind races (WSAEACCES from independent TCP/UDP
//! excluded-port-range tables, WSAEADDRINUSE from `SO_EXCLUSIVEADDRUSE`
//! wildcard holders, WSAEADDRNOTAVAIL from the same reservation layer).
//!
//! Three consumers in the bridge:
//!
//! * [`crate::dns::server::LocalDnsServer::bind`][0] (via hole-bridge) —
//!   UDP+TCP on the same ephemeral loopback port.
//! * `test_support::port_alloc::allocate_ephemeral_port` — subprocess
//!   port handoff in tests.
//! * `proxy::plugin::start_plugin_chain` — SIP003 plugin port (TCP or
//!   TCP+UDP depending on plugin's `udp_supported` bit).
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
use std::time::Duration;

use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, info, warn};

use crate::retry::{is_bind_race, retry_if_async};

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

    let attempt = std::cell::Cell::new(0u32);
    let last_port = std::cell::Cell::new(None::<u16>);
    let n = MAX_BIND_ATTEMPTS.get();

    let result = retry_if_async(
        || {
            let current = attempt.get();
            attempt.set(current + 1);
            let last_port = &last_port;
            async move {
                if current > 0 {
                    info!(
                        target: "hole_common::port_alloc",
                        attempt = current,
                        max_attempts = n,
                        ip = %ip,
                        protocols = %protocols,
                        last_port = last_port.get().unwrap_or(0),
                        reason = "bind_race",
                        "free_port_retry"
                    );
                }
                // TCP first when available — arbitrary ordering; if a
                // caller needs UDP-only the fallback picks UDP.
                let primary = if protocols.contains(Protocols::TCP) {
                    Protocols::TCP
                } else {
                    Protocols::UDP
                };
                let port = probe_bind(SocketAddr::new(ip, 0), primary).await?;
                last_port.set(Some(port));
                let rest = protocols.difference(primary);
                if !rest.is_empty() {
                    ensure_port_free(SocketAddr::new(ip, port), rest).await?;
                }
                Ok::<u16, io::Error>(port)
            }
        },
        is_bind_race,
        MAX_BIND_ATTEMPTS,
        Duration::ZERO,
    )
    .await;

    let attempts = attempt.get();
    match &result {
        Ok(port) => debug!(
            target: "hole_common::port_alloc",
            ip = %ip,
            port = port,
            protocols = %protocols,
            attempts = attempts,
            "free_port ok"
        ),
        Err(e) => warn!(
            target: "hole_common::port_alloc",
            ip = %ip,
            protocols = %protocols,
            attempts = attempts,
            error = %e,
            "free_port exhausted"
        ),
    }
    result
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

#[cfg(test)]
#[path = "port_alloc_tests.rs"]
mod port_alloc_tests;
