//! plugin-e2e's only port-reservation seam.
//!
//! Reserve a cross-process port for the protocols its consumer will bind.
//! Where the consumer is known at reservation time, name it —
//! `hole_common::plugin::plugin_alloc_protocols` keys SS_LOCAL by binary
//! (galoshes TCP+UDP, everything else TCP) and is correct because the bridge
//! knows the binary. Where the reservation happens before the consumer is
//! known, reserve the union over the possible consumers: over-reserving
//! costs a retry, under-reserving costs a race.
//!
//! - [`reserve_ss_local`] — the SIP003 client plugin's local,
//!   data-source-facing endpoint, bound by the child. TCP+UDP because this
//!   harness is generic over client plugins and its consumer set includes
//!   galoshes, whose yamux client binds both there whatever the tunnel is.
//!   It is not that SS_LOCAL is universally TCP+UDP: ex-ray's client inbound
//!   is TCP-only, and the bridge, which knows its binary, correctly reserves
//!   TCP for it.
//! - [`reserve_unbound`] — an endpoint nothing in the test binds, only
//!   dials (or never reaches). Same union, so a later change that does bind
//!   it cannot inherit a narrow reservation.
//! - [`reserve_public`] — parameterised, because its consumer is known and
//!   genuinely varies: ex-ray binds TCP for WS/WS-TLS and UDP for QUIC. Its
//!   argument is "the protocols the plugin subprocess will bind", not "the
//!   protocols the transport uses". Those coincide today; the first is the
//!   reason, the second is a coincidence.

// Every reservation here is handed to a child process that binds it
// out-of-process, so none can be folded into `bind_ephemeral`'s in-process
// closure shape — the documented exception to the bind_ephemeral rule
// (clippy.toml). Module-level: this file holds exactly these three
// functions, so module scope suppresses nothing else.
#![allow(
    clippy::disallowed_methods,
    reason = "every port here crosses a process boundary before it is bound, so it cannot be folded into bind_ephemeral's in-process closure"
)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use util::port_alloc::{free_port, Protocols};

async fn reserve(protocols: Protocols) -> io::Result<SocketAddr> {
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let port = free_port(ip, protocols).await?;
    Ok(SocketAddr::new(ip, port))
}

/// Reserve the SIP003 client plugin's local endpoint (`SS_LOCAL_*`). TCP+UDP
/// — see the module doc for why.
pub async fn reserve_ss_local() -> io::Result<SocketAddr> {
    reserve(Protocols::TCP | Protocols::UDP).await
}

/// Reserve an endpoint that nothing in the test binds. TCP+UDP — see the
/// module doc for why.
pub async fn reserve_unbound() -> io::Result<SocketAddr> {
    reserve(Protocols::TCP | Protocols::UDP).await
}

/// Reserve a plugin's public endpoint for exactly the protocols it will
/// bind there.
pub async fn reserve_public(protocols: Protocols) -> io::Result<SocketAddr> {
    reserve(protocols).await
}

#[cfg(test)]
#[path = "ports_tests.rs"]
mod ports_tests;
