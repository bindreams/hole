//! Network facts a test needs about *this host*.
//!
//! Two kinds, and they are not interchangeable:
//!
//! * [`detect_primary_ipv4`] — an address the host **holds**. Traffic to it
//!   never reaches `hole-tun`: the kernel keeps an on-link `/32` for every
//!   local address, and longest-prefix match beats the bridge's `0.0.0.0/1`
//!   split. That makes it the right target for "Full mode is up and
//!   host-local networking still works", and the wrong one for transit.
//! * [`UNOWNED_DST`] — an address the host provably does **not** hold and
//!   nothing routes, so the `/1` split wins and the only thing that can
//!   answer its SYN is the engine's smoltcp stack reading `hole-tun`. That
//!   is the transit oracle; [`probe_tcp`] is how a test reads it.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Discover a routable primary IPv4 address.
///
/// Strategy:
///
/// 1. Prefer `default_net::get_default_interface()` (authoritative).
/// 2. Fallback: bind a UDP socket and `connect()` to a public sentinel
///    (`8.8.8.8:53`). UDP `connect` does no I/O — it just asks the kernel to
///    pick a source address for packets routed to the sentinel. Read that
///    source address with `local_addr()`.
///
/// Returns `Err` if both strategies produce a loopback / link-local /
/// unspecified address (which would defeat the purpose of a non-loopback
/// target).
pub(crate) fn detect_primary_ipv4() -> Result<Ipv4Addr, String> {
    if let Ok(iface) = default_net::get_default_interface() {
        if let Some(v4) = iface.ipv4.into_iter().next() {
            let ip = v4.addr;
            if !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() {
                return Ok(ip);
            }
        }
    }

    // UDP-connect fallback: ask the kernel to pick a source addr without
    // sending anything.
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.connect("8.8.8.8:53").map_err(|e| e.to_string())?;
    match sock.local_addr().map_err(|e| e.to_string())? {
        SocketAddr::V4(v4) => {
            let ip = *v4.ip();
            if ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() {
                Err(format!("detected unusable primary IPv4: {ip}"))
            } else {
                Ok(ip)
            }
        }
        SocketAddr::V6(_) => Err("no IPv4 primary interface".to_string()),
    }
}

// Unowned probe destination ===========================================================================================

/// A destination this host does not own and nothing routes: `203.0.113.9`,
/// RFC 5737 TEST-NET-3, reserved for documentation.
///
/// Dialing it is dark on any ordinary host. Under `TunnelMode::Full` the
/// bridge's `0.0.0.0/1` split captures the SYN and the in-TUN smoltcp stack
/// answers it, so a completed connect *is* the observation that the packet
/// crossed the tunnel device.
pub(crate) const UNOWNED_DST: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 80);

/// Panic if any local interface holds `ip`.
///
/// A host that owns the probe destination answers it from its own on-link
/// `/32` and silently voids every assertion built on [`UNOWNED_DST`], so this
/// fails as an environment problem rather than as a bridge defect.
pub(crate) fn assert_host_does_not_own(ip: IpAddr) {
    let owner = host_interface_holding(ip);
    assert!(
        owner.is_none(),
        "ENVIRONMENT problem (not the bridge): interface {} holds {ip}, so this host answers it locally \
         and no test can use it as a probe destination",
        owner.unwrap_or_default(),
    );
}

/// Name the local interface holding `ip`, if any. Canonicalises both sides so
/// an IPv4-mapped IPv6 address matches its IPv4 form.
pub(crate) fn host_interface_holding(ip: IpAddr) -> Option<String> {
    let want = ip.to_canonical();
    default_net::get_interfaces()
        .into_iter()
        .find(|iface| {
            iface
                .ipv4
                .iter()
                .map(|net| IpAddr::V4(net.addr))
                .chain(iface.ipv6.iter().map(|net| IpAddr::V6(net.addr)))
                .any(|held| held.to_canonical() == want)
        })
        .map(|iface| match iface.friendly_name {
            Some(friendly) => format!("{friendly} ({})", iface.name),
            None => iface.name,
        })
}

/// What a TCP connect to a probe destination observed.
///
/// `Other` exists so an unrecognised outcome — Windows realistically produces
/// `PermissionDenied` (a host firewall, or a WFP cover held by a concurrent
/// lockdown test), `AddrNotAvailable`, `Uncategorized` — fails loud with its
/// kind named instead of being folded into a bucket that silently flips an
/// assertion's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeOutcome {
    /// The handshake completed.
    Answered,
    /// The SYN drew an RST: something answered, then refused.
    Refused,
    /// The connection was reset.
    Reset,
    /// Nothing answered within the budget, or the kernel had no route.
    NoAnswer,
    /// Anything else, with the kind carried for the failure message.
    Other(ErrorKind),
}

/// How long to wait on a probe expected to find nothing. Matches the lockdown
/// probes' failure-to-human signal.
pub(crate) const DARK_PROBE_BUDGET: Duration = Duration::from_secs(5);

/// How long to wait on the capture oracle, where an answer is expected
/// promptly. Generous on purpose: a starved runner must not be reported as a
/// capture regression.
pub(crate) const CAPTURE_PROBE_BUDGET: Duration = Duration::from_secs(15);

/// Dial `dst` and classify what came back.
pub(crate) fn probe_tcp(dst: SocketAddr, budget: Duration) -> ProbeOutcome {
    // External event with a graceful failure bound: the peer is the `hole
    // bridge run` subprocess' packet loop, or nothing at all. The budget is
    // the failure-to-human signal, not intra-process synchronization.
    match std::net::TcpStream::connect_timeout(&dst, budget) {
        Ok(_) => ProbeOutcome::Answered,
        Err(err) => match err.kind() {
            ErrorKind::ConnectionRefused => ProbeOutcome::Refused,
            ErrorKind::ConnectionReset => ProbeOutcome::Reset,
            ErrorKind::TimedOut | ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable => ProbeOutcome::NoAnswer,
            other => ProbeOutcome::Other(other),
        },
    }
}

#[cfg(test)]
#[path = "net_discovery_tests.rs"]
mod net_discovery_tests;
