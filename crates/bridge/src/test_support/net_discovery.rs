//! Network facts a test needs about *this host*.
//!
//! Two kinds, and they are not interchangeable:
//!
//! * [`detect_primary_ipv4`] — an address the host **holds**. Traffic to it
//!   never reaches `hole-tun`: the kernel keeps an on-link `/32` for every
//!   local address, and longest-prefix match beats whichever half of the
//!   bridge's `/1` split pair covers it. That makes it the right target for
//!   "Full mode is up and host-local networking still works", and the wrong
//!   one for transit.
//! * [`UNOWNED_DSTS`] — addresses the host provably does **not** hold and
//!   nothing routes, so the covering `/1` half wins and the only thing that
//!   can answer their SYN is the engine's smoltcp stack reading `hole-tun`.
//!   That is the transit oracle; [`probe_tcp`] is how a test reads it.
//!
//! [`block_every_in_tun_flow`] lives here too: it is what keeps the transit
//! oracle safe to run, and both `mod tun` suites need it.

use hole_common::config::{FilterAction, FilterRule, MatchType};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

// Host network snapshot ===============================================================================================

/// One read of this host's network state: the interface enumeration, and the
/// source address the kernel picks for off-link IPv4 traffic.
///
/// Both come from one construction on purpose. They are independent kernel
/// sources — the adapter list and the route table — so checking one against
/// the other is a real cross-check, but reading them at two different times
/// straddles a TUN coming up or going down, and the resulting contradiction
/// surfaces as an ownership failure blaming the wrong subsystem.
pub(crate) struct HostNetwork {
    interfaces: Vec<default_net::Interface>,
    primary_ipv4: Result<Ipv4Addr, String>,
}

impl HostNetwork {
    /// Read the host's interfaces and its off-link source address.
    ///
    /// `default_net::get_interfaces` has no error channel — it returns a bare
    /// `Vec`, and on Windows it fills that vector only inside the
    /// `GetAdaptersAddresses` success branch, with no `else`. So an
    /// enumeration failure is an empty vector, otherwise indistinguishable
    /// from "this host holds nothing at all". Every host holds loopback, so an
    /// empty enumeration *is* that failure and is reported as one: the
    /// ownership oracle every capture test is built on must not read a broken
    /// scan as proof of non-ownership.
    pub(crate) fn read() -> Result<Self, String> {
        let interfaces = default_net::get_interfaces();
        if interfaces.is_empty() {
            return Err(
                "interface enumeration returned nothing, but every host holds loopback — the scan itself failed, \
                 so host address ownership cannot be decided"
                    .to_string(),
            );
        }
        Ok(Self {
            interfaces,
            primary_ipv4: detect_primary_ipv4(),
        })
    }

    /// The source address the kernel picks for off-link IPv4 traffic.
    pub(crate) fn primary_ipv4(&self) -> Result<Ipv4Addr, String> {
        self.primary_ipv4.clone()
    }

    /// Name the interface holding `ip`, if any. Canonicalises both sides so
    /// an IPv4-mapped IPv6 address matches its IPv4 form.
    pub(crate) fn holder_of(&self, ip: IpAddr) -> Option<String> {
        let want = ip.to_canonical();
        self.interfaces
            .iter()
            .find(|iface| {
                iface
                    .ipv4
                    .iter()
                    .map(|net| IpAddr::V4(net.addr))
                    .chain(iface.ipv6.iter().map(|net| IpAddr::V6(net.addr)))
                    .any(|held| held.to_canonical() == want)
            })
            .map(|iface| match &iface.friendly_name {
                Some(friendly) => format!("{friendly} ({})", iface.name),
                None => iface.name.clone(),
            })
    }
}

/// Discover a routable primary IPv4 address: ask the kernel which source it
/// would use for off-link traffic.
///
/// UDP `connect` does no I/O — it runs the route lookup and binds the
/// resulting source address, which `local_addr()` then reports.
/// `default_net::get_default_interface()` is this same read plus a scan for
/// the interface holding the answer, so nothing is lost by skipping it.
///
/// Returns `Err` if the kernel's answer is loopback / link-local /
/// unspecified, which would defeat the purpose of a non-loopback target.
pub(crate) fn detect_primary_ipv4() -> Result<Ipv4Addr, String> {
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

// Unowned probe destinations ==========================================================================================

/// IPv4 transit-oracle destination: `203.0.113.9`, RFC 5737 TEST-NET-3,
/// reserved for documentation. It is in the **high** half of IPv4 space, so
/// `128.0.0.0/1` is the route that captures it.
pub(crate) const UNOWNED_DST_V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 80);

/// IPv6 transit-oracle destination: `2001:db8::9`, RFC 3849 documentation
/// space. It is in the **low** half of IPv6 space, so `::/1` is the route that
/// captures it.
///
/// `fd00::ff00:1/64` reaches smoltcp's address list only — neither platform's
/// setup commands assign an IPv6 address to the adapter — so the source
/// address for this SYN comes from wherever the host's own selection finds
/// one. smoltcp answers it either way: `set_any_ip(true)` does not care what
/// the source is.
pub(crate) const UNOWNED_DST_V6: SocketAddr =
    SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 9)), 80);

/// Every destination the transit oracle probes, one per address family.
///
/// Dialing any of them is dark on an ordinary host. Under `TunnelMode::Full`
/// the covering half of the bridge's `/1` split pair captures the SYN and the
/// in-TUN smoltcp stack answers it, so a connect that gets *any* answer is the
/// observation that the packet crossed the tunnel device. Both families are
/// probed because both families' halves are installed as real routes, and an
/// oracle that watches only one leaves the other's capture unproven.
pub(crate) const UNOWNED_DSTS: [SocketAddr; 2] = [UNOWNED_DST_V4, UNOWNED_DST_V6];

/// Panic if any local interface holds `ip`, or if the ownership scan itself
/// could not run.
///
/// A host that owns the probe destination answers it from its own on-link
/// `/32` and silently voids every assertion built on [`UNOWNED_DSTS`], so this
/// fails as an environment problem rather than as a bridge defect. A scan that
/// failed says nothing either way and fails distinctly.
pub(crate) fn assert_host_does_not_own(ip: IpAddr) {
    let host = HostNetwork::read()
        .unwrap_or_else(|err| panic!("ENVIRONMENT problem (not the bridge): cannot scan host addresses: {err}"));
    if let Some(owner) = host.holder_of(ip) {
        panic!(
            "ENVIRONMENT problem (not the bridge): interface {owner} holds {ip}, so this host answers it locally \
             and no test can use it as a probe destination"
        );
    }
}

// Probing =============================================================================================================

/// What a TCP connect to a probe destination observed.
///
/// `Other` exists so an unrecognised outcome — Windows realistically produces
/// `PermissionDenied` (a host firewall, or a WFP cover held by a concurrent
/// lockdown test), `Uncategorized` — fails loud with its kind named instead of
/// being folded into a bucket that silently flips an assertion's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeOutcome {
    /// The handshake completed.
    Answered,
    /// The SYN drew an RST: something answered, then refused.
    Refused,
    /// The connection was reset.
    Reset,
    /// Nothing answered within the budget, the kernel had no route, or the
    /// kernel had no source address to send from. All three mean the SYN drew
    /// nothing back, which is what "dark" is.
    NoAnswer,
    /// Anything else, with the kind carried for the failure message.
    Other(ErrorKind),
}

/// How long a probe waits for an answer.
///
/// One budget for every probe, dark and capture alike. Windows retransmits an
/// unanswered SYN at t≈0, 3 and 9 s and `connect_timeout` truncates at the
/// budget, so a shorter dark probe cannot see a middlebox's answer to the
/// third retransmit while a longer capture probe can — and a "the environment
/// is dark" precondition then passes alongside a "the tunnel captured it"
/// assertion, both green, with the tunnel broken. Two budgets are only safe if
/// the dark one is the larger; one budget makes the question moot.
///
/// Generous on purpose: a starved runner must not be reported as a capture
/// regression.
pub(crate) const PROBE_BUDGET: Duration = Duration::from_secs(15);

/// Dial `dst` and classify what came back.
pub(crate) fn probe_tcp(dst: SocketAddr) -> ProbeOutcome {
    // External event with a graceful failure bound: the peer is the `hole
    // bridge run` subprocess' packet loop, or nothing at all. The budget is
    // the failure-to-human signal, not intra-process synchronization.
    match std::net::TcpStream::connect_timeout(&dst, PROBE_BUDGET) {
        Ok(_) => ProbeOutcome::Answered,
        Err(err) => match err.kind() {
            ErrorKind::ConnectionRefused => ProbeOutcome::Refused,
            ErrorKind::ConnectionReset => ProbeOutcome::Reset,
            ErrorKind::TimedOut
            | ErrorKind::NetworkUnreachable
            | ErrorKind::HostUnreachable
            // No local source address for the family — the SYN never left.
            | ErrorKind::AddrNotAvailable => ProbeOutcome::NoAnswer,
            other => ProbeOutcome::Other(other),
        },
    }
}

// Full-mode test config ===============================================================================================

/// Resolve every in-TUN flow to a drop.
///
/// Load-bearing in any `TunnelMode::Full` test, not decoration. Without it
/// the in-process ss-server's onward dial to the client's destination leaves
/// via the same routing table, matches the same `/1` split pair, re-enters
/// `hole-tun`, and is proxied again — a self-limiting burst up to the
/// engine's `max_connections` ceiling, but 4096 needless sockets on a runner
/// shared with the serialized WFP tests.
///
/// `MatchType::Subnet` matches on the flow's destination IP, so these two
/// rules cover every flow the router sees.
///
/// Side effect worth naming: with `dns.enabled = false` the router has no
/// `local_dns`, so host UDP/53 falls through the cascade and is dropped
/// silently. A host process resolving a name during the window hangs for its
/// own resolver timeout instead of being proxied. That is a bounded drop
/// replacing a bounded burst, but it is a different failure shape.
///
/// Shared rather than copied: both `mod tun` suites are private sibling
/// submodules that cannot see each other, and two literal copies of an
/// invariant this load-bearing drift.
pub(crate) fn block_every_in_tun_flow() -> Vec<FilterRule> {
    vec![
        FilterRule {
            address: "0.0.0.0/0".into(),
            matching: MatchType::Subnet,
            action: FilterAction::Block,
        },
        FilterRule {
            address: "::/0".into(),
            matching: MatchType::Subnet,
            action: FilterAction::Block,
        },
    ]
}

#[cfg(test)]
#[path = "net_discovery_tests.rs"]
mod net_discovery_tests;
