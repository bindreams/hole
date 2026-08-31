//! Default gateway detection.
//!
//! On Windows the upstream route comes from the OS routing table
//! (`platform::best_route` -> `GetBestRoute2`). On macOS it still comes from the
//! `default-net` crate; see bindreams/hole#798 for why the Windows path could
//! not, and `gateway/error.rs` for the failure vocabulary both share.

pub mod error;

// Named `platform`, not `windows`, so the module does not shadow the `windows`
// crate in this file. Matches `routing/failclosed.rs`.
#[cfg(target_os = "windows")]
#[path = "gateway/windows.rs"]
mod platform;

pub use error::{GatewayError, HopDetail};

/// The raw upstream-route lookup. Public so the privileged integration test can
/// drive it against a real wintun adapter, which is the only proof that this
/// path does not have `default-net`'s interface-type blind spot.
#[cfg(target_os = "windows")]
pub use platform::best_route;

use std::net::IpAddr;

use tracing::{debug, warn};

use crate::net::bind_to_interface_v6;

/// The upstream route's form: a real gateway to bypass through, or on-link
/// (no gateway — the destination is directly reachable off the interface
/// itself). `routing.rs`'s IPv4 bypass builder reads this to choose which
/// route form to emit; `gateway_ip` (below) stays the raw address either way
/// for callers not yet updated to read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextHop {
    /// A real next-hop gateway to route the bypass through.
    Via(IpAddr),
    /// The route has no gateway — the destination is directly attached to
    /// the interface.
    OnLink,
}

/// Gateway detection result, bundling the gateway IP with the original
/// interface name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayInfo {
    /// Default gateway IP address (IPv4 in practice — the default-route lookup
    /// is issued for the IPv4 unspecified address). Unspecified
    /// (`0.0.0.0`/`::`) when [`next_hop`](Self::next_hop) is
    /// [`NextHop::OnLink`] — prefer `next_hop` where the on-link/gateway
    /// distinction matters, since a bare `IpAddr` cannot tell "the unspecified
    /// address" from "no gateway" apart.
    pub gateway_ip: IpAddr,
    /// The route's form — see [`NextHop`].
    pub next_hop: NextHop,
    /// Platform-appropriate interface name for route commands.
    /// On Windows: connection alias (e.g., "Wi-Fi"). On macOS: BSD name (e.g., "en0").
    pub interface_name: String,
    /// OS interface index (used by bypass socket helpers to bind to the
    /// upstream NIC).
    pub interface_index: u32,
    /// Whether the upstream interface can reach an IPv6 destination.
    pub ipv6_available: bool,
}

/// One upstream route, as the OS resolved it.
///
/// Lives here rather than in the platform module so [`classify_hop`] has one
/// body for every platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteHop {
    /// Next hop the route names. Unspecified (`0.0.0.0` / `::`) means the route
    /// is **on-link** — there is no gateway address to point a bypass route at.
    pub next_hop: IpAddr,
    pub interface_index: u32,
    /// OS interface alias.
    pub interface_alias: String,
}

/// Detect the system's default gateway IP and original interface name.
#[cfg(target_os = "windows")]
pub fn get_default_gateway_info() -> Result<GatewayInfo, GatewayError> {
    // The IPv4 unspecified address: a lookup for `::` returns ERROR_NOT_FOUND on
    // a working IPv4-only host, which would render as "no default route".
    let dest = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
    let hop = platform::best_route(dest)?;
    let ipv6_available = hop.as_ref().map(|h| probe_ipv6(h.interface_index)).unwrap_or(false);
    classify_hop(hop, ipv6_available)
}

/// Detect the system's default gateway IP and original interface name.
#[cfg(target_os = "macos")]
pub fn get_default_gateway_info() -> Result<GatewayInfo, GatewayError> {
    let iface = default_net::get_default_interface().map_err(|e| GatewayError::RouteQueryFailed {
        code: 0,
        source: std::io::Error::other(e),
    })?;

    let interface_alias = iface.name.clone();
    let interface_index = interface_index_by_name(&iface.name).map_err(|e| GatewayError::InterfaceNameUnavailable {
        interface_index: iface.index,
        source: e,
    })?;
    let next_hop = iface
        .gateway
        .as_ref()
        .map(|gw| gw.ip_addr)
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

    let ipv6_available = probe_ipv6(interface_index);
    let info = classify_hop(
        Some(RouteHop {
            next_hop,
            interface_index,
            interface_alias,
        }),
        ipv6_available,
    )?;
    reject_macos_on_link(info)
}

/// Detect the upstream route to `dest` — the destination-scoped counterpart
/// of [`get_default_gateway_info`], used where the caller has a specific
/// server address to route around (`SystemRouting::default_gateway`).
///
/// On Windows this asks `GetBestRoute2` for `dest` specifically. `default-net`
/// (the macOS backend) has no destination-scoped query — it can only answer
/// "what is the default route" — so `dest` is unused there and the answer is
/// always [`get_default_gateway_info`]'s.
#[cfg(target_os = "windows")]
pub fn upstream_route(dest: IpAddr) -> Result<GatewayInfo, GatewayError> {
    let hop = platform::best_route(dest)?;
    let ipv6_available = hop.as_ref().map(|h| probe_ipv6(h.interface_index)).unwrap_or(false);
    classify_hop(hop, ipv6_available)
}

/// Detect the upstream route to `dest` — see the Windows doc above for why
/// `dest` is unused on macOS.
#[cfg(target_os = "macos")]
pub fn upstream_route(_dest: IpAddr) -> Result<GatewayInfo, GatewayError> {
    get_default_gateway_info()
}

/// Turn a resolved route into a [`GatewayInfo`], or into the reason Hole cannot
/// use it.
///
/// Every branch keys on a **structural** property of what the OS returned — the
/// absence of a route, an unnamed interface. None of them inspects the
/// adapter's type or name: separating "another VPN's tunnel" from "a
/// point-to-point physical link" would take an `IfType` allowlist, which is
/// the heuristic class this codebase does not allow. An unspecified next hop
/// is a route **form** (on-link), not a refusal — see [`NextHop`]; a caller
/// that cannot use an on-link route (macOS has no interface-scoped IPv4
/// bypass — see `reject_macos_on_link`) rejects it itself, after this
/// classification, rather than this shared function guessing on the caller's
/// behalf.
///
/// The refusal branches carry the hop into the error rather than dropping it —
/// see `gateway/error.rs` for why that is the guarantee and the `warn!` is only
/// a convenience.
pub(crate) fn classify_hop(hop: Option<RouteHop>, ipv6_available: bool) -> Result<GatewayInfo, GatewayError> {
    let Some(hop) = hop else {
        warn!("no default route: nothing routes off this host");
        return Err(GatewayError::NoDefaultRoute);
    };

    if hop.interface_alias.is_empty() {
        warn!(
            interface_index = hop.interface_index,
            %hop.next_hop,
            "upstream route names an interface with no alias"
        );
        return Err(GatewayError::InterfaceNameUnavailable {
            interface_index: hop.interface_index,
            source: std::io::Error::other("interface alias is empty"),
        });
    }

    let next_hop = if hop.next_hop.is_unspecified() {
        debug!(
            interface_alias = %hop.interface_alias,
            interface_index = hop.interface_index,
            "default route is on-link — no next-hop gateway"
        );
        NextHop::OnLink
    } else {
        NextHop::Via(hop.next_hop)
    };

    Ok(GatewayInfo {
        gateway_ip: hop.next_hop,
        next_hop,
        interface_name: hop.interface_alias,
        interface_index: hop.interface_index,
        ipv6_available,
    })
}

/// macOS has no interface-scoped IPv4 bypass form (`routing.rs`'s Windows
/// IPv4 bypass builder does; the macOS one does not), so an on-link default
/// route stays a refusal there even though [`classify_hop`] now accepts it.
/// `NoDefaultRoute` rather than `NoUsableGateway`: that message described
/// exactly the condition Windows now supports, so reusing it where it is
/// still unsupported would tell a macOS user something false about what
/// Hole can do.
///
/// Pure and platform-independent so it is testable without macOS: the
/// platform gate lives at its one call site
/// ([`get_default_gateway_info`](self)'s `#[cfg(target_os = "macos")]` arm),
/// not in this function.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn reject_macos_on_link(info: GatewayInfo) -> Result<GatewayInfo, GatewayError> {
    match info.next_hop {
        NextHop::OnLink => Err(GatewayError::NoDefaultRoute),
        NextHop::Via(_) => Ok(info),
    }
}

// Interface index detection ===========================================================================================

/// Resolve an interface's OS index from its route-command name (Windows:
/// friendly name/alias, e.g. `hole-tun`; macOS: BSD name, e.g. `utun7`).
/// Shared by upstream-gateway lookup and [`tun_ipv6_available`], which needs
/// the TUN's own index rather than the upstream one.
#[cfg(target_os = "windows")]
pub(crate) fn interface_index_by_name(name: &str) -> std::io::Result<u32> {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::NO_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex};
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    let alias = HSTRING::from(name);
    let mut luid = NET_LUID_LH::default();
    let err = unsafe { ConvertInterfaceAliasToLuid(&alias, &mut luid) };
    if err != NO_ERROR {
        return Err(std::io::Error::other(format!(
            "ConvertInterfaceAliasToLuid: error {err:?}"
        )));
    }
    let mut index = 0u32;
    let err = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
    if err != NO_ERROR {
        return Err(std::io::Error::other(format!(
            "ConvertInterfaceLuidToIndex: error {err:?}"
        )));
    }
    Ok(index)
}

/// Resolve an interface's OS index from its route-command name (Windows:
/// friendly name/alias; macOS: BSD name, e.g. `utun7`). Shared by
/// upstream-gateway lookup and [`tun_ipv6_available`], which needs the TUN's
/// own index rather than the upstream one.
#[cfg(target_os = "macos")]
pub(crate) fn interface_index_by_name(name: &str) -> std::io::Result<u32> {
    let c_name =
        std::ffi::CString::new(name).map_err(|e| std::io::Error::other(format!("invalid interface name: {e}")))?;
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 {
        return Err(std::io::Error::other(format!("if_nametoindex failed for '{name}'")));
    }
    Ok(idx)
}

// IPv6 availability probes ============================================================================================

/// A fresh IPv6 UDP socket scoped to `interface_index`, or `None` if that
/// interface has no IPv6 binding at all (e.g. `DisabledComponents`, or an EDR
/// policy that unbinds IPv6 from the adapter) — the scoping call itself is
/// what fails there, before any network I/O.
fn bound_ipv6_socket(interface_index: u32) -> Option<socket2::Socket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .ok()?;
    bind_to_interface_v6(&socket, interface_index).ok()?;
    Some(socket)
}

/// Whether `interface_index` has an IPv6 binding, with no attempt to reach
/// anywhere. Used where the question is "can a route command targeting this
/// specific interface succeed", not "can this interface reach the internet"
/// — see [`tun_ipv6_available`].
fn probe_ipv6_bound(interface_index: u32) -> bool {
    bound_ipv6_socket(interface_index).is_some()
}

/// Whether `interface_index` can reach a real IPv6 destination. Used for the
/// upstream gateway, where "bound but no route to the internet" is a
/// legitimate state — see [`GatewayInfo::ipv6_available`]'s doc.
///
/// Deliberately still a socket probe, on both platforms: `connect()` on a UDP
/// socket sends nothing — it is a route lookup **plus source-address
/// selection** — and `GetBestRoute2` reports the second half separately, so a
/// route-table replacement is not equivalent on a host that has a route but no
/// usable source address.
fn probe_ipv6(interface_index: u32) -> bool {
    let Some(socket) = bound_ipv6_socket(interface_index) else {
        return false;
    };
    let target: std::net::SocketAddrV6 = "[2606:4700:4700::1111]:443".parse().unwrap();
    socket
        .connect(&socket2::SockAddr::from(std::net::SocketAddr::V6(target)))
        .is_ok()
}

/// Whether the TUN device named `tun_name` has an IPv6 binding. Meant to be
/// probed AFTER the OS creates the adapter, so it reflects the interface the
/// IPv6 split-route commands (`SetupCommand`) actually target — unlike
/// [`GatewayInfo::ipv6_available`], which measures the upstream interface the
/// commands do NOT name. `false` on any resolution failure (including the
/// adapter not existing yet): `SetupCommand::fatal` treats `false` as
/// "tolerate this command failing", never as "skip issuing it".
pub fn tun_ipv6_available(tun_name: &str) -> bool {
    match interface_index_by_name(tun_name) {
        Ok(index) => probe_ipv6_bound(index),
        Err(_) => false,
    }
}

#[cfg(test)]
#[path = "gateway_tests.rs"]
mod gateway_tests;
