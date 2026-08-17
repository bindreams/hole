//! Windows upstream-route lookup.
//!
//! Asks the OS routing table via [`GetBestRoute2`], which performs the full
//! next-hop selection itself. The `default-net` crate this replaced did not read
//! the routing table at all: it UDP-`connect()`ed to a public address to learn
//! the OS-chosen source address, then scanned `GetAdaptersAddresses` for an
//! adapter carrying it — **skipping every adapter whose `IfType` was not in its
//! own hard-coded allowlist**. Wintun reports `IF_TYPE_PROP_VIRTUAL` (53), which
//! is absent from that list, so a WireGuard/wintun adapter holding the default
//! route (and Hole's own `hole-tun`) was invisible and the scan returned
//! `"Default Interface not found"`. See bindreams/hole#798.
//!
//! Two properties follow from asking the routing table instead of a socket: no
//! adapter class can be filtered out, and no socket is opened — so the lookup is
//! unaffected by the fail-closed WFP cover that is already engaged by the time
//! the bridge asks (`proxy_manager::start` engages it before `start_inner`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ::windows::Win32::Foundation::{
    ERROR_HOST_UNREACHABLE, ERROR_NETWORK_UNREACHABLE, ERROR_NOT_FOUND, NO_ERROR, WIN32_ERROR,
};
use ::windows::Win32::NetworkManagement::IpHelper::{ConvertInterfaceLuidToAlias, GetBestRoute2, MIB_IPFORWARD_ROW2};
use ::windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use ::windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_INET};
use tracing::{debug, warn};

use super::{GatewayError, RouteHop};

/// Windows caps an interface alias at `NDIS_IF_MAX_STRING_SIZE` (255) WCHARs,
/// plus the NUL `ConvertInterfaceLuidToAlias` writes.
const IF_ALIAS_BUF: usize = 256;

/// Classify a `GetBestRoute2` status.
///
/// `None` means "not a failure — the caller returns `Ok(None)`". Keeping the
/// reachability family out of the error type is what stops a "there is no route"
/// answer from rendering as "Could not read the system routing table": the
/// routing table was read fine, and it said no.
///
/// Pure over the status code so the mapping is testable without provoking a real
/// OS failure. Anything unanticipated falls through to a query failure carrying
/// its raw code — a real diagnostic beats a wrong reassurance, and the code keeps
/// it identifiable in `bridge.log`.
pub(crate) fn map_query_error(code: u32) -> Option<GatewayError> {
    let reachability = [ERROR_NETWORK_UNREACHABLE.0, ERROR_HOST_UNREACHABLE.0, ERROR_NOT_FOUND.0];
    if reachability.contains(&code) {
        return None;
    }
    Some(GatewayError::RouteQueryFailed {
        code,
        source: std::io::Error::from_raw_os_error(code as i32),
    })
}

/// Ask the OS which route it would use to reach `dest`.
///
/// Three outcomes, deliberately distinct: `Ok(Some)` is a route, `Ok(None)` is a
/// definitive "no route", `Err` is "the query itself failed".
///
/// Does **not** judge the next hop — an on-link answer is legitimate for a caller
/// asking about a specific destination. Classification is
/// [`super::classify_hop`]'s job.
pub(crate) fn best_route(dest: IpAddr) -> Result<Option<RouteHop>, GatewayError> {
    let dest_sa = to_sockaddr_inet(dest);
    let mut row = MIB_IPFORWARD_ROW2::default();
    let mut best_source = SOCKADDR_INET::default();

    // SAFETY: `GetBestRoute2` reads `dest_sa` and writes `row` / `best_source`,
    // all three owned locals of the exact FFI types. The optional LUID and
    // source-address parameters are `None` (unscoped lookup, OS-chosen source).
    let status = unsafe {
        GetBestRoute2(
            None,
            0,
            None,
            &dest_sa,
            0,
            &mut row as *mut MIB_IPFORWARD_ROW2,
            &mut best_source as *mut SOCKADDR_INET,
        )
    };

    if status != NO_ERROR {
        return match map_query_error(status.0) {
            None => {
                debug!(%dest, status = status.0, "no route to destination");
                Ok(None)
            }
            Some(err) => {
                warn!(%dest, status = status.0, "GetBestRoute2 failed");
                Err(err)
            }
        };
    }

    let interface_index = row.InterfaceIndex;
    let interface_alias = interface_alias(&row.InterfaceLuid, interface_index)?;
    let next_hop = from_sockaddr_inet(&row.NextHop);

    debug!(%dest, %next_hop, interface_index, interface_alias, "resolved upstream route");
    Ok(Some(RouteHop {
        next_hop,
        interface_index,
        interface_alias,
    }))
}

fn interface_alias(luid: &NET_LUID_LH, interface_index: u32) -> Result<String, GatewayError> {
    let mut buf = [0u16; IF_ALIAS_BUF];
    // SAFETY: `luid` is a live reference and `buf` is a fixed-size owned array;
    // the binding passes its length, so the callee cannot overrun it.
    let status: WIN32_ERROR = unsafe { ConvertInterfaceLuidToAlias(luid, &mut buf) };
    if status != NO_ERROR {
        return Err(GatewayError::InterfaceNameUnavailable {
            interface_index,
            source: std::io::Error::from_raw_os_error(status.0 as i32),
        });
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Ok(String::from_utf16_lossy(&buf[..len]))
}

// SOCKADDR_INET conversion ============================================================================================

fn to_sockaddr_inet(addr: IpAddr) -> SOCKADDR_INET {
    let mut sa = SOCKADDR_INET::default();
    match addr {
        IpAddr::V4(v4) => {
            sa.Ipv4.sin_family = AF_INET;
            sa.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
        }
        IpAddr::V6(v6) => {
            sa.Ipv6.sin6_family = AF_INET6;
            sa.Ipv6.sin6_addr.u.Byte = v6.octets();
        }
    }
    sa
}

fn from_sockaddr_inet(sa: &SOCKADDR_INET) -> IpAddr {
    // SAFETY: `SOCKADDR_INET` is a union whose `si_family` discriminant is
    // readable from every variant (all begin with the family field), and the
    // matching variant is read only for its own family.
    let family = unsafe { sa.si_family };
    if family == AF_INET6 {
        let bytes = unsafe { sa.Ipv6.sin6_addr.u.Byte };
        return IpAddr::V6(Ipv6Addr::from(bytes));
    }
    // AF_INET, and AF_UNSPEC — which `GetBestRoute2` reports for an on-link
    // route with no next hop. Both read as the IPv4 address field, and
    // AF_UNSPEC's zeroed field is the unspecified address, which is exactly the
    // on-link marker `classify_hop` keys on.
    let raw = unsafe { sa.Ipv4.sin_addr.S_un.S_addr };
    IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes()))
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
