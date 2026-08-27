//! Pure data description of the DNS-egress confinement filter set. No FFI —
//! compiles and is fully testable on every target, including the Linux
//! baseline check. The platform `windows` module is the only place that
//! turns this into live WFP objects.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

/// The one port this confinement ever names in a `Block` filter: DNS. See
/// `Condition::ServerIp` and `Condition::AppId` for the two permits that are
/// deliberately port-agnostic instead (R0-3, Q9).
pub const DNS_PORT: u16 = 53;

/// A plain 128-bit GUID value, independent of the `windows` crate's
/// `windows::core::GUID` (which only exists on Windows) — keeps this module
/// compilable on every target. The platform `windows` module converts
/// to/from `windows::core::GUID`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guid(pub u128);

/// Fresh GUIDs, minted for this confinement only — disjoint from
/// `crate::routing::failclosed::windows::{PROVIDER_GUID, SUBLAYER_GUID,
/// FILTER_GUIDS, LOCKDOWN_FILTER_GUIDS}`. A copy-paste collision here would
/// let a cover's fixed-GUID sweep delete this confinement's filters (or vice
/// versa); `spec_guids_are_disjoint_from_the_cover_guids` (Windows-only, since
/// the cover GUIDs it compares against live in a Windows-gated module) pins
/// it. Individual filters carry no fixed GUID at all — see the module doc on
/// [`super`] for why a dynamic session doesn't need one.
pub const PROVIDER_GUID: Guid = Guid(0x8f1c6a2e_3d47_4b1a_9e02_7c5f3a1b6d40);
pub const SUBLAYER_GUID: Guid = Guid(0x1b9d4e73_6a52_4c8f_b310_2e6d9a4c7f81);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4 {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    ConnectV4,
    ConnectV6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Permit,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// Match the local interface by LUID, protocol, and remote port — the
    /// positive half: DNS is allowed to leave over `hole-tun` itself.
    OnInterface { luid: u64, l4: L4, remote_port: u16 },
    /// Match the loopback network range (127.0.0.0/8 for v4, ::1/128 for
    /// v6 — `addr`'s family selects which), protocol, and remote port. A
    /// local stub resolver (dnscrypt-proxy, Acrylic, a local Pi-hole) is
    /// permitted to receive queries; ITS own upstream query is still
    /// confined by the same rule, so this opens nothing.
    LoopbackNet { addr: IpAddr, l4: L4, remote_port: u16 },
    /// Match the Shadowsocks server's address, on ANY port — deliberately
    /// no port condition. `server_port` has no validation forbidding 53
    /// (a standard censorship-evasion configuration), and without this
    /// permit the confinement would block the tunnel's own handshake
    /// harder than the fail-closed covers permit it (R0-3).
    ServerIp(IpAddr),
    /// Match the connecting process image path — required, not optional
    /// hardening (Q9): without an App-ID permit, a plugin re-resolving a
    /// hostname during the galoshes yamux self-heal can only reach DNS
    /// through the tunnel it is trying to rebuild, a non-recoverable
    /// circular deadlock. WFP is any-sublayer-blocks-wins, so the lockdown
    /// cover's own App-ID permit — living in a different sublayer — cannot
    /// rescue it.
    AppId(PathBuf),
    /// No local-interface / address condition — protocol + remote port
    /// only. The block-all-else half.
    AnyTo { l4: L4, remote_port: u16 },
}

#[derive(Debug, Clone)]
pub struct FilterSpec {
    pub name: &'static str,
    pub layer: Layer,
    pub action: Action,
    pub condition: Condition,
    pub weight: u8,
}

#[derive(Debug, Clone)]
pub struct ConfineSpec {
    pub provider: Guid,
    pub sublayer: Guid,
    pub filters: Vec<FilterSpec>,
}

/// Weight for every `Permit` filter — higher than [`BLOCK_WEIGHT`] so a
/// permit always outranks the block-all within this confinement's own
/// sublayer (no `CLEAR_ACTION_RIGHT`, matching `failclosed/windows.rs`'s
/// weight-only arbitration).
pub const PERMIT_WEIGHT: u8 = 15;
/// Weight for every `Block` filter. `0`, matching
/// `failclosed/windows.rs:245` — an earlier draft used 8 with no rationale,
/// and an unexplained number in a module whose whole argument is
/// "structural, not heuristic" is not worth the question it invites.
pub const BLOCK_WEIGHT: u8 = 0;

/// Build the DNS-egress confinement: permit UDP+TCP/53 on `tun_luid` and on
/// loopback, permit the Shadowsocks server on any port, permit each of
/// `app_ids` on any port, block UDP+TCP/53 everywhere else. Thirteen filters
/// plus two per `app_ids` entry. Pure — no FFI; `windows::engage` submits it
/// in one transaction inside a dynamic (process-scoped) FWPM session.
pub fn build_spec(tun_luid: u64, server_ip: IpAddr, app_ids: &[PathBuf]) -> ConfineSpec {
    let mut filters = Vec::with_capacity(13 + 2 * app_ids.len());

    for l4 in [L4::Udp, L4::Tcp] {
        for (layer, loopback_addr) in [
            (Layer::ConnectV4, IpAddr::V4(Ipv4Addr::LOCALHOST)),
            (Layer::ConnectV6, IpAddr::V6(Ipv6Addr::LOCALHOST)),
        ] {
            filters.push(FilterSpec {
                name: "dns-confine-tun-permit",
                layer,
                action: Action::Permit,
                condition: Condition::OnInterface {
                    luid: tun_luid,
                    l4,
                    remote_port: DNS_PORT,
                },
                weight: PERMIT_WEIGHT,
            });
            filters.push(FilterSpec {
                name: "dns-confine-loopback-permit",
                layer,
                action: Action::Permit,
                condition: Condition::LoopbackNet {
                    addr: loopback_addr,
                    l4,
                    remote_port: DNS_PORT,
                },
                weight: PERMIT_WEIGHT,
            });
            filters.push(FilterSpec {
                name: "dns-confine-block",
                layer,
                action: Action::Block,
                condition: Condition::AnyTo {
                    l4,
                    remote_port: DNS_PORT,
                },
                weight: BLOCK_WEIGHT,
            });
        }
    }

    let server_layer = match server_ip {
        IpAddr::V4(_) => Layer::ConnectV4,
        IpAddr::V6(_) => Layer::ConnectV6,
    };
    filters.push(FilterSpec {
        name: "dns-confine-server-permit",
        layer: server_layer,
        action: Action::Permit,
        condition: Condition::ServerIp(server_ip),
        weight: PERMIT_WEIGHT,
    });

    for path in app_ids {
        for layer in [Layer::ConnectV4, Layer::ConnectV6] {
            filters.push(FilterSpec {
                name: "dns-confine-appid-permit",
                layer,
                action: Action::Permit,
                condition: Condition::AppId(path.clone()),
                weight: PERMIT_WEIGHT,
            });
        }
    }

    ConfineSpec {
        provider: PROVIDER_GUID,
        sublayer: SUBLAYER_GUID,
        filters,
    }
}

#[cfg(test)]
#[path = "spec_tests.rs"]
mod spec_tests;
