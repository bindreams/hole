//! Gateway-detection failures.
//!
//! # The `Display` / `Debug` split
//!
//! `Display` is the **final user-facing sentence** and nothing else — it is
//! rendered straight into a toast, so it must never carry an adapter alias, an
//! interface index, an address, a path, or an OS error string. Every
//! `#[error(...)]` below is a bare literal with no payload interpolation, which
//! makes that structural rather than a habit.
//!
//! `Debug` carries the diagnostic detail, and the failure call sites log it with
//! `?err`. Three of the four sentences tell the user to read `bridge.log`; if the
//! detail lived only in a `warn!` that someone must remember to write, deleting
//! that line would turn the toast into a promise the log does not keep — leaving
//! support with strictly less than the `"Default Interface not found"` string
//! this type replaces. Carrying it in the error means it travels to every call
//! site on its own.

use std::net::IpAddr;

use thiserror::Error;

/// The upstream route a failure is about. `Debug`-only by design: this is
/// exactly the material that must not reach a toast. Never given a `Display`
/// impl — that would make leaking it a one-character mistake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopDetail {
    /// OS interface alias (Windows connection name, e.g. `Wi-Fi`).
    pub interface_alias: String,
    /// OS interface index.
    pub interface_index: u32,
    /// Next hop the route named. Unspecified means the route is on-link.
    pub next_hop: IpAddr,
}

#[derive(Debug, Error)]
pub enum GatewayError {
    /// The routing table answered, and the answer is that nothing routes off
    /// this host.
    #[error(
        "No default network route was found. Hole needs an active Internet connection before it \
         can build the tunnel."
    )]
    NoDefaultRoute,

    /// Currently unconstructed: an on-link default route classifies as
    /// [`crate::gateway::NextHop::OnLink`] on Windows (which can build an
    /// interface-scoped bypass for it) and as `NoDefaultRoute` on macOS
    /// (which cannot — see `crate::gateway::reject_macos_on_link`). Kept
    /// rather than deleted for the platform-independent copy below, which a
    /// future macOS-support producer can reuse verbatim.
    ///
    /// The copy names two causes and picks neither. On-link is equally the
    /// signature of another VPN's tunnel adapter and of a point-to-point
    /// physical link (cellular/WWAN, PPPoE), and separating them would take an
    /// `IfType` allowlist — the heuristic class this codebase does not allow.
    /// Asserting "a VPN" would be confidently wrong for a mobile user.
    #[error(
        "Your default network route has no gateway Hole can route around, so the tunnel cannot \
         be built. This happens when another VPN is handling your traffic, and on point-to-point \
         links such as some mobile and PPP connections. See bridge.log for the adapter involved."
    )]
    NoUsableGateway { detail: HopDetail },

    /// The route lookup itself failed — distinct from it answering "no route".
    /// `code` is the raw OS status, kept for `bridge.log` so a status this
    /// crate's mapping table does not anticipate is still identifiable.
    #[error("Could not read the system routing table. See bridge.log for details.")]
    RouteQueryFailed { code: u32, source: std::io::Error },

    /// A route was found but its interface could not be named. The alias is not
    /// cosmetic — it is what `netsh interface ip add route`, the system-DNS
    /// capture, and crash-recovery replay all key on.
    #[error("The upstream network adapter could not be identified. See bridge.log for details.")]
    InterfaceNameUnavailable {
        interface_index: u32,
        source: std::io::Error,
    },
}

#[cfg(test)]
#[path = "error_tests.rs"]
mod error_tests;
