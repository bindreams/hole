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
//! `source()` carries the diagnostic cause and call sites log it as an error
//! value (the chain renders `Display` only, so payload held solely in `Debug`,
//! such as `interface_index`, is not in the chain: the site that builds the
//! error logs it). Two of the three sentences point the user at `bridge.log`,
//! so the cause must travel with the error; the wrappers
//! (`RoutingError::Gateway`, `ProxyError::Gateway`) hold the typed error, so the
//! chain survives them.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GatewayError {
    /// The routing table answered, and the answer is that nothing routes off
    /// this host.
    #[error(
        "No default network route was found. Hole needs an active Internet connection before it \
         can build the tunnel."
    )]
    NoDefaultRoute,

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
