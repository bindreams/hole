//! DNS-egress confinement: a WFP filter set (Windows) that permits DNS (UDP+TCP
//! port 53) only on `hole-tun` itself, on loopback, and to the Shadowsocks
//! server, blocking it everywhere else. The positive half (giving the OS a
//! resolver it can reach through the tunnel) lives in `crate::net::metric` and
//! the bridge's resolver-IP advertisement.
//!
//! [`spec`] is pure data (no FFI), so it compiles and tests on every target.
//! The platform module turns it into live WFP objects in a **process-scoped,
//! dynamic** FWPM session: the opposite lifetime from `routing::failclosed`'s
//! persistent covers, because a lockdown cover outliving the bridge is the
//! user's intent while a DNS block outliving the bridge is pure harm.
//!
//! The facade is not `#[cfg]`-free for callers: [`spec`] is exported on every
//! target, but `engage`, `DnsConfineError` and `DnsConfinement` exist on Windows
//! only.

pub mod spec;

pub use spec::{
    build_spec, Action, Condition, ConfineSpec, FilterSpec, Guid, Layer, BLOCK_WEIGHT, DNS_PORT, L4, PERMIT_WEIGHT,
};

#[cfg(target_os = "windows")]
#[path = "dns_confine/windows.rs"]
mod platform;

#[cfg(target_os = "windows")]
pub use platform::{engage, DnsConfineError, DnsConfinement};

// Privileged-lane live proof: engages the real WFP confinement against real
// wintun devices. Gated to the elevated `tun` lane by the crate-root `TUN`
// label; excluded from the unprivileged pass. Windows-only: there is no
// confinement on any other platform.
#[cfg(all(test, target_os = "windows"))]
#[path = "dns_confine/privileged_tests.rs"]
mod privileged_tests;
