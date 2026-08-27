//! DNS-egress confinement — a WFP filter set (Windows) that permits DNS
//! (UDP+TCP port 53) only on `hole-tun` itself, on loopback, to the
//! Shadowsocks server, and to the process paths that must be able to
//! resolve off-tunnel (see [`spec::Condition::AppId`]), blocking it
//! everywhere else. This is the *negative* half of #846: the positive half
//! (give the OS a resolver it can reach through the tunnel) stays where it
//! is, in `crate::net::metric` + the bridge's existing resolver-IP
//! advertisement.
//!
//! [`spec`] is pure data — no FFI, compiles and tests on every target.
//! The platform module that turns it into live WFP objects (added in a
//! **process-scoped, dynamic** FWPM session — the opposite lifetime from
//! `routing::failclosed`'s persistent covers, and deliberately so: a
//! lockdown cover outliving the bridge is the user's intent, a DNS block
//! outliving the bridge is pure harm) lands alongside it.
//!
//! `#[cfg]`-free facade, mirroring `routing::failclosed`'s shape.

pub mod spec;

pub use spec::{
    build_spec, Action, Condition, ConfineSpec, FilterSpec, Guid, Layer, BLOCK_WEIGHT, DNS_PORT, L4, PERMIT_WEIGHT,
};
