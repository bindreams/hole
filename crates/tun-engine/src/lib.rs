//! `tun-engine` — cross-platform TUN device, OS routing, and gateway
//! discovery primitives for building split-tunnel VPN/proxy daemons.
//!
//! This crate is independent of any particular tunneling protocol or
//! higher-level application; it provides:
//!
//! - [`routing`] — a [`Routing`] trait, a production [`SystemRouting`] impl
//!   that shells out to `netsh` / `route(8)`, and a crash-recovery state
//!   file (`bridge-routes.json`).
//! - [`gateway`] — detect the system's default gateway + interface.
//! - [`device::wintun`] (Windows-only) — resolve and pre-load `wintun.dll`.
//! - [`net`] — small OS-level socket-binding utilities.
//!
//! ## Test-isolation contract
//!
//! Production I/O that mutates the host's routing tables MUST go through
//! the [`Routing`] trait. The free functions `setup_routes` and
//! `teardown_routes` are lint-disallowed outside the crate's own internals
//! (see workspace `clippy.toml`). This is a hard guard-rail — see
//! bindreams/hole#165.

#[cfg(test)]
fn main() {
    skuld::run_all();
}

pub mod device;
pub mod error;
pub mod gateway;
pub mod net;
pub mod routing;

pub use error::{DeviceError, RoutingError};
pub use gateway::{get_default_gateway_info, GatewayInfo};
pub use routing::{Routing, SystemRoutes, SystemRouting};
