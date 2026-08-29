//! `tun-engine` — cross-platform TUN device, OS routing, gateway
//! discovery, and a smoltcp-backed packet-loop engine for building
//! split-tunnel VPN/proxy daemons.
//!
//! This crate is independent of any particular tunneling protocol or
//! higher-level application; it provides:
//!
//! - [`routing`] — a [`routing::Routing`] trait, a production
//!   [`routing::SystemRouting`] impl, and a crash-recovery state file.
//! - [`gateway`] — detect the system's default gateway + interface.
//! - [`device`] — cross-platform TUN open (`Device::build(...)`). Windows
//!   additionally provides [`device::wintun`] for wintun.dll pre-loading.
//! - [`engine`] — the packet-loop [`engine::Engine`]; exposes caller-owned
//!   dispatch via the [`engine::Router`] trait + optional
//!   [`engine::DnsInterceptor`] hook.
//! - [`helpers`] — ready-made splice primitives for SOCKS5 proxy, raw
//!   bypass, and SOCKS5 UDP relay — use them inside a `Router` impl.
//! - [`net`] — small OS-level socket-binding utilities.
//!
//! ## Test-isolation contract
//!
//! Production I/O that mutates the host's routing tables MUST go through
//! the [`routing::Routing`] trait. The free functions `setup_routes` and
//! `teardown_routes` are lint-disallowed outside the crate's own internals
//! (see workspace `clippy.toml`). See bindreams/hole#165.

// Install the workspace test subscriber + panic hook. The dev-dep
// is gated on cfg(test) because it isn't linked in non-test builds.
// See `crates/test-observability/` and bindreams/hole#301.
#[cfg(test)]
hole_test_observability::register!();

#[cfg(test)]
fn main() {
    skuld::run_all();
}

/// The elevated-lane label (→ skuld filter name `tun`). skuld requires each
/// label to be declared exactly once per test binary, and every module under
/// this crate compiles into the SAME binary, so this is the crate's only
/// declaration — a second `#[skuld::label] const TUN` anywhere would mint a
/// different serial token and panic the runner at startup.
#[cfg(test)]
#[skuld::label]
pub(crate) const TUN: skuld::Label;

pub mod adapter_cleanup;
pub mod device;
pub mod engine;
pub mod error;
pub mod gateway;
pub mod helpers;
pub mod net;
pub mod routing;
#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub mod sim;

// Dev-only; see the module doc. `cfg(test)` so this crate's own privileged
// tests get it without the feature.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub use device::{Assigned, Device, DeviceConfig, MutDeviceConfig};
pub use engine::{
    DnsInterceptor, Engine, EngineConfig, MutEngineConfig, Router, TcpFlow, TcpMeta, UdpFlow, UdpMeta, UdpSender,
};
pub use error::{DeviceError, EngineError, RoutingError};
pub use gateway::{get_default_gateway_info, GatewayInfo};
pub use routing::{Routing, SystemRoutes, SystemRouting};
