//! Error types for tun-engine submodules.

use std::path::PathBuf;

use thiserror::Error;

/// Errors surfaced by the `routing` module: gateway discovery and route
/// table manipulation.
#[derive(Debug, Error)]
pub enum RoutingError {
    #[error("gateway detection failed: {0}")]
    Gateway(String),
    #[error("route setup failed: {0}")]
    RouteSetup(String),
}

/// Errors surfaced by the `device` module: TUN lifecycle and platform
/// driver loading.
#[derive(Debug, Error)]
pub enum DeviceError {
    #[error("TUN device open failed: {0}")]
    TunOpen(#[source] std::io::Error),
    #[error("invalid device config: {0}")]
    InvalidConfig(&'static str),
    #[error("wintun.dll not found (tried: {})", .tried.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", "))]
    WintunMissing { tried: Vec<PathBuf> },
    #[error("wintun.dll load failed at {}: {message}", .path.display())]
    WintunLoad { path: PathBuf, message: String },
    /// The device exists; its IPv6 address does not. `index` is `0` — the
    /// reserved sentinel — when no interface index could be derived at all.
    #[error("IPv6 address assignment failed on interface {index}: {message}")]
    Ipv6Assign { index: u32, message: String },
}

/// Errors surfaced by the `engine` module.
#[derive(Debug, Error)]
pub enum EngineError {
    #[error("engine setup failed: {0}")]
    Setup(String),
}
