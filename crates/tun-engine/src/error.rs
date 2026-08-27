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
    /// A pre-existing adapter named `alias` does not carry Hole's own
    /// adapter GUID — it belongs to something else (most often a build of
    /// Hole itself that crashed before it could tear the adapter down; see
    /// `crates/tun-engine/src/device/identity.rs`). PII-free and
    /// actionable: names no filesystem path, and points at the escape.
    #[error("an existing '{alias}' adapter does not belong to Hole; run scripts/network-reset.py to remove it")]
    ForeignAdapter { alias: String },
}

/// Errors surfaced by the `engine` module.
#[derive(Debug, Error)]
pub enum EngineError {
    #[error("engine setup failed: {0}")]
    Setup(String),
}
