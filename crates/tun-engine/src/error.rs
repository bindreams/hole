//! Error types for tun-engine submodules.

use std::path::PathBuf;

use thiserror::Error;

use crate::gateway::GatewayError;

/// Errors surfaced by the `routing` module: gateway discovery and route
/// table manipulation.
#[derive(Debug, Error)]
pub enum RoutingError {
    /// Transparent: [`GatewayError`]'s `Display` is already the finished,
    /// PII-free user sentence, and its `Debug` carries the adapter detail. A
    /// prefix here would be a second one inside `tray.rs`'s `Bridge error: {..}`,
    /// and re-stringifying would destroy the detail at this boundary.
    #[error(transparent)]
    Gateway(#[from] GatewayError),
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
}

/// Errors surfaced by the `engine` module.
#[derive(Debug, Error)]
pub enum EngineError {
    #[error("engine setup failed: {0}")]
    Setup(String),
}
