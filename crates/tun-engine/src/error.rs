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

/// A route command that did not succeed: the spawn failed, or the child exited
/// non-zero. Only the FATAL (install) phase produces one — best-effort cleanup
/// has no error channel at all. See `routing`'s "Execution" section.
///
/// `Display` is PII-free by construction — program name (`netsh` / `route`),
/// position within the phase, exit code. A [`RoutingError::RouteSetup`] built
/// from this reaches a GUI toast verbatim (`StartError::Failed`), so the argv
/// (which carries the server IP and the upstream interface name) and the
/// child's stdout/stderr are logged at `warn` by the runner instead.
#[derive(Debug, Error)]
#[error("`{program}` (command {} of {total}) {failure}", .index + 1)]
pub struct RouteCommandError {
    pub(crate) program: String,
    /// Zero-based position in the phase's command list; `Display` shows it
    /// one-based.
    pub(crate) index: usize,
    pub(crate) total: usize,
    pub(crate) failure: CommandFailure,
}

/// How a single route command failed. `-1` is the exit code stand-in for a
/// child terminated by a signal (`ExitStatus::code() == None`).
#[derive(Debug, Error)]
pub(crate) enum CommandFailure {
    #[error("failed to start: {0}")]
    Spawn(std::io::Error),
    #[error("exited with code {0}")]
    Exit(i32),
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
