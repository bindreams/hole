//! Error types for tun-engine submodules.

use std::path::PathBuf;

use thiserror::Error;

use crate::gateway::GatewayError;

/// Errors surfaced by the `routing` module: gateway discovery and route
/// table manipulation.
#[derive(Debug, Error)]
pub enum RoutingError {
    /// Gateway failure; log with `util::error_chain`.
    #[error("gateway detection failed: {0}")]
    Gateway(#[source] GatewayError),
    #[error("route setup failed: {0}")]
    RouteSetup(String),
    /// The route record is newer than this release, corrupt, or its read fails.
    /// It may name routes an earlier run left behind, so nothing is installed
    /// over it and it is left as it is. `Display` names the path: it is for
    /// the log, not a toast; use [`RoutingError::redacted`] for a toast.
    #[error("{}", state_unreadable(&path.display()))]
    StateUnreadable { path: PathBuf },
}

fn state_unreadable(record: &dyn std::fmt::Display) -> String {
    format!("the route record {record} cannot be read; it is left as it is, and no route is installed over it")
}

impl RoutingError {
    /// The text for a toast: `Display`, with the record named by its file name
    /// instead of its path. One exhaustive match, so a new variant must choose.
    ///
    /// `RouteSetup` and `Gateway` text is built path-free at its sources: a
    /// write failure names the `io::ErrorKind` only (`state_write_failed`), and
    /// the full error is logged.
    pub fn redacted(&self) -> String {
        match self {
            RoutingError::Gateway(_) => self.to_string(),
            RoutingError::RouteSetup(_) => self.to_string(),
            RoutingError::StateUnreadable { .. } => state_unreadable(&crate::routing::state::STATE_FILE_NAME),
        }
    }
}

#[cfg(target_os = "macos")]
impl RoutingError {
    /// A state file under `what` could not be written. The toast text names the
    /// error's kind only (`tempfile`'s error text names the path); the full
    /// error goes to the log.
    pub(crate) fn state_write_failed(what: &str, e: &std::io::Error) -> Self {
        tracing::error!(error = %util::error_chain::error_chain(e), "{what} could not be written");
        RoutingError::RouteSetup(format!("{what} could not be written ({})", e.kind()))
    }
}

/// A checkpoint of the route record that did not land.
#[derive(Debug, Error)]
pub(crate) enum CheckpointFailure {
    /// Only the kind: an `io::Error`'s text can name a path (`tempfile`'s does),
    /// and this reaches a toast. The full error is logged where the write failed.
    #[error("the route record could not be written ({kind})")]
    Io { kind: std::io::ErrorKind },
    /// Newer, corrupt, or its read fails: refused, not replaced. Carries the
    /// path for the log; `Display` omits it.
    #[error("the route record cannot be read")]
    RecordUnreadable { path: PathBuf },
}

/// Why `setup_routes` stopped.
#[derive(Debug, Error)]
pub(crate) enum SetupFailure {
    #[error(transparent)]
    Command(RouteCommandError),
    /// The record of the next command could not be written, so it did not run.
    #[error(transparent)]
    Checkpoint(CheckpointFailure),
}

impl From<SetupFailure> for RoutingError {
    fn from(failure: SetupFailure) -> Self {
        match failure {
            SetupFailure::Command(e) => RoutingError::RouteSetup(e.to_string()),
            SetupFailure::Checkpoint(e @ CheckpointFailure::Io { .. }) => RoutingError::RouteSetup(e.to_string()),
            SetupFailure::Checkpoint(CheckpointFailure::RecordUnreadable { path }) => {
                RoutingError::StateUnreadable { path }
            }
        }
    }
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
