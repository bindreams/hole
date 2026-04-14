//! RAII wrapper around `netsh trace start / stop` scoped to the bridge
//! process lifetime.
//!
//! # Why
//!
//! The ETW consumer in [`crate::diagnostics::etw`] captures TCPIP / WFP /
//! Winsock-AFD provider events at the event-schema layer. It does NOT
//! capture raw packets or NDIS-layer wire events. For #200 the remaining
//! evidence surface is the packet wire itself — did the SYN leave the
//! loopback adapter, or did TCPIP log a 1004 without anything hitting
//! NDIS. `netsh trace start` with the `InternetClient` scenario produces
//! an `.etl` file that includes the raw packet capture plus deep NDIS
//! / AFD provider data, which — unlike the live event stream — can be
//! opened offline in Wireshark or `netsh trace convert`.
//!
//! # Lifecycle
//!
//! - [`start`] spawns `netsh.exe trace start scenario=InternetClient
//!   capture=yes correlation=no tracefile=<path> maxsize=64
//!   report=disabled sessionname=hole-bridge-trace-<pid>`.
//! - The returned [`NetshTraceGuard`] owns the running session. Its
//!   `Drop` impl shells out to `netsh trace stop sessionname=...`,
//!   flushing the circular buffer to the ETL file.
//! - [`sweep_stale_sessions`] enumerates live sessions via Win32
//!   `QueryAllTracesW` (same code path as
//!   [`crate::diagnostics::etw::sweep_stale_sessions`]) and stops any
//!   `hole-bridge-trace-*` left by a crashed prior bridge.
//!
//! # Caveats
//!
//! - `netsh trace start` requires admin elevation. In CI (GitHub
//!   Actions `windows-latest`) the bridge child inherits the
//!   `runneradmin` token, so elevation is available. On local-dev
//!   runs without elevation the start call fails and we log at
//!   `error!` and continue; bridge startup is not aborted.
//! - ETW session names are machine-global — a parallel test harness
//!   would collide on `hole-bridge-trace-<pid>` only if two bridges
//!   had the same PID, which does not happen inside a single OS.
//! - `maxsize=64` is MB, circular. A 30 s bridge lifetime under the
//!   nextest `terminate-after` cap stays well below that.

use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, warn};

/// Prefix used for this module's session names. Matches the
/// `hole-bridge-trace-<pid>` format built in [`session_name`].
const SESSION_PREFIX: &str = "hole-bridge-trace-";

/// Build the netsh trace session name for the current process.
fn session_name() -> String {
    format!("{SESSION_PREFIX}{}", std::process::id())
}

/// Default location for the ETL file. Callers (primarily
/// [`crate::foreground::run`]) pass the bridge's `log_dir` so the ETL
/// lands alongside `bridge.log` and is uploaded by the same CI
/// artifact step.
pub fn default_etl_path(log_dir: &Path) -> PathBuf {
    log_dir.join("netsh-trace.etl")
}

/// Errors returned from [`start`]. Same shape as
/// [`crate::diagnostics::etw::EtwError`] — caller logs at `error!` and
/// continues.
#[derive(Debug, thiserror::Error)]
pub enum NetshTraceError {
    #[error("failed to spawn netsh.exe: {0}")]
    Spawn(std::io::Error),
    #[error("netsh trace start exited with code {code} (stdout={stdout} stderr={stderr})")]
    NonzeroExit { code: i32, stdout: String, stderr: String },
}

/// RAII guard for a live `netsh trace` session.
///
/// `Drop` unconditionally runs `netsh trace stop`. The stop call
/// itself may emit a few hundred ms of work to flush the kernel
/// buffers; callers have to expect this on clean shutdown.
pub struct NetshTraceGuard {
    session: String,
    etl_path: PathBuf,
}

impl Drop for NetshTraceGuard {
    fn drop(&mut self) {
        let session = self.session.clone();
        let etl_path = self.etl_path.clone();
        match Command::new("netsh")
            .args(["trace", "stop", &format!("sessionname={session}")])
            .output()
        {
            Ok(o) => {
                info!(
                    session = %session,
                    etl = %etl_path.display(),
                    exit = o.status.code().unwrap_or(-1),
                    stdout_bytes = o.stdout.len(),
                    stderr_bytes = o.stderr.len(),
                    "netsh trace stopped"
                );
                if !o.status.success() {
                    warn!(
                        stdout = %String::from_utf8_lossy(&o.stdout),
                        stderr = %String::from_utf8_lossy(&o.stderr),
                        "netsh trace stop reported nonzero exit",
                    );
                }
            }
            Err(e) => warn!(error = %e, session = %session, "netsh trace stop spawn failed"),
        }
    }
}

/// Sweep stale `hole-bridge-trace-*` sessions left by a crashed prior
/// bridge, then start a fresh netsh trace session for this PID and
/// return an RAII guard.
pub fn start(log_dir: &Path) -> Result<NetshTraceGuard, NetshTraceError> {
    crate::diagnostics::etw_sweep::sweep_sessions_with_prefix(SESSION_PREFIX, "netsh-trace");

    let session = session_name();
    let etl_path = default_etl_path(log_dir);

    let output = Command::new("netsh")
        .args([
            "trace",
            "start",
            "scenario=InternetClient",
            "capture=yes",
            "correlation=no",
            "report=disabled",
            "maxsize=64",
            &format!("tracefile={}", etl_path.display()),
            &format!("sessionname={session}"),
        ])
        .output()
        .map_err(NetshTraceError::Spawn)?;

    if !output.status.success() {
        return Err(NetshTraceError::NonzeroExit {
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    info!(
        session = %session,
        etl = %etl_path.display(),
        "netsh trace started",
    );
    Ok(NetshTraceGuard { session, etl_path })
}
