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

use crate::diagnostics::etw::read_wide_string;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, warn};

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
    sweep_stale_sessions();

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

/// Enumerate live ETW sessions via Win32 `QueryAllTracesW` and stop
/// any whose name starts with [`SESSION_PREFIX`]. Mirrors the ETW
/// consumer's sweep at
/// [`crate::diagnostics::etw::sweep_stale_sessions`] — best-effort,
/// warns on failure, never aborts startup.
fn sweep_stale_sessions() {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Diagnostics::Etw::{
        ControlTraceW, QueryAllTracesW, CONTROLTRACE_HANDLE, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_PROPERTIES,
    };

    const MAX_SESSIONS: usize = 128;
    const STRING_RESERVE: usize = 1024;
    const PROPERTIES_SIZE: usize = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 2 * STRING_RESERVE;

    let mut buffer = vec![0u8; PROPERTIES_SIZE * MAX_SESSIONS];
    let mut pointers: Vec<*mut EVENT_TRACE_PROPERTIES> = Vec::with_capacity(MAX_SESSIONS);
    for i in 0..MAX_SESSIONS {
        // SAFETY: we own `buffer` and lay out one properties-sized slot
        // per index; Windows fills them in via QueryAllTracesW.
        let p = unsafe {
            buffer
                .as_mut_ptr()
                .add(i * PROPERTIES_SIZE)
                .cast::<EVENT_TRACE_PROPERTIES>()
        };
        unsafe {
            (*p).Wnode.BufferSize = PROPERTIES_SIZE as u32;
            (*p).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            (*p).LogFileNameOffset = (std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + STRING_RESERVE) as u32;
        }
        pointers.push(p);
    }

    let mut session_count: u32 = 0;
    // SAFETY: QueryAllTracesW takes an array of pre-initialised
    // EVENT_TRACE_PROPERTIES pointers, fills them in, and writes the
    // count to the out parameter.
    let query_err = unsafe { QueryAllTracesW(&mut pointers, &mut session_count) };
    if query_err != ERROR_SUCCESS {
        warn!(code = query_err.0, "netsh-trace: QueryAllTracesW failed during sweep");
        return;
    }

    let count = session_count as usize;
    let mut swept = 0u32;
    for p in pointers.iter().take(count.min(MAX_SESSIONS)).copied() {
        // SAFETY: Windows filled in the null-terminated wide logger name
        // at offset LoggerNameOffset within the allocation we supplied.
        let name_ptr = unsafe {
            (p as *const u8)
                .add(std::mem::size_of::<EVENT_TRACE_PROPERTIES>())
                .cast::<u16>()
        };
        let name = unsafe { read_wide_string(name_ptr) };
        if !name.starts_with(SESSION_PREFIX) {
            continue;
        }

        let mut wide: Vec<u16> = name.encode_utf16().collect();
        wide.push(0);

        // SAFETY: `wide` is null-terminated and outlives the call;
        // `p` is valid for the duration of the sweep.
        let stop_err = unsafe {
            ControlTraceW(
                CONTROLTRACE_HANDLE { Value: 0 },
                windows::core::PCWSTR(wide.as_ptr()),
                p,
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        if stop_err == ERROR_SUCCESS {
            info!(session = %name, "netsh-trace: swept stale session");
            swept += 1;
        } else {
            warn!(session = %name, code = stop_err.0, "netsh-trace: failed to stop stale session");
        }
    }
    if swept == 0 {
        debug!("netsh-trace: no stale sessions to sweep");
    } else {
        // The first start after a crash often finds a leftover session
        // that was never drained — once we've stopped them, the
        // subsequent `netsh trace start` should succeed cleanly.
        info!(
            swept,
            "netsh-trace: swept leftover sessions from prior runs; next start should succeed"
        );
    }
}
