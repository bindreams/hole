//! Cross-privilege update-in-progress marker. Written by the privileged bridge
//! to the SERVICE log dir (GUI-readable across the privilege boundary, the
//! tombstone precedent) at cutover start; cleared unconditionally by the next
//! bridge's post-bind sweep. Does triple duty: (1) GUI no-surprise-Disconnected
//! (`observed_running` holds the last snapshot while it is set), (2) the bridge
//! shutdown disarms the lockdown guard while it is set (cover persists), (3) the
//! GUI banner source.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Fixed marker filename (single-occupancy: one cutover per machine). The GUI
/// finds it by this constant, not by enumeration.
pub const MARKER_FILE: &str = "update-in-progress.json";

/// Schema version. Bump on a breaking shape change; `read` returns None on an
/// unknown version (load-None-on-mismatch), but `clear` is remove-by-path and
/// ignores the schema entirely.
pub const MARKER_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarkerInfo {
    pub version: u32,
    pub from_version: String,
    pub to_version: String,
    pub pid: u32,
    pub started_at_unix: u64,
}

/// The SERVICE log directory (where the privileged bridge writes its logs and
/// the marker). Deduped from the per-platform literals previously hardcoded in
/// `platform/windows.rs`, `platform/macos.rs`, and `log_collector.rs`.
pub fn service_log_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into()))
            .join("hole")
            .join("logs")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/var/log/hole")
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        PathBuf::from("/var/log/hole")
    }
}

/// Atomically write the marker into `log_dir`. Temp-file + same-dir rename so a
/// reader never sees a partial write; on Unix the file is set to mode 0o644
/// (GUI-readable across the privilege boundary — the default 0o600 from a
/// root-daemon umask would silently break the cross-privilege read).
pub fn write(log_dir: &Path, info: &MarkerInfo) -> io::Result<()> {
    std::fs::create_dir_all(log_dir)?;
    let tmp = log_dir.join(format!("{MARKER_FILE}.tmp"));
    let json = serde_json::to_vec(info).map_err(io::Error::other)?;
    std::fs::write(&tmp, &json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
    }
    std::fs::rename(&tmp, log_dir.join(MARKER_FILE))?;
    Ok(())
}

/// Read the marker if present and the schema matches. Absent or unparsable or
/// unknown-version => None.
pub fn read(log_dir: &Path) -> Option<MarkerInfo> {
    let bytes = std::fs::read(log_dir.join(MARKER_FILE)).ok()?;
    let info: MarkerInfo = serde_json::from_slice(&bytes).ok()?;
    (info.version == MARKER_VERSION).then_some(info)
}

/// Unconditionally remove the marker by known path. NOT parse-then-clear: a
/// from->to schema bump across the cutover must never strand it. Absent is Ok.
pub fn clear(log_dir: &Path) -> io::Result<()> {
    match std::fs::remove_file(log_dir.join(MARKER_FILE)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
#[path = "update_marker_tests.rs"]
mod update_marker_tests;
