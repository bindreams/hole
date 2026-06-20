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
///
/// Overwrites an existing marker. For the single-occupancy claim use
/// [`write_new`], which fails if the marker already exists.
pub fn write(log_dir: &Path, info: &MarkerInfo) -> io::Result<()> {
    let tmp = staged_marker(log_dir, info)?;
    std::fs::rename(&tmp, log_dir.join(MARKER_FILE))?;
    Ok(())
}

/// Atomically write the marker as a single-occupancy CLAIM: fails with
/// `AlreadyExists` if a marker is already present. Collapses the check and the
/// claim into one atomic op, so two concurrent cutover requests cannot both win
/// (the loser gets `AlreadyExists` → 409). `hard_link` is the cross-platform
/// O_EXCL primitive (`link(2)`/`CreateHardLink` fail `EEXIST`/`ERROR_ALREADY_EXISTS`
/// when the destination exists), and links the fully-written temp content so a
/// reader never sees a partial file.
pub fn write_new(log_dir: &Path, info: &MarkerInfo) -> io::Result<()> {
    let tmp = staged_marker(log_dir, info)?;
    let final_path = log_dir.join(MARKER_FILE);
    let res = std::fs::hard_link(&tmp, &final_path);
    // The temp is consumed either way (linked-then-unlinked, or cleaned up on a
    // lost claim) so a `.tmp` never lingers.
    let _ = std::fs::remove_file(&tmp);
    res
}

/// Write the marker JSON to a UNIQUELY-named same-dir temp file with the
/// cross-privilege mode, returning its path. A unique name (not a fixed `.tmp`)
/// so two concurrent claims do not corrupt a shared temp. The caller publishes
/// it (rename = overwrite, hard_link = claim).
fn staged_marker(log_dir: &Path, info: &MarkerInfo) -> io::Result<PathBuf> {
    std::fs::create_dir_all(log_dir)?;
    let json = serde_json::to_vec(info).map_err(io::Error::other)?;
    let tmp = tempfile::Builder::new()
        .prefix(MARKER_FILE)
        .suffix(".tmp")
        .tempfile_in(log_dir)?;
    std::fs::write(tmp.path(), &json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o644))?;
    }
    // Persist the temp (suppress its delete-on-drop) and hand back the path; the
    // caller renames/links it and removes any leftover.
    let (_, path) = tmp.keep().map_err(|e| io::Error::other(e.to_string()))?;
    Ok(path)
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
