//! Cross-privilege update-in-progress marker. Written by the privileged bridge
//! to the SERVICE log dir (GUI-readable across the privilege boundary, the
//! tombstone precedent) at cutover start; cleared unconditionally by the next
//! bridge's post-bind sweep. Does double duty: (1) GUI no-surprise-Disconnected
//! for a READABLE marker (`observed_running` holds the last snapshot while one
//! is set; a marker naming no identifiable driver reports the failed update
//! instead), (2) the bridge shutdown disarms the lockdown guard while it is set
//! (cover persists).
//!
//! Only one reader needs the payload — the GUI resolving the driver's liveness.
//! Every other reader asks [`is_present`], so a marker it cannot parse still
//! counts as a cutover claim — but a read that could not establish whether a
//! marker exists at all does not, since it carries no evidence of one.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Fixed marker filename (single-occupancy: one cutover per machine). The GUI
/// finds it by this constant, not by enumeration.
pub const MARKER_FILE: &str = "update-in-progress.json";

/// Schema version. Bump on a breaking shape change; `read` answers
/// [`Marker::Unreadable`] for an unknown version, but `clear` is remove-by-path
/// and ignores the schema entirely.
pub const MARKER_VERSION: u32 = 3;

/// What [`read`] found. Unlike `plugin_state::Loaded`'s sibling variant,
/// `Unreadable` carries no reason: every reader treats "present but
/// unidentifiable" the same way, so the reason is logged where it is detected.
#[derive(Debug)]
pub enum Marker {
    Absent,
    /// A marker file EXISTS but its driver cannot be identified — a regular file
    /// that could not be opened, an unparseable body, or a version this build
    /// does not know. A cutover claim either way.
    Unreadable,
    /// Whether a marker exists could not be established: the existence probe
    /// failed, or it found something that is not a regular file. NOT a claim —
    /// neither a failed read nor a directory is evidence a marker is there — so
    /// readers pass it through rather than report a cutover they could never
    /// retract.
    Indeterminate,
    Present(MarkerInfo),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarkerInfo {
    pub version: u32,
    /// The cutover DRIVER's persisted identity — the process whose death means
    /// the cutover is abandoned (the detached child on Windows; the inline actor
    /// on macOS). `(pid, raw kernel start token)`, so a recycled pid never
    /// restores to it and there is no failed-probe value to special-case.
    pub driver: cosca::identity::ProcessIdRecord,
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
/// `owner` chowns the persisted marker to the elevated-run user (a user-scoped
/// elevated bridge writes into the user's profile); `None` for the root daemon,
/// whose service log dir is root-owned by design. The chown lands on the temp
/// in [`staged_marker`], whose inode the rename publishes unchanged.
///
/// Overwrites an existing marker. For the single-occupancy claim use
/// [`write_new`], which fails if the marker already exists.
pub fn write(log_dir: &Path, info: &MarkerInfo, owner: Option<(u32, u32)>) -> io::Result<()> {
    let tmp = staged_marker(log_dir, info, owner)?;
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
///
/// `owner` chowns the marker to the elevated-run user (see [`write`]); `None`
/// for the root daemon. A lost claim (`AlreadyExists`) only removes its own
/// staged temp, so the existing marker's ownership is never disturbed.
pub fn write_new(log_dir: &Path, info: &MarkerInfo, owner: Option<(u32, u32)>) -> io::Result<()> {
    let tmp = staged_marker(log_dir, info, owner)?;
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
///
/// `owner` chowns the temp BEFORE it is published. Both publishers keep the same
/// inode (rename moves it, hard_link shares then unlinks the temp name), so the
/// persisted marker carries this owner; `None` leaves it root-owned for the daemon.
fn staged_marker(log_dir: &Path, info: &MarkerInfo, owner: Option<(u32, u32)>) -> io::Result<PathBuf> {
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
    util::ownership::chown_if_some(tmp.path(), owner);
    // Persist the temp (suppress its delete-on-drop) and hand back the path; the
    // caller renames/links it and removes any leftover.
    let (_, path) = tmp.keep().map_err(|e| io::Error::other(e.to_string()))?;
    Ok(path)
}

/// Read the marker, distinguishing "no cutover was claimed" from "a cutover was
/// claimed by a driver this build cannot identify" from "whether one was claimed
/// could not be established".
pub fn read(log_dir: &Path) -> Marker {
    let path = log_dir.join(MARKER_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Marker::Absent,
        Err(e) => return unopened(&path, &e),
    };
    let info: MarkerInfo = match serde_json::from_slice(&bytes) {
        Ok(info) => info,
        Err(e) => {
            tracing::warn!(error = %e, "update marker could not be parsed");
            return Marker::Unreadable;
        }
    };
    if info.version != MARKER_VERSION {
        tracing::warn!(
            got = info.version,
            want = MARKER_VERSION,
            "update marker schema mismatch"
        );
        return Marker::Unreadable;
    }
    Marker::Present(info)
}

/// Classify a marker that could not be OPENED. Presence comes from an existence
/// probe, never from the open's error: a failed open is not evidence a file is
/// there. A claim requires a regular FILE — anything else at that path is not a
/// marker and asserts nothing about a cutover. `symlink_metadata`, so a dangling
/// symlink reads as that anomaly rather than as a definitive absence.
fn unopened(path: &Path, open_error: &io::Error) -> Marker {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => {
            tracing::warn!(error = %open_error, "update marker exists but could not be read");
            Marker::Unreadable
        }
        // `error!`, not `warn!`: unlike a failed probe this is not an environmental
        // io failure, it is a path nothing in hole can produce.
        Ok(meta) => {
            tracing::error!(
                file_type = ?meta.file_type(),
                open_error = %open_error,
                "the update marker path holds something that is not a regular file; \
                 it claims no cutover"
            );
            Marker::Indeterminate
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Marker::Absent,
        Err(e) => {
            tracing::warn!(
                open_error = %open_error,
                probe_error = %e,
                "whether an update marker exists could not be determined"
            );
            Marker::Indeterminate
        }
    }
}

/// Whether a cutover has been CLAIMED, whatever shape the claim is in. A marker
/// file that exists but cannot be opened — a Windows sharing violation, the
/// exact case the post-sweep re-check guards — counts as present.
/// [`Marker::Indeterminate`] does not: nothing established that a marker is
/// there, and answering `true` would make the re-check refuse every start
/// forever with no way for the sweep to end it.
pub fn is_present(log_dir: &Path) -> bool {
    matches!(read(log_dir), Marker::Unreadable | Marker::Present(_))
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

/// Overwrite the marker's driver identity in place. The Windows cutover
/// initiator stamps the frozen child's identity here so the marker names the
/// driver, not the initiator.
///
/// Anything but [`Marker::Present`] is an `Err`. Succeeding would leave the
/// marker naming the INITIATOR, which the cutover then stops — and the GUI
/// resolves that identity as dead and reports a failed update on a successful
/// one. Failing costs nothing: the caller kills the still-suspended child and
/// clears the marker, so no cutover is claimed.
pub fn stamp_driver(log_dir: &Path, driver: &cosca::identity::ProcessIdRecord) -> io::Result<()> {
    let Marker::Present(mut info) = read(log_dir) else {
        return Err(io::Error::other(
            "no readable update marker to stamp the cutover driver into",
        ));
    };
    info.driver = driver.clone();
    write(log_dir, &info, None)
}

#[cfg(test)]
#[path = "update_marker_tests.rs"]
mod update_marker_tests;
