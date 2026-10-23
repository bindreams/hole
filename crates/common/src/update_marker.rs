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
use util::dir::{Dir, EntryKind, ReadDir, Staged};

/// Fixed marker filename (single-occupancy: one cutover per machine). The GUI
/// finds it by this constant, not by enumeration.
pub const MARKER_FILE: &str = "update-in-progress.json";

/// Schema version. Bump on a breaking shape change; `read` answers
/// [`Marker::Unreadable`] for an unknown version, but `clear` is remove-by-name
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
/// in [`stage_marker`], whose inode the rename publishes unchanged.
///
/// Overwrites an existing marker. For the single-occupancy claim use
/// [`write_new`], which fails if the marker already exists.
pub fn write(log_dir: &Path, info: &MarkerInfo, owner: Option<(u32, u32)>) -> io::Result<()> {
    let dir = Dir::open(log_dir, true, owner)?;
    let staged = stage_marker(&dir, info, owner)?;
    staged.publish()
}

/// Atomically write the marker as a single-occupancy CLAIM: fails with
/// `AlreadyExists` if a marker is already present. Collapses the check and the
/// claim into one atomic op, so two concurrent cutover requests cannot both win
/// (the loser gets `AlreadyExists` → 409). [`Staged::claim`] is a hard link
/// (`link(2)`/`CreateHardLink` fail `EEXIST`/`ERROR_ALREADY_EXISTS` when the
/// destination exists) of the fully-written temp file, so a reader never sees a
/// partial file.
///
/// `owner` chowns the marker to the elevated-run user (see [`write()`]); `None`
/// for the root daemon. A lost claim (`AlreadyExists`) only removes its own
/// staged temp, so the existing marker's ownership is never disturbed.
pub fn write_new(log_dir: &Path, info: &MarkerInfo, owner: Option<(u32, u32)>) -> io::Result<()> {
    let dir = Dir::open(log_dir, true, owner)?;
    let staged = stage_marker(&dir, info, owner)?;
    staged.claim()
}

/// The marker JSON in a uniquely-named same-dir temp file with the
/// cross-privilege mode (a unique name so two concurrent claims do not corrupt
/// a shared temp). The caller publishes it (`publish` = overwrite, `claim` =
/// claim). The temp is dropped, and removed, if it is not.
///
/// `owner` chowns the temp BEFORE it is published, through its own handle. Both
/// publishers keep the same inode (rename moves it, the link shares it and the
/// temp name is then unlinked), so the persisted marker carries this owner;
/// `None` leaves it root-owned for the daemon. The directory is the one `dir`
/// was opened on, never the path again: the log directory sits in the user's
/// profile when the bridge is user-scoped.
fn stage_marker<'a>(dir: &'a Dir, info: &MarkerInfo, owner: Option<(u32, u32)>) -> io::Result<Staged<'a>> {
    let json = serde_json::to_vec(info).map_err(io::Error::other)?;
    dir.stage(MARKER_FILE.as_ref(), &json, owner, readable_by_the_gui)
}

/// Widens the staged file from the `0o600` it is sealed to, to `0o644`: the GUI reads the marker across the
/// privilege boundary, and the default from a root-daemon umask would silently break that read.
fn readable_by_the_gui(_staged: &std::fs::File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        _staged.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

/// Read the marker, distinguishing "no cutover was claimed" from "a cutover was
/// claimed by a driver this build cannot identify" from "whether one was claimed
/// could not be established".
///
/// Through a [`ReadDir`], for the GUI and the bridge alike: the bridge reads it as root
/// or SYSTEM in a log directory a user may own, where a link or a FIFO planted at
/// the name must be neither followed nor waited for.
pub fn read(log_dir: &Path) -> Marker {
    let dir = match ReadDir::open(log_dir) {
        Ok(dir) => dir,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Marker::Absent,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "whether an update marker exists could not be determined: the log directory could not be opened"
            );
            return Marker::Indeterminate;
        }
    };
    let bytes = match dir.read(MARKER_FILE.as_ref()) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Marker::Absent,
        Err(e) => return unopened(&dir, &e),
    };
    let info: MarkerInfo = match serde_json::from_slice(&bytes) {
        Ok(info) => info,
        Err(e) => {
            // Shadowed so the raw error, which quotes the file, cannot be logged; see `ParseFailure`.
            let e = util::parse_error::ParseFailure::from(&e);
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

/// Classify a marker that could not be READ. Presence comes from asking the directory what the name is, never from
/// the read's error: a failed read is not evidence a file is there. A claim requires a regular FILE; anything else
/// at the name (a link, a FIFO, a directory) is not a marker and asserts nothing about a cutover. The name is never
/// followed, so a link is classified as the anomaly it is instead of being resolved to whatever it points at; the
/// marker is only ever published by rename or hard link, so hole never creates one.
fn unopened(dir: &ReadDir, read_error: &io::Error) -> Marker {
    match dir.kind_of(MARKER_FILE.as_ref()) {
        Ok(Some(EntryKind::File)) => {
            tracing::warn!(error = %read_error, "update marker exists but could not be read");
            Marker::Unreadable
        }
        // `error!`, not `warn!`: unlike a failed probe this is not an environmental
        // io failure, it is a name nothing in hole can produce.
        Ok(Some(kind)) => {
            tracing::error!(
                ?kind,
                read_error = %read_error,
                "the update marker name holds something that is not a regular file; it claims no cutover"
            );
            Marker::Indeterminate
        }
        Ok(None) => Marker::Absent,
        Err(e) => {
            tracing::warn!(
                read_error = %read_error,
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
    let dir = match Dir::open(log_dir, false, None) {
        Ok(dir) => dir,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    match dir.unlink(MARKER_FILE.as_ref()) {
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
