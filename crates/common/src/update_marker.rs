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

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use util::versioned_file::{
    Change, CreateOutcome, Loaded, Obsolete, Placement, Role, Schema, StoreError, UnreadableKind, UpdateOutcome,
    VersionedFile, VersionedState,
};

/// Fixed marker filename (single-occupancy: one cutover per machine). The GUI
/// finds it by this constant, not by enumeration.
pub const MARKER_FILE: &str = "update-in-progress.json";

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

/// The marker's payload. The file is `{"version": 3, "driver": ...}`: the version is the framing's, and the previous
/// release (which declares `deny_unknown_fields`) reads exactly these two keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarkerInfo {
    /// The cutover DRIVER's persisted identity — the process whose death means
    /// the cutover is abandoned (the detached child on Windows; the inline actor
    /// on macOS). `(pid, raw kernel start token)`, so a recycled pid never
    /// restores to it and there is no failed-probe value to special-case.
    pub driver: cosca::identity::ProcessIdRecord,
}

impl Schema for MarkerInfo {
    const VERSION: u32 = 3;
    type Prev = Obsolete<2>;

    fn upgrade(prev: Obsolete<2>) -> Self {
        match prev {}
    }
}

/// A claim on the name: never stored over, whatever it holds, and removed by name whatever it holds, so a schema bump
/// across the cutover never strands it.
impl VersionedState for MarkerInfo {
    const FILE_NAME: &'static str = MARKER_FILE;
    const ROLE: Role = Role::Claim;
}

util::assert_contiguous!(MarkerInfo);

fn marker_file(log_dir: &Path) -> VersionedFile<MarkerInfo> {
    VersionedFile::new(log_dir)
}

/// Where the marker is written: the log directory is handed to `owner` (never secured further), and the file is
/// `0o644` on unix, because the GUI reads it across the privilege boundary and the default `0o600` from a root-daemon
/// umask would silently break that read.
struct MarkerPlacement {
    owner: Option<(u32, u32)>,
}

impl Placement for MarkerPlacement {
    fn owner(&self) -> Option<(u32, u32)> {
        self.owner
    }

    fn prepare_dir(&self, _dir: &util::dir::Dir) -> io::Result<()> {
        Ok(())
    }

    fn prepare_tmp(&self, _tmp: &File) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            _tmp.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        }
        Ok(())
    }
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

/// Claim the marker as the single-occupancy cutover claim: `Taken` if anything is already at the name, a marker this
/// release cannot read included. Collapses the check and the claim into one atomic op, so two concurrent cutover
/// requests cannot both win (the loser gets `Taken` → 409). A reader never sees a partial file.
///
/// `owner` hands the marker to the elevated-run user (a user-scoped elevated bridge writes into the user's profile);
/// `None` for the root daemon, whose service log dir is root-owned by design. A lost claim only removes its own staged
/// temp, so the existing marker's ownership is never disturbed.
pub fn claim(log_dir: &Path, info: &MarkerInfo, owner: Option<(u32, u32)>) -> Result<CreateOutcome, StoreError> {
    marker_file(log_dir).create_new(info, &MarkerPlacement { owner })
}

/// Read the marker, distinguishing "no cutover was claimed" from "a cutover was
/// claimed by a driver this build cannot identify" from "whether one was claimed
/// could not be established".
///
/// Through a [`util::dir::ReadDir`], for the GUI and the bridge alike: the bridge reads it as root
/// or SYSTEM in a log directory a user may own, where a link or a FIFO planted at
/// the name must be neither followed nor waited for.
pub fn read(log_dir: &Path) -> Marker {
    match marker_file(log_dir).observe().loaded {
        Loaded::Absent => Marker::Absent,
        Loaded::Current { value, .. } => Marker::Present(value),
        Loaded::Obsolete { .. } => Marker::Unreadable,
        Loaded::Newer { .. } => Marker::Unreadable,
        Loaded::Corrupt { .. } => Marker::Unreadable,
        Loaded::Unreadable { kind, .. } => match kind {
            // The directory did not open: nothing established that a marker is there.
            UnreadableKind::Directory => Marker::Indeterminate,
            // A claim requires a regular FILE; anything else at the name (a link, a FIFO, a directory) is not a
            // marker and asserts nothing about a cutover. `error!`, not `warn!`: it is not an environmental io
            // failure, it is a name nothing in hole can produce.
            UnreadableKind::NotAFile => {
                tracing::error!(
                    "the update marker name holds something that is not a regular file; it claims no cutover"
                );
                Marker::Indeterminate
            }
            // The file is there and could not be read (a Windows sharing violation): a claim.
            UnreadableKind::File => Marker::Unreadable,
        },
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
    marker_file(log_dir)
        .update(&MarkerPlacement { owner: None }, |_| (Change::Remove, ()))
        .map(|_| ())
        .map_err(io_error)
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
    let (_, outcome) = marker_file(log_dir)
        .update(&MarkerPlacement { owner: None }, |observed| match &observed.loaded {
            Loaded::Current { .. } => (Change::Store(MarkerInfo { driver: driver.clone() }), ()),
            _ => (Change::Keep, ()),
        })
        .map_err(io_error)?;
    match matches!(outcome, UpdateOutcome::Stored) {
        true => Ok(()),
        false => Err(io::Error::other(
            "no readable update marker to stamp the cutover driver into",
        )),
    }
}

/// The error of an `io::Result` function of this module: an I/O error as it is, anything else wrapped.
fn io_error(e: StoreError) -> io::Error {
    match e {
        StoreError::Io(e) => e,
        other => io::Error::other(other),
    }
}

#[cfg(test)]
#[path = "update_marker_tests.rs"]
mod update_marker_tests;
