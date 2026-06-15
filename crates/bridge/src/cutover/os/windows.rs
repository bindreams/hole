//! Real Windows `CutoverOs`: rename-away-then-move-in swap (D1) + raw SCM
//! stop/start driven by the `scm_wait` state machine. The detached-child
//! lifetime + breakaway probe live at the apply layer, which spawns THIS process
//! as `hole bridge cutover`; this impl is the swap+restart body that child runs.

use std::path::{Path, PathBuf};

use crate::cutover::os::CutoverOs;
use crate::cutover::scm_wait::{stop_via_notify, ScmActor, SystemScmActor, WantState};
use crate::platform::os::SERVICE_NAME;

/// One image to rename-away-then-move-in: the live binary at `installed` is
/// renamed aside, then the staged new bytes are moved onto `installed`.
#[derive(Clone)]
pub struct ImageMove {
    /// Canonical installed path (e.g. the Program Files `hole.exe`, galoshes,
    /// wintun.dll).
    pub installed: PathBuf,
    /// New image staged on the SAME volume as `installed` (cross-volume rename
    /// fails / copies, breaking the running-image swap).
    pub staged: PathBuf,
}

pub struct WindowsCutoverOs {
    /// Every bundled binary to swap (the full BINDIR set: hole.exe, plugins,
    /// wintun.dll, debug symbols, NOTICES), in order.
    pub images: Vec<ImageMove>,
    /// Target version, used for the `.old-<ver>` rename-away name.
    pub target_version: String,
}

/// Rename-away name for the live binary: `<file>.old-<ver>`. The live image keeps
/// this inode (held `FILE_SHARE_DELETE`), so the canonical path is freed for the
/// new bytes; the next bridge start sweeps `*.old-*` once no process maps it.
pub fn old_name(installed: &Path, target_version: &str) -> PathBuf {
    let file = installed
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    installed.with_file_name(format!("{file}.old-{target_version}"))
}

/// A fully-swapped image, retained so a later failure can undo it. The `old`
/// binary is kept (its delete is deferred to after the whole set swaps).
struct Completed {
    installed: PathBuf,
    staged: PathBuf,
    old: PathBuf,
}

/// Undo completed swaps in reverse, restoring the prior consistent set: move the
/// new bytes back to staging, then the old binary back to the canonical path.
/// Best-effort per step — a swap that already committed must be reverted as far
/// as the filesystem allows; the alternative (leaving a mixed set) is worse.
fn rollback(completed: &[Completed]) {
    for c in completed.iter().rev() {
        let _ = std::fs::rename(&c.installed, &c.staged);
        let _ = std::fs::rename(&c.old, &c.installed);
    }
}

impl CutoverOs for WindowsCutoverOs {
    fn swap_images(&mut self) -> std::io::Result<()> {
        // Rename-away-then-move-in, ALL-OR-NOTHING across the full BINDIR set.
        // `std::fs::rename` uses FileRenameInfoEx + POSIX semantics on this
        // toolchain, which renames a running exe held FILE_SHARE_DELETE; the
        // move-in flips `same_file::Handle` identity so the GUI self-heal returns
        // Relaunch. Same-volume staging is required.
        //
        // A mid-loop failure must NOT leave a mixed old/new set — the service
        // would boot from inconsistent binaries. So the destructive delete of the
        // swapped-out `.old-*` images is DEFERRED until every image swaps; until
        // then each undo target still exists, and any failure rolls the completed
        // swaps back to the prior consistent set before erroring.
        let mut completed: Vec<Completed> = Vec::with_capacity(self.images.len());
        for img in &self.images {
            let old = old_name(&img.installed, &self.target_version);
            if let Err(e) = std::fs::rename(&img.installed, &old) {
                rollback(&completed); // this image is untouched
                return Err(e);
            }
            // The live image now keeps the renamed `old` inode. Move the staged
            // new bytes onto the freed canonical path.
            if let Err(e) = std::fs::rename(&img.staged, &img.installed) {
                // This image is half-swapped: restore its old binary first, then
                // unwind the earlier ones.
                let _ = std::fs::rename(&old, &img.installed);
                rollback(&completed);
                return Err(e);
            }
            completed.push(Completed {
                installed: img.installed.clone(),
                staged: img.staged.clone(),
                old,
            });
        }
        // All images swapped — only now drop the swapped-out old binaries.
        // Best-effort: fails while old GUIs/bridge map the old inode; the next
        // bridge start sweeps the survivors (orphan_sweep).
        for c in &completed {
            let _ = std::fs::remove_file(&c.old);
        }
        Ok(())
    }

    fn stop_service_wait_stopped(&mut self) -> std::io::Result<()> {
        let mut actor = SystemScmActor::open(SERVICE_NAME)?;
        stop_via_notify(&mut actor)
    }

    fn start_service_wait_running(&mut self) -> std::io::Result<()> {
        let mut actor = SystemScmActor::open(SERVICE_NAME)?;
        actor.arm(WantState::Running)?;
        actor.start()?;
        while actor.wait_callback()? != WantState::Running {
            actor.arm(WantState::Running)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
