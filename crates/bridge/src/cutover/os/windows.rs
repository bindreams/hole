//! Real Windows `CutoverOs`: rename-away-then-move-in swap (D1) + raw SCM
//! stop/start driven by the `scm_wait` state machine. The detached-child
//! lifetime + breakaway probe live at the apply layer, which spawns THIS process
//! as `hole bridge cutover`; this impl is the swap+restart body that child runs.

use std::path::{Path, PathBuf};

use crate::cutover::os::CutoverOs;
use crate::cutover::scm_wait::{start_via_notify, stop_via_notify, SystemScmActor};
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
    // A BINDIR entry always has a filename; a missing one is a caller bug, not a
    // runtime condition to paper over with an empty rename target.
    debug_assert!(
        installed.file_name().is_some(),
        "BINDIR image has no filename: {installed:?}"
    );
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

/// Per-image filesystem steps the swap loop drives, isolated so the all-or-
/// nothing ordering is verified cfg-free with a recording fake. The real impl is
/// `FsSwapStep` (plain `std::fs::rename`); each step is best-effort on the
/// rollback paths (a revert that cannot complete must not mask the original
/// error).
trait WindowsSwapStep {
    /// Rename the live binary aside to `old` (it keeps this inode via
    /// `FILE_SHARE_DELETE`), freeing the canonical path.
    fn rename_away(&self, index: usize, installed: &Path, old: &Path) -> std::io::Result<()>;
    /// Move the staged new bytes onto the freed canonical path.
    fn move_in(&self, index: usize, staged: &Path, installed: &Path) -> std::io::Result<()>;
    /// A move-in failed: restore THIS image's old binary to the canonical path
    /// before unwinding the earlier (fully-committed) images.
    fn restore_half_swapped(&self, index: usize, old: &Path, installed: &Path);
    /// Undo a committed swap: new bytes back to staging, old binary back to the
    /// canonical path — the prior consistent set.
    fn undo(&self, index: usize, installed: &Path, staged: &Path, old: &Path);
    /// Drop the swapped-out old binary. Run ONLY after every image commits (so a
    /// rollback before it can still restore the prior set).
    fn remove_old(&self, index: usize, old: &Path);
}

/// Real filesystem swap steps. `std::fs::rename` uses FileRenameInfoEx + POSIX
/// semantics on this toolchain, which renames a running exe held
/// `FILE_SHARE_DELETE`; the move-in flips `same_file::Handle` identity so the GUI
/// self-heal returns Relaunch. Same-volume staging is required.
struct FsSwapStep;

impl WindowsSwapStep for FsSwapStep {
    fn rename_away(&self, _index: usize, installed: &Path, old: &Path) -> std::io::Result<()> {
        std::fs::rename(installed, old)
    }
    fn move_in(&self, _index: usize, staged: &Path, installed: &Path) -> std::io::Result<()> {
        std::fs::rename(staged, installed)
    }
    fn restore_half_swapped(&self, _index: usize, old: &Path, installed: &Path) {
        let _ = std::fs::rename(old, installed);
    }
    fn undo(&self, _index: usize, installed: &Path, staged: &Path, old: &Path) {
        let _ = std::fs::rename(installed, staged);
        let _ = std::fs::rename(old, installed);
    }
    fn remove_old(&self, _index: usize, old: &Path) {
        // Best-effort: fails while old GUIs/bridge map the old inode; the next
        // bridge start sweeps the survivors (orphan_sweep).
        let _ = std::fs::remove_file(old);
    }
}

/// Drive the rename-away-then-move-in swap ALL-OR-NOTHING across the full BINDIR
/// set. A mid-loop failure must NOT leave a mixed old/new set — the service would
/// boot from inconsistent binaries — so the destructive delete of the swapped-out
/// `.old-*` images is DEFERRED until every image commits; until then each undo
/// target still exists, and any failure rolls the completed swaps back to the
/// prior consistent set before erroring.
///
/// This is the Windows sibling of macOS `platform::swap::execute_plan`: both keep
/// the swap all-or-nothing by deferring the destructive delete until the whole
/// set commits, so any failure rolls back to the prior consistent set. The
/// drivers differ in primitive (rename-away/move-in retaining `.old-<ver>` here
/// vs `renamex_np` exchange there) and so are not yet unified.
fn execute_image_swaps<O: WindowsSwapStep>(images: &[ImageMove], target_version: &str, ops: &O) -> std::io::Result<()> {
    let mut completed: Vec<Completed> = Vec::with_capacity(images.len());
    for (index, img) in images.iter().enumerate() {
        let old = old_name(&img.installed, target_version);
        if let Err(e) = ops.rename_away(index, &img.installed, &old) {
            undo_all(&completed, ops); // this image is untouched
            return Err(e);
        }
        if let Err(e) = ops.move_in(index, &img.staged, &img.installed) {
            // This image is half-swapped: restore its old binary first, then
            // unwind the earlier (fully-committed) ones.
            ops.restore_half_swapped(index, &old, &img.installed);
            undo_all(&completed, ops);
            return Err(e);
        }
        completed.push(Completed {
            installed: img.installed.clone(),
            staged: img.staged.clone(),
            old,
        });
    }
    // All images swapped — only now drop the swapped-out old binaries.
    for (index, c) in completed.iter().enumerate() {
        ops.remove_old(index, &c.old);
    }
    Ok(())
}

/// Undo committed swaps in reverse, restoring the prior consistent set, tagging
/// each `undo` with the committed image's own index.
fn undo_all<O: WindowsSwapStep>(completed: &[Completed], ops: &O) {
    for (index, c) in completed.iter().enumerate().rev() {
        ops.undo(index, &c.installed, &c.staged, &c.old);
    }
}

impl CutoverOs for WindowsCutoverOs {
    fn swap_images(&mut self) -> std::io::Result<()> {
        execute_image_swaps(&self.images, &self.target_version, &FsSwapStep)
    }

    fn stop_service_wait_stopped(&mut self) -> std::io::Result<()> {
        let mut actor = SystemScmActor::open(SERVICE_NAME)?;
        stop_via_notify(&mut actor)
    }

    fn start_service_wait_running(&mut self) -> std::io::Result<()> {
        let mut actor = SystemScmActor::open(SERVICE_NAME)?;
        start_via_notify(&mut actor)
    }
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
