//! macOS image-swap: the `.app` bundle via `renamex_np(RENAME_SWAP)` (APFS atomic
//! directory exchange) + the single `HELPER_PATH` file via plain `fs::rename`.
//! Swapping BOTH in one place keeps the `.app` and its privileged helper in
//! lockstep across an update.
//!
//! The plan is pure (cfg-free, table-tested on any host); the real FFI
//! (`renamex_np`, the `getattrlist VOL_CAP_INT_RENAME_SWAP` volume probe, and
//! `execute_swap`) is gated to macOS behind the #165 isolation contract.

use std::path::{Path, PathBuf};

// Pure plan ===========================================================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapPrimitive {
    /// APFS atomic directory swap (the `.app` is a non-empty directory; plain
    /// `rename` cannot replace a non-empty dir — `ENOTEMPTY`).
    RenameSwap,
    /// Plain `fs::rename` (a single file).
    PlainRename,
}

#[derive(Debug, Clone)]
pub struct ImageSwap {
    pub staging: PathBuf,
    pub dest: PathBuf,
    pub primitive: SwapPrimitive,
    /// `RENAME_SWAP` exchanges entries; the old inode ends up at `staging` and is
    /// NOT auto-removed, so it must be explicitly deleted (else staging leaks).
    pub delete_swapped_out_staging: bool,
}

#[derive(Debug, Clone)]
pub struct SwapPlan {
    pub app: ImageSwap,
    pub helper: ImageSwap,
}

/// Decide the primitive for each image: the `.app` bundle (a directory) swaps via
/// `RENAME_SWAP`; the helper (a single file) via plain rename.
pub fn plan_swap(app_staging: &Path, app_dest: &Path, helper_staging: &Path, helper_dest: &Path) -> SwapPlan {
    SwapPlan {
        app: ImageSwap {
            staging: app_staging.into(),
            dest: app_dest.into(),
            primitive: SwapPrimitive::RenameSwap,
            delete_swapped_out_staging: true,
        },
        helper: ImageSwap {
            staging: helper_staging.into(),
            dest: helper_dest.into(),
            primitive: SwapPrimitive::PlainRename,
            delete_swapped_out_staging: false,
        },
    }
}

/// Two paths are on the same volume iff their `st_dev` match. `rename`/`renamex_np`
/// fail `EXDEV` across volumes, so staging must be on the destination volume (a
/// DMG mount is a separate volume).
pub fn same_volume(a_dev: u64, b_dev: u64) -> bool {
    a_dev == b_dev
}

/// The per-image primitives the orchestrator drives. The real macOS FFI provides
/// `swap`/`reswap`/`delete_staging`; tests provide a recorder so the all-or-
/// nothing ordering is verified cfg-free, without privilege.
pub trait SwapOps {
    /// Swap `img.staging` onto `img.dest` (RENAME_SWAP for a dir, plain rename
    /// for a file). `index` identifies the image (0 = app, 1 = helper).
    fn swap(&self, img: &ImageSwap, index: usize) -> std::io::Result<()>;
    /// Undo a committed swap: swap `img.dest` back to `img.staging`. Best-effort
    /// (a rollback step that cannot complete must not mask the original error).
    fn reswap(&self, img: &ImageSwap, index: usize);
    /// Delete the swapped-out staging left by a RENAME_SWAP. Run only after every
    /// image has swapped (so a rollback before it can still restore the bundle).
    fn delete_staging(&self, img: &ImageSwap, index: usize);
}

/// Drive a planned swap ALL-OR-NOTHING: swap every image first; on any failure
/// roll back the committed swaps (in reverse) and error, leaving the prior
/// consistent set; only after the whole set commits delete the swapped-out
/// staging. Deferring the delete is what makes the rollback possible — a swapped-
/// out `.app` is unrecoverable once its staging is removed.
///
/// ROLLBACK PRECONDITION: a `PlainRename` image has no recoverable inverse (its
/// pre-swap dest was overwritten by the new bytes), so `reswap` is a no-op for
/// it. Rollback is therefore correct only if no `PlainRename` image is ever in
/// the committed-and-then-rolled-back set — i.e. every `PlainRename` image must
/// be the LAST in the plan, so a later image's failure can never strand it. The
/// debug-assert enforces this so a future image-set growth that misplaces a
/// `PlainRename` image fails loud instead of silently leaving a mixed set.
pub fn execute_plan<O: SwapOps>(plan: &SwapPlan, ops: &O) -> std::io::Result<()> {
    let images = [&plan.app, &plan.helper];
    debug_assert!(
        images[..images.len() - 1]
            .iter()
            .all(|img| matches!(img.primitive, SwapPrimitive::RenameSwap)),
        "a PlainRename image must be last (its swap has no recoverable inverse for rollback)"
    );
    let mut committed: Vec<usize> = Vec::with_capacity(images.len());
    for (index, img) in images.iter().enumerate() {
        if let Err(e) = ops.swap(img, index) {
            for &done in committed.iter().rev() {
                ops.reswap(images[done], done);
            }
            return Err(e);
        }
        committed.push(index);
    }
    for &index in &committed {
        if images[index].delete_swapped_out_staging {
            ops.delete_staging(images[index], index);
        }
    }
    Ok(())
}

// macOS FFI seam ======================================================================================================

#[cfg(target_os = "macos")]
mod imp {
    #![allow(clippy::disallowed_methods)]

    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    use super::{execute_plan, same_volume, ImageSwap, SwapOps, SwapPlan, SwapPrimitive};

    fn cstring(path: &Path) -> io::Result<std::ffi::CString> {
        std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)
    }

    /// `RENAME_SWAP` via `renamex_np`: atomically exchange two directory entries.
    /// The caller must have confirmed the destination volume supports it
    /// (`volume_supports_rename_swap`) and that both paths are on it.
    pub fn rename_swap(src: &Path, dst: &Path) -> io::Result<()> {
        let csrc = cstring(src)?;
        let cdst = cstring(dst)?;
        // SAFETY: both args are valid NUL-terminated C strings; RENAME_SWAP is a
        // documented flag for `renamex_np` on volumes advertising
        // VOL_CAP_INT_RENAME_SWAP (probed before the call).
        let rc = unsafe { libc::renamex_np(csrc.as_ptr(), cdst.as_ptr(), libc::RENAME_SWAP) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// `getattrlist` buffer for the volume-capabilities query. `#[repr(C)]` +
    /// `packed` matches the kernel's `attrreference`-free layout: a leading
    /// `u32` length the kernel fills, then the `vol_capabilities_attr_t`.
    #[repr(C, packed)]
    struct VolCapsBuf {
        length: u32,
        caps: libc::vol_capabilities_attr_t,
    }

    /// Probe whether `vol_path`'s volume supports `RENAME_SWAP`
    /// (`VOL_CAP_INT_RENAME_SWAP`). This is a per-VOLUME capability, not an
    /// OS-version gate. On any probe failure, returns `Ok(false)` so the caller
    /// takes the documented fallback rather than risking an `ENOTSUP` mid-swap.
    pub fn volume_supports_rename_swap(vol_path: &Path) -> io::Result<bool> {
        let cpath = cstring(vol_path)?;
        let mut attrlist = libc::attrlist {
            bitmapcount: libc::ATTR_BIT_MAP_COUNT,
            reserved: 0,
            commonattr: 0,
            volattr: libc::ATTR_VOL_INFO | libc::ATTR_VOL_CAPABILITIES,
            dirattr: 0,
            fileattr: 0,
            forkattr: 0,
        };
        let mut buf = VolCapsBuf {
            length: 0,
            caps: unsafe { std::mem::zeroed() },
        };
        // SAFETY: `cpath` is a valid C string; `attrlist`/`buf` are live, sized
        // exactly, and the kernel writes at most `size_of::<VolCapsBuf>()` bytes.
        let rc = unsafe {
            libc::getattrlist(
                cpath.as_ptr(),
                &mut attrlist as *mut _ as *mut libc::c_void,
                &mut buf as *mut _ as *mut libc::c_void,
                std::mem::size_of::<VolCapsBuf>(),
                0,
            )
        };
        if rc != 0 {
            return Ok(false);
        }
        let valid = buf.caps.valid[libc::VOL_CAPABILITIES_INTERFACES];
        let caps = buf.caps.capabilities[libc::VOL_CAPABILITIES_INTERFACES];
        let bit = libc::VOL_CAP_INT_RENAME_SWAP;
        Ok((valid & bit != 0) && (caps & bit != 0))
    }

    fn parent_dev(path: &Path) -> io::Result<u64> {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other(format!("path has no parent: {path:?}")))?;
        Ok(std::fs::metadata(parent)?.dev())
    }

    /// Swap one image by its primitive after asserting same-volume staging.
    fn swap_one(img: &ImageSwap) -> io::Result<()> {
        let sdev = parent_dev(&img.staging)?;
        let ddev = parent_dev(&img.dest)?;
        if !same_volume(sdev, ddev) {
            return Err(io::Error::other(format!(
                "cross-volume swap rejected (EXDEV): {:?} -> {:?}",
                img.staging, img.dest
            )));
        }
        match img.primitive {
            // RENAME_SWAP exchanges entries, so the inverse is the same call.
            SwapPrimitive::RenameSwap => rename_swap(&img.staging, &img.dest),
            SwapPrimitive::PlainRename => std::fs::rename(&img.staging, &img.dest),
        }
    }

    /// Real FFI swap primitives. `delete_staging` runs only after the whole set
    /// commits (`execute_plan`), so a mid-set failure can still RENAME_SWAP the
    /// `.app` back from its swapped-out staging.
    struct MacosSwapOps;

    impl SwapOps for MacosSwapOps {
        fn swap(&self, img: &ImageSwap, _index: usize) -> io::Result<()> {
            swap_one(img)
        }
        fn reswap(&self, img: &ImageSwap, _index: usize) {
            // The swapped-in dest sits at `dest`; exchange/rename it back. For
            // PlainRename the pre-swap dest is gone (it was a single file moved
            // onto by the new bytes — not recoverable), so only RENAME_SWAP has a
            // meaningful inverse. The helper is the LAST image, so it never needs
            // reswap (nothing committed after it).
            if matches!(img.primitive, SwapPrimitive::RenameSwap) {
                let _ = rename_swap(&img.dest, &img.staging);
            }
        }
        fn delete_staging(&self, img: &ImageSwap, _index: usize) {
            // The pre-swap destination now sits at `staging`; remove it.
            let _ = std::fs::remove_dir_all(&img.staging);
        }
    }

    /// Execute a planned swap ALL-OR-NOTHING (swap both, roll back on failure,
    /// delete swapped-out staging only after both commit).
    pub fn execute_swap(plan: &SwapPlan) -> io::Result<()> {
        execute_plan(plan, &MacosSwapOps)
    }
}

#[cfg(target_os = "macos")]
pub use imp::{execute_swap, rename_swap, volume_supports_rename_swap};

#[cfg(test)]
#[path = "swap_tests.rs"]
mod swap_tests;
