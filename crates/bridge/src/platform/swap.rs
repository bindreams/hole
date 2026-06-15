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

// macOS FFI seam ======================================================================================================

#[cfg(target_os = "macos")]
mod imp {
    #![allow(clippy::disallowed_methods)]

    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    use super::{same_volume, ImageSwap, SwapPlan, SwapPrimitive};

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

    fn execute_one(img: &ImageSwap) -> io::Result<()> {
        let sdev = parent_dev(&img.staging)?;
        let ddev = parent_dev(&img.dest)?;
        if !same_volume(sdev, ddev) {
            return Err(io::Error::other(format!(
                "cross-volume swap rejected (EXDEV): {:?} -> {:?}",
                img.staging, img.dest
            )));
        }
        match img.primitive {
            SwapPrimitive::RenameSwap => {
                rename_swap(&img.staging, &img.dest)?;
                if img.delete_swapped_out_staging {
                    // The pre-swap destination now sits at `staging`; remove it.
                    std::fs::remove_dir_all(&img.staging)?;
                }
            }
            SwapPrimitive::PlainRename => std::fs::rename(&img.staging, &img.dest)?,
        }
        Ok(())
    }

    /// Execute a planned swap: per image, assert same-volume staging, swap by the
    /// chosen primitive, then delete the swapped-out staging when required.
    pub fn execute_swap(plan: &SwapPlan) -> io::Result<()> {
        execute_one(&plan.app)?;
        execute_one(&plan.helper)
    }
}

#[cfg(target_os = "macos")]
pub use imp::{execute_swap, rename_swap, volume_supports_rename_swap};

#[cfg(test)]
#[path = "swap_tests.rs"]
mod swap_tests;
