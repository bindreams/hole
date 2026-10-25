//! Generic ownership primitive: `lchown(2)` a path to a uid/gid. Not
//! Hole-specific — a thin, testable wrapper over `libc::lchown`. macOS is the
//! only current user; elsewhere it is a no-op so callers stay cfg-free.
//!
//! Uses `lchown`, NOT `chown`: it does not follow symlinks. Invoked as root on
//! paths under the user-writable profile tree, `chown` would be a chown-through-
//! symlink privesc primitive (the target's owner, not the link's, gets rewritten).
//! Same hardening the repair walk in `hole`'s `setup.rs` relies on.

use std::path::Path;

#[cfg(target_os = "macos")]
pub fn chown_path(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: `c` is a valid NUL-terminated path for the duration of the call.
    let rc = unsafe { libc::lchown(c.as_ptr(), uid, gid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "macos"))]
pub fn chown_path(_path: &Path, _uid: u32, _gid: u32) -> std::io::Result<()> {
    Ok(())
}

/// The `(uid, gid)` that owns `path` itself (a symlink is not followed, matching
/// [`chown_path`]); `None` where ownership is not managed, or if `path` cannot
/// be examined.
#[cfg(target_os = "macos")]
pub fn owner_of(path: &Path) -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    owner_from_stat(path, std::fs::symlink_metadata(path).map(|m| (m.uid(), m.gid())))
}

/// The owner a stat reported. A path that does not exist yet has no owner to keep;
/// any other failure is logged, because the caller meant to preserve an ownership
/// and is about to lose it.
#[cfg(any(target_os = "macos", test))]
fn owner_from_stat(path: &Path, stat: std::io::Result<(u32, u32)>) -> Option<(u32, u32)> {
    match stat {
        Ok(owner) => Some(owner),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            tracing::warn!(
                error = %crate::error_chain::error_chain(&e),
                path = %path.display(),
                "could not read the owner of a path, so its ownership is not preserved"
            );
            None
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub fn owner_of(_path: &Path) -> Option<(u32, u32)> {
    None
}

/// Best-effort `chown` when an owner is set; a failure is logged and swallowed.
pub fn chown_if_some(path: &Path, owner: Option<(u32, u32)>) {
    if let Some((uid, gid)) = owner {
        if let Err(e) = chown_path(path, uid, gid) {
            tracing::warn!(error = %e, path = %path.display(), "chown failed");
        }
    }
}

/// The ownership a state-file rewrite reads and sets, behind a seam so a test can
/// see what a rewrite asked for on a host where it cannot observe a chown.
pub trait Ownership {
    fn owner_of(&self, path: &Path) -> Option<(u32, u32)>;
    fn chown(&self, path: &Path, owner: Option<(u32, u32)>);
}

/// [`Ownership`] over [`owner_of`] and [`chown_if_some`].
pub struct RealOwnership;

impl Ownership for RealOwnership {
    fn owner_of(&self, path: &Path) -> Option<(u32, u32)> {
        owner_of(path)
    }

    fn chown(&self, path: &Path, owner: Option<(u32, u32)>) {
        chown_if_some(path, owner);
    }
}

#[cfg(test)]
#[path = "ownership_tests.rs"]
mod ownership_tests;

#[cfg(test)]
#[path = "ownership_stat_tests.rs"]
mod ownership_stat_tests;
