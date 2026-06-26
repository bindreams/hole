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

/// Best-effort `chown` when an owner is set; a failure is logged and swallowed.
pub fn chown_if_some(path: &Path, owner: Option<(u32, u32)>) {
    if let Some((uid, gid)) = owner {
        if let Err(e) = chown_path(path, uid, gid) {
            tracing::warn!(error = %e, path = %path.display(), "chown failed");
        }
    }
}

#[cfg(test)]
#[path = "ownership_tests.rs"]
mod ownership_tests;
