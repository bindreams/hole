//! Unix: the lock's mode gives read and write to each class that has write on
//! the guarded file, and to its owner always; its owner and group are the
//! guarded file's.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// The principals that may write one file.
pub(in crate::versioned_file) struct Writers {
    mode: u32,
    uid: u32,
    gid: u32,
}

/// The lock mode for a guarded file of `file_mode`.
fn lock_mode(file_mode: u32) -> u32 {
    let owner = 0o600;
    let group = if file_mode & 0o020 != 0 { 0o060 } else { 0 };
    let other = if file_mode & 0o002 != 0 { 0o006 } else { 0 };
    owner | group | other
}

impl Writers {
    /// Those of `reference`, the file being guarded or about to be.
    pub(in crate::versioned_file) fn of(reference: &Path) -> io::Result<Self> {
        let meta = std::fs::metadata(reference)?;
        Ok(Self {
            mode: lock_mode(meta.mode()),
            uid: meta.uid(),
            gid: meta.gid(),
        })
    }

    /// Gives `file` exactly this access, whatever it has now. Taking the
    /// owner needs the privilege to `chown`: without it this fails, rather
    /// than leave a lock the guarded file's writers cannot open.
    pub(in crate::versioned_file) fn apply(&self, file: &File, _path: &Path) -> io::Result<()> {
        let meta = file.metadata()?;
        if (meta.uid(), meta.gid()) != (self.uid, self.gid) {
            // SAFETY: the descriptor is open for the call.
            if unsafe { libc::fchown(file.as_raw_fd(), self.uid, self.gid) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        file.set_permissions(PermissionsExt::from_mode(self.mode))
    }

    /// [`apply`](Self::apply), unless `file` already has the mode: a writer
    /// that is not the owner can open the lock but could not change it.
    pub(in crate::versioned_file) fn conform(&self, file: &File, path: &Path) -> io::Result<()> {
        if file.metadata()?.mode() & 0o777 == self.mode {
            return Ok(());
        }
        self.apply(file, path)
    }
}
