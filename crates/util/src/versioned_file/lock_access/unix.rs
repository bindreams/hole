//! Unix: the lock's mode gives read and write to each class that has write on
//! the guarded file, and to its owner always; its owner and group are the
//! guarded file's.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
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

/// Never follows a link, and never blocks on a pipe or a device that is not a
/// lock; whatever is opened is checked to be a regular file.
fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    options
}

/// Opens the lock file at `path` for reading and writing. `NotFound` only when
/// there is nothing at `path`: a link, even a dangling one, is an error of its
/// own, as is anything else that is not a regular file.
pub(in crate::versioned_file) fn open_existing(path: &Path) -> io::Result<File> {
    let file = options().open(path).map_err(|e| match e.raw_os_error() {
        Some(libc::ELOOP) => io::Error::new(io::ErrorKind::InvalidData, "the lock path is a symbolic link"),
        _ => e,
    })?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the lock path is not a regular file",
        ));
    }
    Ok(file)
}

impl Writers {
    /// Those of `reference`, the file being guarded or about to be. `NotFound`
    /// when there is no such entry; a link is an entry, and its writers are its
    /// owner alone: `store` replaces the link, and `remove` and `move_aside`
    /// act on the name, whatever it points at.
    pub(in crate::versioned_file) fn of(reference: &Path) -> io::Result<Self> {
        let meta = std::fs::symlink_metadata(reference)?;
        let mode = if meta.is_symlink() {
            0o600
        } else {
            lock_mode(meta.mode())
        };
        Ok(Self {
            mode,
            uid: meta.uid(),
            gid: meta.gid(),
        })
    }

    /// Makes the lock file at `path`: `AlreadyExists` when anything is there.
    /// It is made owner-only, whatever the umask, and given this access before
    /// the call returns, so no one gets more than its creator until then.
    /// `after_creation` runs at the first instant, before anything is changed.
    pub(in crate::versioned_file) fn create(
        &self,
        path: &Path,
        after_creation: impl FnOnce(&File),
    ) -> io::Result<File> {
        let file = options().create_new(true).mode(0o600).open(path)?;
        after_creation(&file);
        self.apply(&file)?;
        Ok(file)
    }

    /// Gives `file` exactly this access, whatever it has now. Taking the
    /// owner needs the privilege to `chown`: without it this fails, rather
    /// than leave a lock the guarded file's writers cannot open.
    fn apply(&self, file: &File) -> io::Result<()> {
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
    pub(in crate::versioned_file) fn conform(&self, file: &File, _path: &Path) -> io::Result<()> {
        if file.metadata()?.mode() & 0o777 == self.mode {
            return Ok(());
        }
        self.apply(file)
    }
}
