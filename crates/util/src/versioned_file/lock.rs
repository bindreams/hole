//! The exclusive lock that makes `store`, `remove` and `move_aside` one
//! decision each: held on a sibling file, `<name>.lock`, from the probe of the
//! file to the last write.

use std::fs::File;
use std::io;
use std::path::Path;

use super::lock_access::{open_existing, Writers};
use super::store::Fs;
use super::sys;

/// An exclusive advisory lock on a lock file, released on drop.
///
/// The lock file is never deleted: removing it would let one writer lock the
/// old file while another creates and locks a new one. It is empty and only
/// ever locked. Its access is the access of the file it guards, cut down to
/// the principals that may write that file (see [`Writers`]).
#[must_use = "the lock is released when this is dropped"]
pub(super) struct Lock {
    file: File,
}

impl Lock {
    /// Blocks until the lock is held: there is no timeout, because the holder
    /// is another writer of the same file, never an event that may not
    /// happen. A missing directory is `NotFound`.
    ///
    /// A missing lock file is created with the access of `reference`, the
    /// file it guards, and one that exists is brought to it. A missing
    /// `reference` is `NotFound`, before the lock file is looked at: nothing
    /// is created for a file that is not there.
    pub(super) fn acquire(fs: &dyn Fs, path: &Path, reference: &Path) -> io::Result<Self> {
        let file = open_or_create(path, &Writers::of(reference)?, fs)?;
        fs.lock(&file)?;
        Ok(Self { file })
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        sys::unlock(&self.file);
    }
}

/// Opened for writing as well as reading: on some network file systems a lock
/// needs write access to its file.
///
/// Straight-line, with no loop: open what is there, else create it, and if
/// that lost to another creator open what it made. The type never removes a
/// lock file, so the last open can only find nothing if something outside it
/// removed the file in between, and that is an error, not a reason to go
/// round again. A link or anything but a regular file at the name is an error
/// at the first open, and the create refuses a name that is taken.
fn open_or_create(path: &Path, writers: &Writers, fs: &dyn Fs) -> io::Result<File> {
    match open_existing(path) {
        Ok(file) => return conformed(writers, file, path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    match writers.create(path, |file| fs.after_lock_created(file)) {
        Ok(file) => Ok(file),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let file = open_existing(path).map_err(|e| match e.kind() {
                // `NotFound` means "no state file" to the callers; this is not that.
                io::ErrorKind::NotFound => io::Error::other("the lock file was removed while it was being opened"),
                _ => e,
            })?;
            conformed(writers, file, path)
        }
        Err(e) => Err(e),
    }
}

fn conformed(writers: &Writers, file: File, path: &Path) -> io::Result<File> {
    writers.conform(&file, path)?;
    Ok(file)
}

#[cfg(test)]
#[path = "lock_tests.rs"]
mod lock_tests;
