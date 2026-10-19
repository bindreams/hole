//! The exclusive lock that makes `store`, `remove` and `move_aside` one
//! decision each: held on a sibling file, `<name>.lock`, from the probe of the
//! file to the last write.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

use super::store::Fs;
use super::sys;

/// An exclusive advisory lock on a lock file, released on drop.
///
/// The lock file is never deleted: removing it would let one writer lock the
/// old file while another creates and locks a new one. It is empty and only
/// ever locked, so an existing one is opened read-only.
#[must_use = "the lock is released when this is dropped"]
pub(super) struct Lock {
    file: File,
}

impl Lock {
    /// Creates the lock file when it is missing, then blocks until the lock
    /// is held: there is no timeout, because the holder is another writer of
    /// the same file, never an event that may not happen. A missing directory
    /// is `NotFound`.
    pub(super) fn acquire(fs: &dyn Fs, path: &Path) -> io::Result<Self> {
        let file = open_or_create(path)?;
        fs.lock(&file)?;
        Ok(Self { file })
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        sys::unlock(&self.file);
    }
}

fn open_or_create(path: &Path) -> io::Result<File> {
    match OpenOptions::new().read(true).open(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        found => return found,
    }
    match OpenOptions::new().write(true).create_new(true).open(path) {
        // Another writer created it first; the lock file is never deleted.
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => OpenOptions::new().read(true).open(path),
        created => created,
    }
}
