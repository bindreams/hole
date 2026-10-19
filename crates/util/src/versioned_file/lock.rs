//! The exclusive lock that makes `store`, `remove` and `move_aside` one
//! decision each: held on a sibling file, `<name>.lock`, from the probe of the
//! file to the last write.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

use super::lock_access::Writers;
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
        let file = open_or_create(path, &Writers::of(reference)?)?;
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
fn open_or_create(path: &Path, writers: &Writers) -> io::Result<File> {
    let dir = path.parent().expect("a lock file is always inside a directory");
    let name = path.file_name().expect("a lock file has a name").to_string_lossy();
    loop {
        match OpenOptions::new().read(true).write(true).open(path) {
            Ok(file) => {
                writers.conform(&file, path)?;
                return Ok(file);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        // Complete before it has its name, so no one can open it with the
        // access a new file gets by default. It is published by a link that
        // fails when another writer got there first.
        let tmp = tempfile::Builder::new()
            .prefix(&format!(".{name}."))
            .suffix(".tmp")
            .tempfile_in(dir)?;
        writers.apply(tmp.as_file(), tmp.path())?;
        match tmp.persist_noclobber(path) {
            Ok(file) => return Ok(file),
            // The lock file is never deleted, so the next open finds it.
            Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.error),
        }
    }
}

#[cfg(test)]
#[path = "lock_tests.rs"]
mod lock_tests;
