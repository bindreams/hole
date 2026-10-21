//! A directory that is only read from.

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::path::Path;

use super::{platform, read_whole, single_component, EntryKind};

/// An open directory with no way to write in it: it has no method that adds, replaces, renames or removes a name, so
/// code that only reads cannot do more, on any platform. Opened by [`ReadDir::open`] or taken from a [`super::Dir`]
/// by [`super::Dir::reader`].
///
/// Windows is not asked for the right to add to the directory, so a folder whose ACL allows reading alone is still
/// read. The walk to it is [`super::Dir::open`]'s, with the same judgment of every link.
pub struct ReadDir {
    file: File,
}

impl ReadDir {
    /// Opens the directory at `path`, following a link only under the ownership-transition rule (see the module doc
    /// of [`super`]). Nothing is created.
    pub fn open(path: &Path) -> io::Result<ReadDir> {
        #[cfg(windows)]
        return platform::open_dir_read(path).map(Self::from_handle);
        #[cfg(unix)]
        return platform::open_dir(path, false, None, platform::caller()).map(Self::from_handle);
    }

    pub(super) fn from_handle(file: File) -> ReadDir {
        ReadDir { file }
    }

    /// The handle, for a test to ask the OS what it was opened with.
    #[cfg(test)]
    pub(super) fn file(&self) -> &File {
        &self.file
    }

    /// The whole file `name`, read through a handle that shares delete, so a replace of the file does not wait for
    /// the read. `NotFound` for a missing file. A symlink at the name is an error, not followed; so is anything that
    /// is not a regular file ([`super::Refusal::NotRegular`], and a FIFO is never waited for).
    pub fn read(&self, name: &OsStr) -> io::Result<Vec<u8>> {
        read_whole(&self.file, name)
    }

    /// What `name` is right now, or `None` if there is nothing. A symlink is itself, not what it points at.
    pub fn kind_of(&self, name: &OsStr) -> io::Result<Option<EntryKind>> {
        single_component(name)?;
        platform::kind_of(&self.file, name)
    }
}

#[cfg(test)]
#[path = "read_dir_tests.rs"]
mod read_dir_tests;
