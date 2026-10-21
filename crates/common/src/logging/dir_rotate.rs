//! The log file: a size-rotated file inside a [`Dir`], so the directory is opened once without following a
//! symlink and every open, rename and `chown` after it is by a single name inside that handle.
//!
//! The log directory is the interactive user's when the bridge runs elevated on their behalf, so a path-based
//! rotator (open, rename, `chown` by the whole path) would follow whatever the user swaps in for a component of
//! it, as root.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Write};

use util::dir::Dir;

/// `<name>` (current) and `<name>.1` (the previous one): the active file is renamed over `<name>.1` once it
/// reaches `limit` bytes, and a write that straddles the limit is split exactly there.
pub struct DirRotate {
    dir: Dir,
    name: OsString,
    rotated: OsString,
    limit: usize,
    owner: Option<(u32, u32)>,
    /// `None` when the file could not be opened: a line is then dropped, as a log must never take the process down.
    file: Option<File>,
    /// Bytes in the active file.
    count: usize,
}

impl DirRotate {
    /// `owner` is given the active file each time it is created, so the user can read it without elevating, and is
    /// the only owner an existing active file may have.
    pub fn new(dir: Dir, name: &std::ffi::OsStr, limit: usize, owner: Option<(u32, u32)>) -> Self {
        assert!(limit > 0, "a log file that holds no bytes cannot be rotated");
        let mut rotated = name.to_os_string();
        rotated.push(".1");
        let mut this = Self {
            dir,
            name: name.to_os_string(),
            rotated,
            limit,
            owner,
            file: None,
            count: 0,
        };
        this.open_active();
        this
    }

    /// Opens the active file (see [`Dir::append_own_file`]: a file at the name that is not the owner's is replaced,
    /// never written to), and counts what it already holds. A new file is given to `owner`.
    fn open_active(&mut self) {
        self.file = self.dir.append_own_file(&self.name, 0o644, self.owner).ok();
        self.count = self
            .file
            .as_ref()
            .and_then(|file| file.metadata().ok())
            .map_or(0, |meta| meta.len() as usize);
    }

    fn rotate(&mut self) -> io::Result<()> {
        // Closed first: Windows does not rename a file that a handle without delete sharing has open, and no
        // other handle of ours does.
        self.file = None;
        let renamed = self.dir.rename(&self.name, &self.rotated);
        self.open_active();
        renamed
    }
}

impl Write for DirRotate {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        let written = buf.len();
        while self.count + buf.len() > self.limit {
            // A file from a run with a larger limit may already be over this one.
            let room = self.limit.saturating_sub(self.count);
            if let Some(file) = &mut self.file {
                file.write_all(&buf[..room])?;
            }
            self.rotate()?;
            buf = &buf[room..];
        }
        self.count += buf.len();
        if let Some(file) = &mut self.file {
            file.write_all(buf)?;
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.as_mut().map_or(Ok(()), |file| file.flush())
    }
}

#[cfg(test)]
#[path = "dir_rotate_tests.rs"]
mod dir_rotate_tests;
