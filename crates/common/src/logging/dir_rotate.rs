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
///
/// The active file never holds more than `limit` bytes. A name the user holds (a directory at `<name>.1`, a handle
/// without delete sharing) cannot take the rotation, and the log is theirs to block, so the file goes to
/// `<name>.1.fallback` instead, replacing the one before it: at most one such file exists. When no name can take it
/// the file stays full and the lines are dropped, as they are while it cannot be opened, until one can.
pub struct DirRotate {
    dir: Dir,
    name: OsString,
    rotated: OsString,
    fallback: OsString,
    limit: usize,
    owner: Option<(u32, u32)>,
    /// `None` when the file could not be opened: a line is then dropped, as a log must never take the process down.
    file: Option<File>,
    /// Bytes in the active file.
    count: usize,
    /// Told why the file could not be opened, the first time it cannot.
    notice: Box<dyn FnMut(&io::Error) + Send>,
    noticed: bool,
}

impl DirRotate {
    /// `owner` is given the active file each time it is created, so the user can read it without elevating, and is
    /// the only owner an existing active file may have.
    pub fn new(dir: Dir, name: &std::ffi::OsStr, limit: usize, owner: Option<(u32, u32)>) -> Self {
        Self::with_notice(dir, name, limit, owner, |err| {
            // No subscriber can carry this: the file is the log. The error carries no path.
            let _ = writeln!(io::stderr(), "hole: the log file is disabled, it was not opened: {err}");
        })
    }

    fn with_notice(
        dir: Dir,
        name: &std::ffi::OsStr,
        limit: usize,
        owner: Option<(u32, u32)>,
        notice: impl FnMut(&io::Error) + Send + 'static,
    ) -> Self {
        assert!(limit > 0, "a log file that holds no bytes cannot be rotated");
        let mut rotated = name.to_os_string();
        rotated.push(".1");
        let mut fallback = rotated.clone();
        fallback.push(".fallback");
        let mut this = Self {
            dir,
            name: name.to_os_string(),
            rotated,
            fallback,
            limit,
            owner,
            file: None,
            count: 0,
            notice: Box::new(notice),
            noticed: false,
        };
        this.open_active();
        this
    }

    /// Opens the active file (see [`Dir::append_own_file`]: a file at the name that is not the owner's, or has another name, is replaced,
    /// never written to), and counts what it already holds. A new file is given to `owner`. The first failure to
    /// open is said once; later ones, and the retry at every write, are silent.
    fn open_active(&mut self) {
        match self.dir.append_own_file(&self.name, 0o644, self.owner) {
            Ok(file) => self.file = Some(file),
            Err(err) => {
                self.file = None;
                if !std::mem::replace(&mut self.noticed, true) {
                    (self.notice)(&err);
                }
            }
        }
        self.count = self
            .file
            .as_ref()
            .and_then(|file| file.metadata().ok())
            .map_or(0, |meta| meta.len() as usize);
    }

    /// Renames the active file over `<name>.1` and opens a fresh active file. If `<name>.1` cannot take it, the fallback
    /// does; once `<name>.1` can again, the fallback, which holds older lines, is removed. If neither can, the same
    /// file is reopened, still full, and the next write tries again.
    fn rotate(&mut self) {
        // Closed first: Windows does not rename a file that a handle without delete sharing has open, and no
        // other handle of ours does.
        self.file = None;
        // Neither failure is reported: the file is reopened either way, and a log has nowhere to say that it could
        // not rotate.
        match self.dir.rename(&self.name, &self.rotated) {
            Ok(()) => {
                let _ = self.dir.unlink(&self.fallback);
            }
            Err(_) => {
                let _ = self.dir.rename(&self.name, &self.fallback);
            }
        }
        self.open_active();
    }
}

impl Write for DirRotate {
    /// Takes at most the bytes that fit below the limit, so a line that straddles it is split exactly there across
    /// two calls (`write_all` makes the second). Never fails after taking bytes. A line is dropped, and said to be
    /// taken, while the file cannot be opened or, being full, cannot be rotated: a log must never take the process
    /// down, and must never fill the disk.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.file.is_none() {
            self.open_active();
        }
        // A file from a run with a larger limit may already be over this one, and so may one whose rotation failed.
        if self.file.is_some() && self.count >= self.limit {
            self.rotate();
        }
        let Some(file) = &mut self.file else {
            return Ok(buf.len());
        };
        // Still full: nothing could take it.
        let Some(room) = self.limit.checked_sub(self.count).filter(|room| *room > 0) else {
            return Ok(buf.len());
        };
        let taken = file.write(&buf[..buf.len().min(room)])?;
        self.count += taken;
        Ok(taken)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.as_mut().map_or(Ok(()), |file| file.flush())
    }
}

#[cfg(test)]
#[path = "dir_rotate_tests.rs"]
mod dir_rotate_tests;
