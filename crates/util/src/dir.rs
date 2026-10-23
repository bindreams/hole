//! A directory opened through handles, following a link only where that is safe, and file operations relative to it.
//!
//! A state directory can sit under the interactive user's profile while a
//! privileged process writes to it, so every component of its path is the user's
//! to replace. A path call (`create_dir_all`, `chown`, `rename`) re-resolves the
//! whole path each time, so a component swapped for a symlink between two calls
//! sends the next one anywhere. [`Dir`] resolves the path once, judging every
//! link it meets, and then every operation names a file by its
//! single name *inside the handle*: there is no path left to swap.
//!
//! # Resolution
//!
//! [`Dir::open`] starts at the root (or the current directory) and opens one
//! component at a time relative to the handle it already holds.
//!
//! - Unix: `openat(O_DIRECTORY | O_NOFOLLOW)` per component, with `mkdirat` for a
//!   missing one when asked. Every component is opened for lookup only (Linux
//!   `O_PATH`, macOS `O_SEARCH`), so a directory the caller can search but not
//!   read (`0o311`) is on a usable path; the final directory is then reopened
//!   readable through the handle in hand, for `fchown`, `fchmod` and `fsync`.
//!   Needs Linux 2.6.39 (`O_PATH`) or macOS 10.10. There is no
//!   whole-path no-follow flag in use (`openat2(RESOLVE_NO_SYMLINKS)` is Linux
//!   5.6, `O_NOFOLLOW_ANY` macOS 10.15), so one code path serves every version.
//! - Windows: `NtCreateFile` relative to the parent handle with
//!   `FILE_OPEN_REPARSE_POINT`, which opens a symlink, junction or mount point as
//!   itself so it can be judged and read (`FSCTL_GET_REPARSE_POINT`). Present in
//!   every NT version; any other kind of reparse point is refused.
//!
//! A link is followed under the ownership-transition rule (see `trail` and
//! CONTRIBUTING.md, "Privileged code in folders a user may own"): the walk never
//! moves from a folder an unprivileged user owns into one somebody else owns.
//! Links the system owns (unix: root; Windows: SYSTEM, Administrators,
//! TrustedInstaller) stay trusted, which keeps macOS's `/var`, `/tmp` and `/etc`
//! (and with them `temp_dir()`) working; a user's link to a folder that user owns
//! is followed (a profile moved to another disk); a user's link to a folder the
//! system or another account owns is refused. A walk follows at most as many links
//! as the OS itself follows in one path (Linux 40, macOS 32, Windows 63), which
//! also refuses a loop; a link met again after its target was walked counts again.
//! A folder the walk makes below a user's link is given to that user, so the next walk
//! through the link finds it theirs. Unix opens the made name once, requires the
//! handle to be a directory the process itself owns (the user can swap the name
//! after the `mkdirat`) and `fchown`s that handle; Windows sets the owner, which needs
//! the restore privilege an elevated token holds. The final name of a file operation
//! is never followed.
//!
//! Given an `owner` (unix ids), the final directory must be owned by it or by
//! this process; any other owner is refused. Windows has no unix ids and does not
//! check.
//!
//! A directory only read from is a [`ReadDir`]: the same walk, no write methods.
//!
//! The refusals are an `InvalidData` [`io::Error`] holding a [`Refusal`]; they
//! carry no path.
//!
//! # Operations
//!
//! [`ReadDir::read`], [`Dir::open_file`], [`Dir::link`], [`Dir::rename`],
//! [`Dir::rename_noreplace`] and [`Dir::unlink`] take single names, and none
//! follows a symlink at the name: a link is renamed, linked or removed as
//! itself, and reading or appending through one is an error. [`Dir::stage`]
//! writes a complete temp file that [`Staged::publish`] renames over a name or
//! [`Staged::claim`] links to a free one; [`Dir::write_atomic`] is the two in one.
//! On Windows a file that is read or appended shares everything with other
//! handles, delete included, and a replace or an unlink has POSIX semantics where
//! the volume has them (Windows 10 1607, NTFS), so an open reader neither blocks
//! it nor keeps the old name alive.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

mod read_dir;
mod trail;

#[cfg(any(test, feature = "test-support"))]
pub mod testing;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as platform;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as platform;

pub use platform::Caller;
pub use read_dir::ReadDir;

/// Why a path was not opened as a directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A link (Windows: reparse point) in the path that the ownership-transition rule does not let the walk follow,
    /// a link that is not one the walk can read, or more links than the OS follows in a path.
    Symlink,
    /// A component that exists and is not a directory.
    NotDirectory,
    /// The final directory is owned by neither the expected owner nor this process.
    #[cfg(unix)]
    ForeignOwner { uid: u32 },
    /// A file that is read where it is not a regular file (a FIFO, a device).
    NotRegular,
    /// A file that is read where the folder's owner cannot vouch for it: another user's, or a second name of a file
    /// the system owns (a hard link a user planted).
    ForeignFile,
}

impl Refusal {
    /// The refusal inside `err`, or `None` if `err` is not one.
    pub fn from_error(err: &io::Error) -> Option<&Refusal> {
        err.get_ref()?.downcast_ref()
    }

    pub(crate) fn into_io_error(self) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, self)
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Symlink => f.write_str("a directory in the path is a symbolic link"),
            Refusal::NotDirectory => f.write_str("a component of the path is not a directory"),
            #[cfg(unix)]
            Refusal::ForeignOwner { uid } => write!(f, "the directory is owned by uid {uid}"),
            Refusal::NotRegular => f.write_str("the file is not a regular file"),
            Refusal::ForeignFile => f.write_str("the file is not one the folder's owner can vouch for"),
        }
    }
}

impl std::error::Error for Refusal {}

/// How [`Dir::open_file`] opens a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenFile {
    /// Create the file; `AlreadyExists` if the name is taken, by anything. Never follows a symlink.
    /// Unix: created with `mode` (before the umask). Windows ignores `mode`.
    CreateNew { mode: u32 },
    /// Open what is there, `NotFound` if nothing. A symlink (Windows: reparse point) is opened as itself, not followed.
    Existing,
    /// Open what is there to read, `NotFound` if nothing. Never follows a symlink, and never blocks on a FIFO
    /// (unix): anything that is not a regular file is [`Refusal::NotRegular`]. Shares everything with other
    /// handles, delete included, so a replace of the file does not wait for the reader.
    Read,
    /// Open what is there to append to, `NotFound` if nothing: it does not create the file, so that the caller
    /// knows whether it made it. Never follows a symlink. Shares everything with other handles, delete included,
    /// so a reader or a rename of the name does not wait for the writer. A FIFO is opened without blocking (unix),
    /// which fails while nothing reads it.
    Append,
    /// Create the file to append to; `AlreadyExists` if the name is taken, by anything. Never follows a symlink.
    /// Unix: created with `mode` (before the umask). Windows ignores `mode`. Shares as [`Self::Append`].
    CreateAppend { mode: u32 },
}

/// What a name in a [`Dir`] is, not following a symlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A symlink (Windows: any reparse point).
    Symlink,
    Directory,
    /// A regular file.
    File,
    /// A FIFO, socket or device.
    Other,
}

/// Which file a name or an open handle denotes: equal when both are the same file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId(platform::FileId);

impl FileId {
    /// The file `file` is open on.
    pub fn of(file: &File) -> io::Result<FileId> {
        platform::file_id(file).map(FileId)
    }
}

/// An open directory to write in. Every operation takes a single file name inside it; what only reads is a
/// [`ReadDir`], which has no write methods on any platform.
pub struct Dir {
    file: File,
}

impl Dir {
    /// Opens the directory at `path`, following a link only under the ownership-transition rule (module doc).
    /// With `create`, a missing component is created relative to its parent's handle (unix: mode
    /// `0o777` before the umask, as `create_dir_all`). `owner`: see the module doc.
    pub fn open(path: &Path, create: bool, owner: Option<(u32, u32)>) -> io::Result<Dir> {
        Self::open_as(path, create, owner, platform::caller())
    }

    /// [`Self::open`] as `caller`; the seam lets a test claim to be another user.
    #[doc(hidden)]
    pub fn open_as(path: &Path, create: bool, owner: Option<(u32, u32)>, caller: Caller) -> io::Result<Dir> {
        platform::open_dir(path, create, owner, caller).map(|file| Dir { file })
    }

    /// The directory's own handle, for an operation on the directory itself (an ACL on Windows).
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Opens or creates `name` in the directory; see [`OpenFile`].
    pub fn open_file(&self, name: &OsStr, how: OpenFile) -> io::Result<File> {
        single_component(name)?;
        platform::open_file(&self.file, name, how)
    }

    /// The file `name` denotes right now, or `None`. A symlink is itself, not what it points at.
    pub fn id_of(&self, name: &OsStr) -> io::Result<Option<FileId>> {
        single_component(name)?;
        platform::id_of(&self.file, name).map(|id| id.map(FileId))
    }

    /// What `name` is right now, or `None` if there is nothing.
    pub fn kind_of(&self, name: &OsStr) -> io::Result<Option<EntryKind>> {
        single_component(name)?;
        platform::kind_of(&self.file, name)
    }

    /// A read-only view of this directory, for what only reads: it holds a duplicate of the handle, so it stays
    /// valid after `self` is dropped, and it has no way to write.
    pub fn reader(&self) -> io::Result<ReadDir> {
        Ok(ReadDir::from_handle(self.file.try_clone()?))
    }

    /// Gives the file `existing` a second name `new`, which must be free: `AlreadyExists` otherwise. A symlink is
    /// linked as itself, never what it points at.
    pub fn link(&self, existing: &OsStr, new: &OsStr) -> io::Result<()> {
        single_component(existing)?;
        single_component(new)?;
        platform::link(&self.file, existing, new)
    }

    /// Renames `from` to `to`, replacing `to` if it is there. Both are names in this directory.
    pub fn rename(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        single_component(from)?;
        single_component(to)?;
        platform::rename_by_name(&self.file, from, to)
    }

    /// Renames `from` to `to` in one atomic step, `AlreadyExists` if `to` is there. `Unsupported` where the platform
    /// or the filesystem cannot: the caller must not fall back to an exists-then-rename check, which is the race this
    /// call closes.
    pub fn rename_noreplace(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        single_component(from)?;
        single_component(to)?;
        platform::rename_noreplace(&self.file, from, to)
    }

    /// Flushes the directory, making the renames and unlinks done in it durable. A volume with no directory flush
    /// answers an error ([`io::Error::raw_os_error`]) the caller decides on.
    pub fn sync(&self) -> io::Result<()> {
        self.file.sync_all()
    }

    /// Writes `bytes` to a new same-directory temp file, syncs it, seals it to `owner` (unix: `fchmod 0600`,
    /// `fchown(owner)`) and passes it to `protect` (the place for a Windows ACL, or a wider unix mode), but does not
    /// give it `name`: [`Staged::publish`] replaces `name` with it and [`Staged::claim`] takes `name` only if it is
    /// free. Dropped, it removes the temp file.
    pub fn stage(
        &self,
        name: &OsStr,
        bytes: &[u8],
        owner: Option<(u32, u32)>,
        protect: impl FnOnce(&File) -> io::Result<()>,
    ) -> io::Result<Staged<'_>> {
        single_component(name)?;
        let (temp_name, temp) = self.create_temp(name)?;
        let mut staged = Staged {
            dir: self,
            name: name.to_os_string(),
            temp_name,
            temp: Some(temp),
            pending: true,
        };
        let temp = staged.temp.as_mut().expect("just set");
        temp.write_all(bytes)?;
        temp.sync_all()?;
        platform::seal(temp, owner)?;
        protect(temp)?;
        Ok(staged)
    }

    /// Opens `name` to append to, a file this call can trust: one it created (then given to `owner`), or an
    /// existing one that is `owner`'s own (unix: owned by `owner`'s uid; no `owner`: any regular file; Windows: a
    /// regular file with no other name, as the system makes one). Anything else at the name (another name of
    /// someone else's file, a link, a FIFO) is unlinked and replaced by a fresh file: it is never written to, and
    /// never changed. A directory at the name is an error. An existing file's mode and owner are left as they are.
    /// For a log in a folder a user may own, where a name the user planted must not make a privileged writer
    /// change a file it did not make.
    pub fn append_own_file(&self, name: &OsStr, mode: u32, owner: Option<(u32, u32)>) -> io::Result<File> {
        self.append_own_file_with(name, mode, owner, || {})
    }

    /// [`Self::append_own_file`] with `before_append` run right before an existing name is opened: the point where a
    /// name changed by another principal meets a guard that judged it earlier.
    pub(crate) fn append_own_file_with(
        &self,
        name: &OsStr,
        mode: u32,
        owner: Option<(u32, u32)>,
        mut before_append: impl FnMut(),
    ) -> io::Result<File> {
        // Each pass after the first means the user changed the name since the last one; the loop ends once they stop.
        loop {
            match self.open_file(name, OpenFile::CreateAppend { mode }) {
                Ok(file) => {
                    give_file(&file, owner);
                    return Ok(file);
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err),
            }
            before_append();
            // Opened first and judged only on failure: a name judged first can change before it is opened.
            let file = match self.open_file(name, OpenFile::Append) {
                Ok(file) => file,
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => match self.kind_of(name) {
                    Ok(None) => continue,
                    Ok(Some(EntryKind::Symlink | EntryKind::Other)) => {
                        self.unlink_if_there(name)?;
                        continue;
                    }
                    Ok(Some(EntryKind::File | EntryKind::Directory)) | Err(_) => return Err(err),
                },
            };
            if platform::is_own_file(&file, owner)? {
                return Ok(file);
            }
            // Closed first: Windows does not delete a name while a handle without delete sharing is open.
            drop(file);
            self.unlink_if_there(name)?;
        }
    }

    fn unlink_if_there(&self, name: &OsStr) -> io::Result<()> {
        match self.unlink(name) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }

    /// Removes the name, whatever it is, but not what it points at. `NotFound` if there is none.
    pub fn unlink(&self, name: &OsStr) -> io::Result<()> {
        single_component(name)?;
        platform::unlink(&self.file, name)
    }

    /// [`Self::open`] with the right to read and rewrite the final directory's ACL through [`Self::file`], which
    /// opening for use does not ask for (and which fails where the caller lacks it).
    #[cfg(windows)]
    pub fn open_for_acl(path: &Path, create: bool) -> io::Result<Dir> {
        platform::open_dir_with(path, create, platform::ACL_RIGHTS).map(|file| Dir { file })
    }

    /// Hands the directory itself to `owner` and, if given, sets its mode (unix; `0o700` for a state
    /// directory). A failed `fchown` is logged and not returned: an unprivileged run cannot give a
    /// file away and is no worse off for it. Windows has no unix ids or mode: set the ACL on
    /// [`Self::file`].
    pub fn secure(&self, owner: Option<(u32, u32)>, mode: Option<u32>) -> io::Result<()> {
        platform::secure_dir(&self.file, owner, mode)
    }

    /// Writes `bytes` to `name` as a whole or not at all: a same-directory temp file is written,
    /// synced, sealed to its owner (unix: `fchmod 0600`, `fchown(owner)`), passed to `protect` (the
    /// place for a Windows ACL) and then renamed over `name`. Everything is done through the temp
    /// file's handle before the rename, and the final name is never touched after it, so a
    /// name swapped for a hard link or symlink after the rename changes nothing.
    pub fn write_atomic(
        &self,
        name: &OsStr,
        bytes: &[u8],
        owner: Option<(u32, u32)>,
        protect: impl FnOnce(&File) -> io::Result<()>,
    ) -> io::Result<()> {
        self.write_atomic_with(name, bytes, owner, protect, || {})
    }

    /// [`Self::write_atomic`] with `after_rename` run right after the rename: the point where a
    /// name changed by another principal would meet any step that still went by the final name.
    pub(crate) fn write_atomic_with(
        &self,
        name: &OsStr,
        bytes: &[u8],
        owner: Option<(u32, u32)>,
        protect: impl FnOnce(&File) -> io::Result<()>,
        after_rename: impl FnOnce(),
    ) -> io::Result<()> {
        self.stage(name, bytes, owner, protect)?.publish_with(after_rename)
    }

    /// A new file named after `name` that nobody else holds, and its name.
    fn create_temp(&self, name: &OsStr) -> io::Result<(OsString, File)> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let mut temp_name = OsString::from(".");
            temp_name.push(name);
            temp_name.push(format!(
                ".{}.{}.tmp",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match platform::create_temp(&self.file, &temp_name) {
                Ok(file) => return Ok((temp_name, file)),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err),
            }
        }
    }
}

/// A complete temp file in a [`Dir`] that does not yet have its final name; see [`Dir::stage`].
pub struct Staged<'a> {
    dir: &'a Dir,
    name: OsString,
    temp_name: OsString,
    temp: Option<File>,
    /// The temp name still exists and is ours to remove.
    pending: bool,
}

impl Staged<'_> {
    /// Renames the temp file over the final name, replacing what is there.
    pub fn publish(self) -> io::Result<()> {
        self.publish_with(|| {})
    }

    /// [`Self::publish`] with `after_rename` run right after the rename.
    pub(crate) fn publish_with(mut self, after_rename: impl FnOnce()) -> io::Result<()> {
        let temp = self.temp.as_ref().expect("held until dropped");
        platform::rename(&self.dir.file, temp, &self.temp_name, &self.name)?;
        // The temp name is gone: it is the final name now.
        self.pending = false;
        after_rename();
        Ok(())
    }

    /// Gives the temp file the final name if that is free (`AlreadyExists` otherwise), by a hard link, then removes
    /// the temp name. Two claims of one name cannot both win, and a reader never sees a partial file.
    pub fn claim(self) -> io::Result<()> {
        self.dir.link(&self.temp_name, &self.name)
    }
}

impl Drop for Staged<'_> {
    fn drop(&mut self) {
        // Closed first: Windows does not let a name be deleted while a handle that does not share delete is open.
        drop(self.temp.take());
        if self.pending {
            // The caller already has its answer, so a failure is logged, not returned: the name stays in a folder
            // a user may own, and after a `claim` it is a second link to the published file. Gone already is fine.
            match platform::unlink(&self.dir.file, &self.temp_name) {
                Err(err) if err.kind() != io::ErrorKind::NotFound => {
                    tracing::warn!(error = %err, temp = %self.temp_name.to_string_lossy(), "a temporary file was left behind");
                }
                _ => {}
            }
        }
    }
}

/// Hands the open file to `owner` (unix `fchown`; Windows has no unix ids). A failure is logged and not returned: an
/// unprivileged run cannot give a file away and is no worse off for it.
pub fn give_file(file: &File, owner: Option<(u32, u32)>) {
    platform::give_file(file, owner);
}

/// Writes `bytes` to the state file `name` in `state_dir` as a whole or not at all, for a privileged
/// writer whose state directory the interactive user may own: the directory is opened without
/// following a symlink and created if missing, handed to `owner`, and the file is written through
/// [`Dir::write_atomic`] (owned by `owner`, mode `0600`, unix). Nothing goes by path after the open.
pub fn write_state_file(state_dir: &Path, name: &OsStr, bytes: &[u8], owner: Option<(u32, u32)>) -> io::Result<()> {
    let dir = Dir::open(state_dir, true, owner)?;
    dir.secure(owner, None)?;
    dir.write_atomic(name, bytes, owner, |_| Ok(()))
}

/// Removes the state file `name` in `state_dir`, the counterpart of [`write_state_file`] for a privileged step that
/// runs in a folder the interactive user may own: the directory is opened without following a symlink and the name
/// is unlinked through the handle, so a link planted in the path is refused ([`Refusal`]) and a link at the name is
/// removed as itself. Missing is `Ok`, whether the file or the directory. Nothing is created.
pub fn remove_state_file(state_dir: &Path, name: &OsStr) -> io::Result<()> {
    let dir = match Dir::open(state_dir, false, None) {
        Ok(dir) => dir,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    match dir.unlink(name) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

/// Makes `dir` (and the folders above it) if missing and frees `name` in it, for a privileged step about to create
/// `name` itself by path, as a socket bind does, in a folder the interactive user may own. Both go through a handle
/// opened without following a symlink: a link planted on the way is refused ([`Refusal`]), and what is at `name`
/// (a stale file, or a link) is unlinked as itself. A name that is not there is `Ok`; one that cannot be unlinked is
/// an error, as it is for [`remove_state_file`].
pub fn make_dir_and_free_name(dir: &Path, name: &OsStr) -> io::Result<()> {
    match Dir::open(dir, true, None)?.unlink(name) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

/// The whole file `name` in the state directory `state_dir`, the counterpart of [`write_state_file`] for a reader
/// that runs privileged. `NotFound` for a missing file or directory. The directory is walked by [`ReadDir::open`]: a
/// link at the name, or a FIFO a user planted there, is an error, never the file it leads to and never a wait. So is a
/// file the folder's owner cannot vouch for ([`Refusal::ForeignFile`]): one owned by the folder's own user is read, and
/// so is one the system owns that has no second name, but a second name a user added to any other file is not. The
/// files this reads are published by rename, so none has a second name of its own making. A file the system owns that
/// the user moved to the name is read: the caller parses it as its schema and logs a `ParseFailure`, never the text.
pub fn read_state_file(state_dir: &Path, name: &OsStr) -> io::Result<Vec<u8>> {
    ReadDir::open(state_dir)?.read_vouched(name)
}

/// The whole file `name` in the directory `dir`, through a handle that shares delete, so a replace of the file does
/// not wait for the read. A symlink at the name is an error, not followed.
fn read_whole(dir: &File, name: &OsStr) -> io::Result<Vec<u8>> {
    single_component(name)?;
    read_to_end(platform::open_file(dir, name, OpenFile::Read)?)
}

/// [`read_whole`] for a file the folder's owner must vouch for ([`trail::may_read`]): refused with
/// [`Refusal::ForeignFile`] before a byte is read.
fn read_whole_vouched(dir: &File, name: &OsStr) -> io::Result<Vec<u8>> {
    single_component(name)?;
    let file = platform::open_file(dir, name, OpenFile::Read)?;
    if !platform::is_vouched_for(dir, &file)? {
        return Err(Refusal::ForeignFile.into_io_error());
    }
    read_to_end(file)
}

fn read_to_end(mut file: File) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// `name` must be one ordinary file name: no separator, and not empty, `.` or `..`.
fn single_component(name: &OsStr) -> io::Result<()> {
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(only)), None) if only == name => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a single file name",
        )),
    }
}

#[cfg(test)]
#[path = "dir_tests.rs"]
mod dir_tests;
