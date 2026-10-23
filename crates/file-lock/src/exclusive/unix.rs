//! Unix half of [`super::Exclusive`]: `flock`, `fstat` vetting, `fchmod`, `fchown`.

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;

use super::{split, Refusal, Refused};
use util::dir::{Dir, FileId, OpenFile};

/// What `fstat` says about the opened lock file; the only input to [`vet`].
#[derive(Clone, Copy, Debug)]
pub(super) struct Facts {
    pub regular: bool,
    pub uid: u32,
    /// The file's link count: how many names it has.
    pub links: u64,
}

/// What to do with an existing lock file that passed [`vet`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// Lock it where it is.
    Keep,
    /// Not the expected owner's, and not another principal's: a file this process
    /// left behind before its `fchown`, or one it only appears to own. Unlink the
    /// name and create a fresh file; the old file is never modified.
    Replace,
}

/// Decides whether an opened file may be used as the lock file.
///
/// `euid` is this process's effective uid. With `owner` given, only a file owned
/// by `owner`'s uid exactly is kept. One owned by `euid` instead is replaced: this
/// process created it and died before its `fchown`, or a file it owns was linked
/// at the name, and the two look alike. One owned by anyone else is refused.
/// Without an `owner`, no ownership is expected and none is checked.
///
/// The file is regular: [`open_locked_with`] refuses anything else before it takes the lock.
pub(super) fn vet(facts: Facts, euid: u32, owner: Option<(u32, u32)>) -> Result<Verdict, Refusal> {
    debug_assert!(
        facts.regular,
        "a file that is not regular is refused before it is locked"
    );
    match owner {
        Some((uid, _)) if facts.uid != uid && facts.uid == euid => return Ok(Verdict::Replace),
        Some((uid, _)) if facts.uid != uid => return Err(Refusal::ForeignOwner { uid: facts.uid }),
        _ => {}
    }
    Ok(Verdict::Keep)
}

/// Whether the open may change the mode and owner of the file it holds.
///
/// Only a file this call made, or one the expected owner owns and that has no other name: a file with another name
/// may be someone else's inode, hard-linked at the lock name, and is locked as it is. The count is read from the
/// open file under the lock; a name added later is a name for the lock file itself.
pub(super) fn changes(created: bool, facts: Facts, owner: Option<(u32, u32)>) -> bool {
    created || (owner.is_some() && facts.links == 1)
}

/// Who is acquiring: this process's effective uid.
pub(super) type Caller = u32;

/// The running process as a [`Caller`].
pub(super) fn caller() -> Caller {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

fn facts_of(file: &File) -> io::Result<Facts> {
    let meta = file.metadata()?;
    Ok(Facts {
        regular: meta.file_type().is_file(),
        uid: meta.uid(),
        links: meta.nlink(),
    })
}

fn refuse(path: &Path, why: Refusal) -> io::Error {
    Refused {
        path: path.to_path_buf(),
        why,
    }
    .into_io_error()
}

/// A file opened at the lock name, and whether this open created it.
struct Opened {
    file: File,
    created: bool,
}

/// A locked file, and whether [`changes`] let its mode be set (its owner is set after, by [`open_locked`]).
pub(super) struct Locked {
    pub file: File,
    changeable: bool,
}

/// Creates the lock file with `O_EXCL`, which never follows a symlink and never
/// reuses an existing file; if the name exists, opens that without `O_CREAT`.
/// `Ok(None)` when the name vanished between the two.
fn open_name(dir: &Dir, name: &OsStr, path: &Path) -> io::Result<Option<Opened>> {
    match dir.open_file(name, OpenFile::CreateNew { mode: 0o600 }) {
        Ok(file) => return Ok(Some(Opened { file, created: true })),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(Refused::from_failed_open(dir, name, path, err)),
    }
    match dir.open_file(name, OpenFile::Existing) {
        Ok(file) => Ok(Some(Opened { file, created: false })),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(Refused::from_failed_open(dir, name, path, err)),
    }
}

/// Whether `name` in `dir` still names the file `file` is open on.
fn names(dir: &Dir, name: &OsStr, file: &File) -> io::Result<bool> {
    Ok(dir.id_of(name)? == Some(FileId::of(file)?))
}

/// `flock` exclusive, blocking or not per `block`; `Ok(false)` when not blocking and held elsewhere.
fn lock(file: &File, block: bool) -> io::Result<bool> {
    let op = if block {
        libc::LOCK_EX
    } else {
        libc::LOCK_EX | libc::LOCK_NB
    };
    // SAFETY: the fd is valid; `file` outlives the call.
    let rc = unsafe { libc::flock(file.as_raw_fd(), op) };
    if rc == 0 {
        return Ok(true);
    }
    let err = io::Error::last_os_error();
    if !block && err.raw_os_error() == Some(libc::EWOULDBLOCK) {
        return Ok(false);
    }
    Err(err)
}

/// Opens and locks the lock file, blocking or not per `block`; see the module doc
/// for the protocol. `Ok(None)` only when `block` is false and the lock is held
/// elsewhere.
pub(super) fn open_locked(
    path: &Path,
    block: bool,
    owner: Option<(u32, u32)>,
    euid: Caller,
) -> io::Result<Option<File>> {
    let Some(Locked { file, changeable }) = open_locked_with(path, block, owner, euid, || {})? else {
        return Ok(None);
    };
    if changeable {
        chown_fd(&file, owner)?;
    }
    Ok(Some(file))
}

/// [`open_locked`] with `after_open` run right after each open: the point where
/// another principal's change to the name matters.
pub(super) fn open_locked_with(
    path: &Path,
    block: bool,
    owner: Option<(u32, u32)>,
    euid: Caller,
    mut after_open: impl FnMut(),
) -> io::Result<Option<Locked>> {
    let (parent, name) = split(path)?;
    // Everything below goes through this handle, never through `path` again.
    let dir = Dir::open_as(parent, true, owner, euid).map_err(|err| Refused::from_dir_error(path, err))?;
    loop {
        let Some(Opened { file, created }) = open_name(&dir, name, path)? else {
            continue;
        };
        after_open();

        // Not locked until known to be a regular file: `flock` on a FIFO or device is not ours to try.
        if !created && !facts_of(&file)?.regular {
            return Err(refuse(path, Refusal::NotRegular));
        }
        if !lock(&file, block)? {
            return Ok(None);
        }
        // Whoever held the lock before may have unlinked or replaced the name; this
        // file is then an orphan, and the name is evaluated afresh.
        if !names(&dir, name, &file)? {
            continue;
        }

        // Judged under the lock, so the owner it sees is the one that stays.
        let verdict = match created {
            true => Verdict::Keep,
            false => vet(facts_of(&file)?, euid, owner).map_err(|why| refuse(path, why))?,
        };
        match verdict {
            Verdict::Replace => match dir.unlink(name) {
                Ok(()) => continue,
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => return Err(err),
            },
            Verdict::Keep => {}
        }

        // The create mode is already at most 0600; this makes it exactly so, whatever the umask.
        let changeable = changes(created, facts_of(&file)?, owner);
        if changeable {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        return Ok(Some(Locked { file, changeable }));
    }
}

/// `fchown` on the file descriptor, never on the path. No-op when `owner` is `None`.
fn chown_fd(file: &File, owner: Option<(u32, u32)>) -> io::Result<()> {
    let Some((uid, gid)) = owner else {
        return Ok(());
    };
    // SAFETY: `file.as_raw_fd()` is a valid, open fd for the duration of
    // this call.
    let rc = unsafe { libc::fchown(file.as_raw_fd(), uid, gid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
#[path = "unix_tests.rs"]
mod unix_tests;
