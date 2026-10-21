//! Unix half of [`super::Exclusive`]: `flock`, `fstat` vetting, `fchmod`, `fchown`.

use std::fs::File;
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;

use super::{Refusal, Refused};

/// What `fstat` says about the opened lock file; the only input to [`vet`].
#[derive(Clone, Copy, Debug)]
pub(super) struct Facts {
    pub regular: bool,
    pub links: u64,
    pub uid: u32,
}

/// Decides whether an opened file may be used as the lock file.
///
/// `euid` is this process's effective uid. With `owner` given the file must be
/// owned by `owner`'s uid or by `euid` (a file this process created before it
/// got to `fchown`); without one, ownership is not checked.
pub(super) fn vet(facts: Facts, euid: u32, owner: Option<(u32, u32)>) -> Result<(), Refusal> {
    if !facts.regular {
        return Err(Refusal::NotRegular);
    }
    if facts.links != 1 {
        return Err(Refusal::ExtraLinks { links: facts.links });
    }
    match owner {
        Some((uid, _)) if facts.uid != uid && facts.uid != euid => Err(Refusal::ForeignOwner { uid: facts.uid }),
        _ => Ok(()),
    }
}

/// Who is acquiring: this process's effective uid, which the owner rule accepts
/// as the owner of a file it created before it got to `fchown`.
pub(super) type Caller = u32;

/// The running process as a [`Caller`].
pub(super) fn caller() -> Caller {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

/// Open (creating if absent) with `O_NOFOLLOW` — refuses to follow a symlink
/// planted at `path` — vet the opened file through its descriptor, then set its
/// mode and take an exclusive `flock` on it, blocking or not per `block`.
/// `Ok(None)` only when `block` is false and the lock is held elsewhere; a
/// blocking open always resolves to `Ok(Some(_))` or `Err`. `euid` is the
/// effective uid the vet accepts besides `owner`'s.
pub(super) fn open_locked(
    path: &Path,
    block: bool,
    owner: Option<(u32, u32)>,
    euid: Caller,
) -> io::Result<Option<File>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|err| Refused::from_failed_open(path, err))?;

    let meta = file.metadata()?;
    let facts = Facts {
        regular: meta.file_type().is_file(),
        links: meta.nlink(),
        uid: meta.uid(),
    };
    vet(facts, euid, owner).map_err(|why| {
        Refused {
            path: path.to_path_buf(),
            why,
        }
        .into_io_error()
    })?;

    // Set the mode explicitly rather than trust the create-time mode above to
    // survive umask. Only after `vet`: this is a change to the file.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;

    let op = if block {
        libc::LOCK_EX
    } else {
        libc::LOCK_EX | libc::LOCK_NB
    };
    // SAFETY: `file.as_raw_fd()` is a valid, open fd for the lifetime of
    // this call (`file` is not dropped until after it returns).
    let rc = unsafe { libc::flock(file.as_raw_fd(), op) };
    if rc == 0 {
        return Ok(Some(file));
    }
    let err = io::Error::last_os_error();
    if !block && err.raw_os_error() == Some(libc::EWOULDBLOCK) {
        return Ok(None);
    }
    Err(err)
}

/// `fchown` on the file descriptor, never on the path. No-op when `owner` is
/// `None`.
pub(super) fn chown_fd(file: &File, owner: Option<(u32, u32)>) -> io::Result<()> {
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
