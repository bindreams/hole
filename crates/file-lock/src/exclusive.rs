//! A cross-process exclusive file lock, associated with the open file
//! description/handle (not the owning process), so same-process contention
//! is testable by opening the same path twice.
//!
//! `Exclusive` is the shared core: a bare acquired-lock token with no
//! knowledge of what path means or who wraps it. Domain-specific callers (e.g.
//! `TargetExclusive` in the bridge) wrap it with their own keyed path and
//! `Send`-ness. `Exclusive` stays `Send`; a newtype opts out via
//! `PhantomData<*const ()>` when its contract needs it.
//!
//! **Invariant: no token without holding the lock.** Constructing an
//! `Exclusive` *is* acquiring it — there is no separate "acquired" state to
//! forget to check, and no `Held` arm on the blocking path: a blocking
//! acquisition cannot observe contention, only succeed or fail with an I/O
//! error.
//!
//! # Open protocol
//!
//! The lock sits in a directory another principal may write (the
//! elevation-mode state dir belongs to the interactive user), so whatever is at
//! the lock name is attacker-chosen, and the name, like every directory above it,
//! can change between any two calls that take it. The protocol decides on what
//! the attacker cannot change once the file is open, never on the name:
//!
//! 1. Create the file with `O_CREAT|O_EXCL` (Windows: `CREATE_NEW`). That never
//!    follows a symlink and never reuses a file, so a file it creates is ours.
//! 2. If the name exists, reopen it without creating; a name that vanished goes
//!    back to 1. A symlink (Windows: any reparse point), directory, socket or
//!    other non-regular file is refused with a [`Refused`].
//! 3. Unix, with an `owner`: the existing file's uid must be the owner's,
//!    exactly. Only root can change a file's uid, so, unlike its link count, it
//!    cannot change after the check. A file owned by this process instead is not
//!    used: it is locked, its *name* is unlinked, and a fresh file is created.
//!    That recovers the file a previous run created and died before its
//!    `fchown` (refusing it would lock the owner out). It is also what happens
//!    to an unrelated file this process owns that was hard-linked at the name:
//!    the unlink touches only the name, never that file. A file owned by anyone
//!    else is refused.
//! 4. `fchmod` and `fchown` are applied only to a file this call created or the
//!    `owner` already owns. With no `owner` an existing file is only locked.
//! 5. Once locked, the name must still name the open file (device and inode);
//!    if the previous holder unlinked it, start over.
//!
//! So whatever an attacker does to the name or its links, before or after the
//! open, no file but one this call created or the `owner` owns is
//! re-permissioned or chowned. A kept file with a second name is also refused,
//! but that check does not protect: the count can change after it is read.
//!
//! The directory part of `path` is opened once, as a [`Dir`] (missing components
//! created, no symlink another user could have planted followed, and with an
//! `owner` the directory must be owned by it or by this process), and every step
//! on the lock file above goes through that handle: the open, the name check and
//! the unlink of a leftover. A path swapped after the directory is open is never
//! consulted.
//!
//! Windows applies no security descriptor (the owner-only DACL comes from the
//! install path), so it has nothing to redirect. It opens without
//! `FILE_SHARE_DELETE`, so while the lock is held the name can be neither
//! removed nor renamed and the vetted file stays the one at the name.
//!
//! **Hooks.** `on_acquire_entry` and `on_token_drop` are deliberate no-op seams
//! for a caller-side depth guard; keep the calls.

use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use crate::dir::{self, Dir, EntryKind};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as platform;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as platform;

// Extensibility hooks =================================================================================================

/// Called at the start of every acquisition attempt ([`Exclusive::try_acquire`]
/// and [`Exclusive::acquire`]), before anything else.
#[inline]
fn on_acquire_entry() {}

/// Called when a held [`Exclusive`] token's lock is released (on `Drop`).
#[inline]
fn on_token_drop() {}

// Refusal =============================================================================================================

/// Why an existing lock file was refused. The one place that decides how each
/// reason reads.
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    /// Not a regular file: a FIFO, device, socket or directory.
    NotRegular,
    /// More than one name: a hard link planted next to some other file.
    ExtraLinks { links: u64 },
    /// A symbolic link where the lock file should be. On Windows any reparse
    /// point (a junction is a directory symlink) counts.
    Symlink,
    /// Owned by neither the expected owner nor this process.
    #[cfg(unix)]
    ForeignOwner { uid: u32 },
    /// The directory the lock file is in was refused; see [`dir::Refusal`].
    Directory(dir::Refusal),
}

impl Refusal {
    /// What sits at `name` in `dir` when opening it failed, if that is a reason to refuse it: the
    /// OS reports a symlink, directory or socket by an errno that differs per platform.
    fn of_unopenable(dir: &Dir, name: &OsStr) -> Option<Self> {
        match dir.kind_of(name) {
            Ok(Some(EntryKind::Symlink)) => Some(Refusal::Symlink),
            Ok(Some(EntryKind::Directory | EntryKind::Other)) => Some(Refusal::NotRegular),
            Ok(Some(EntryKind::File) | None) | Err(_) => None,
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::NotRegular => f.write_str("the lock file is not a regular file"),
            Refusal::ExtraLinks { links } => write!(f, "the lock file has {links} links, not 1"),
            Refusal::Symlink => f.write_str("the lock file is a symbolic link"),
            #[cfg(unix)]
            Refusal::ForeignOwner { uid } => write!(f, "the lock file is owned by uid {uid}"),
            Refusal::Directory(why) => write!(f, "the lock file's directory was refused: {why}"),
        }
    }
}

/// The payload of the `InvalidData` [`io::Error`] that [`Exclusive::try_acquire`]
/// and [`Exclusive::acquire`] return for a refused lock file; recover it with
/// [`Refused::from_error`].
///
/// The path is a filesystem path, so it can name an account (the lock sits in a
/// user's profile). Neither `Display` nor `Debug` carries it: logging the error
/// with `%e` or `?e` cannot leak it. [`Refused::path`] is the one way out, for
/// a caller whose sink may hold a path.
pub struct Refused {
    path: PathBuf,
    why: Refusal,
}

impl Refused {
    /// The refusal inside `err`, or `None` if `err` is not one.
    pub fn from_error(err: &io::Error) -> Option<&Refused> {
        err.get_ref()?.downcast_ref()
    }

    /// The lock path that was refused.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn into_io_error(self) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, self)
    }

    /// `err`, a failed open of `name` in `dir` (the lock file `path`), as a refusal when what sits
    /// there is one.
    fn from_failed_open(dir: &Dir, name: &OsStr, path: &Path, err: io::Error) -> io::Error {
        match Refusal::of_unopenable(dir, name) {
            Some(why) => Refused {
                path: path.to_path_buf(),
                why,
            }
            .into_io_error(),
            None => err,
        }
    }

    /// `err`, a failed open of the lock file's directory, as a refusal when it is one.
    fn from_dir_error(path: &Path, err: io::Error) -> io::Error {
        match dir::Refusal::from_error(&err) {
            Some(&why) => Refused {
                path: path.to_path_buf(),
                why: Refusal::Directory(why),
            }
            .into_io_error(),
            None => err,
        }
    }
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "refusing to lock: {}", self.why)
    }
}

impl fmt::Debug for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Refused")
            .field("why", &self.why)
            .finish_non_exhaustive()
    }
}

impl std::error::Error for Refused {}

/// The directory part and the file name of the lock path. A bare name is in the current directory.
fn split(path: &Path) -> io::Result<(&Path, &OsStr)> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "a lock path must end in a file name"))?;
    let parent = path.parent().filter(|parent| !parent.as_os_str().is_empty());
    Ok((parent.unwrap_or(Path::new(".")), name))
}

// Exclusive ===========================================================================================================

/// A held exclusive lock on the file at the path it was acquired for.
/// Dropping it releases the lock (closing the underlying file description
/// releases every `flock`/`LockFileEx` lock held through it — no explicit
/// unlock call is needed or made).
pub struct Exclusive {
    // Never read: closing it on drop releases the lock.
    #[allow(dead_code)]
    file: File,
}

impl Exclusive {
    /// Attempt to acquire the lock without blocking.
    ///
    /// `Ok(None)` means the lock is currently held by someone else (this
    /// process or another) — contention, not an error. `owner`, when
    /// `Some((uid, gid))`, is applied via `fchown` once the lock is held (unix;
    /// Windows ignores it), and an existing lock file is only used if `uid`
    /// owns it; `None` expects no owner and leaves an existing file as it is
    /// (the root-owned `--service` daemon case). See the module doc's open
    /// protocol.
    ///
    /// Missing directories above the file are created. A symlink, directory,
    /// socket or other non-regular file at the path, a file with a second name,
    /// one owned by a third party, or a directory in the path that is a symlink
    /// or (with an `owner`) owned by a third party, is refused with an
    /// `InvalidData` error holding a [`Refused`]; a refused file is never
    /// re-permissioned and nothing is created outside the directory the path
    /// names.
    pub fn try_acquire(path: &Path, owner: Option<(u32, u32)>) -> io::Result<Option<Self>> {
        Self::try_acquire_as(path, owner, platform::caller())
    }

    /// [`Self::try_acquire`] as `caller`. The seam lets a test drive a file the
    /// real caller owns through the owner rule, which an unprivileged test cannot
    /// otherwise make fail.
    fn try_acquire_as(path: &Path, owner: Option<(u32, u32)>, caller: platform::Caller) -> io::Result<Option<Self>> {
        on_acquire_entry();
        match platform::open_locked(path, false, owner, caller)? {
            Some(file) => {
                platform::chown_fd(&file, owner)?;
                Ok(Some(Exclusive { file }))
            }
            None => Ok(None),
        }
    }

    /// Acquire the lock, blocking until it is available. See [`Self::try_acquire`]
    /// for `owner` and the refusals.
    ///
    /// Callers must be a leaf with respect to the invariant their own wrapper
    /// documents; `Exclusive` does not enforce it.
    pub fn acquire(path: &Path, owner: Option<(u32, u32)>) -> io::Result<Self> {
        Self::acquire_as(path, owner, platform::caller())
    }

    /// [`Self::acquire`] as `caller`; see [`Self::try_acquire_as`].
    fn acquire_as(path: &Path, owner: Option<(u32, u32)>, caller: platform::Caller) -> io::Result<Self> {
        on_acquire_entry();
        let file = platform::open_locked(path, true, owner, caller)?.expect("blocking open_locked always returns Some");
        platform::chown_fd(&file, owner)?;
        Ok(Exclusive { file })
    }
}

impl Drop for Exclusive {
    fn drop(&mut self) {
        on_token_drop();
    }
}

#[cfg(test)]
#[path = "exclusive_tests.rs"]
mod exclusive_tests;
