//! A cross-process exclusive file lock, associated with the open file
//! description/handle (not the owning process), so same-process contention
//! is testable by opening the same path twice.
//!
//! `Exclusive` is the shared core: a bare acquired-lock token with no
//! knowledge of what path means or who wraps it. Domain-specific callers
//! (`crates/bridge/src/target.rs`'s `TargetExclusive`, and the sibling three
//! newtypes #878 adds after this lands — `SocketExclusive`,
//! `Arc<MachineExclusive>`, `StateExclusive`) wrap it with their own keyed
//! path and their own `Send`-ness. `Exclusive` itself stays `Send` (a `File`
//! is `Send`); a newtype opts out via its own `PhantomData<*const ()>` field
//! when its contract needs it — see `TargetExclusive` for why.
//!
//! **Invariant: no token without holding the lock.** Constructing an
//! `Exclusive` *is* acquiring it — there is no separate "acquired" state to
//! forget to check, and no `Held` arm on the blocking path: a blocking
//! acquisition cannot observe contention, only succeed or fail with an I/O
//! error.
//!
//! **Open discipline (security-relevant).** The lock sits in a directory
//! another principal may write (the elevation-mode state dir belongs to the
//! interactive user), so whatever is at the lock name when it is opened is
//! attacker-chosen. Every check and every change goes through the open
//! descriptor/handle, never the path:
//!
//! - the open refuses a symlink (`O_NOFOLLOW` on unix, reparse-point rejection
//!   on Windows);
//! - the opened file must be a regular file with exactly one link, and (unix,
//!   when an `owner` is given) owned by that owner or by the process itself.
//!   A hard link planted at the lock name to some other file passes
//!   `O_NOFOLLOW`; without this check the `fchmod`/`fchown` below would
//!   re-permission that file. A file that fails is refused with a path-free
//!   error ([`Refused`]), never repaired;
//! - only a file that passed is `fchmod`ed to `0600` and `fchown`ed to
//!   `owner`. Windows applies no security descriptor at all, by path or by
//!   handle: the owner-only DACL comes from the install path.
//!
//! The link-count window is closed: a hard link made to the lock file *after*
//! the check can only name our own lock file, which is ours to permission.
//!
//! **Extensibility hook for #878's depth guard.** `#878` adds a
//! complementary, debug-only thread-local depth guard on top of this core:
//! set while a leaf token is alive, checked on every acquisition, to catch
//! (in debug builds) an attempt to acquire a second lock while a leaf one
//! is already held on the same thread. This module must not foreclose that
//! guard, so [`on_acquire_entry`] and [`on_token_drop`] are called at the
//! two points the guard needs — entry to every acquisition attempt, and
//! release of a held token — and are deliberately no-ops here. Do not
//! remove these calls when refactoring; they are the seam, not dead code.

use std::fmt;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

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
/// and [`Exclusive::acquire`]), before anything else. See the module doc's
/// "Extensibility hook for #878's depth guard".
#[inline]
fn on_acquire_entry() {}

/// Called when a held [`Exclusive`] token's lock is released (on `Drop`).
/// See the module doc's "Extensibility hook for #878's depth guard".
#[inline]
fn on_token_drop() {}

// Refusal =============================================================================================================

/// Why an existing lock file was refused. The one place that decides how each
/// reason reads; platform modules only choose which reason applies.
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
}

impl Refusal {
    /// What sits at `path` when opening it failed, if that is a reason to refuse it: the
    /// OS reports a symlink, directory or socket by an errno that differs per platform.
    fn of_unopenable(path: &Path) -> Option<Self> {
        let kind = std::fs::symlink_metadata(path).ok()?.file_type();
        if kind.is_symlink() {
            Some(Refusal::Symlink)
        } else if !kind.is_file() {
            Some(Refusal::NotRegular)
        } else {
            None
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

    /// `err`, a failed open of `path`, as a refusal when what sits at `path` is one.
    fn from_failed_open(path: &Path, err: io::Error) -> io::Error {
        match Refusal::of_unopenable(path) {
            Some(why) => Refused {
                path: path.to_path_buf(),
                why,
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

// Exclusive ===========================================================================================================

/// A held exclusive lock on the file at the path it was acquired for.
/// Dropping it releases the lock (closing the underlying file description
/// releases every `flock`/`LockFileEx` lock held through it — no explicit
/// unlock call is needed or made).
pub struct Exclusive {
    // Never read directly — held only so its `Drop` (closing the fd/handle)
    // releases the OS-level lock when this token drops.
    #[allow(dead_code)]
    file: File,
}

impl Exclusive {
    /// Attempt to acquire the lock without blocking.
    ///
    /// `Ok(None)` means the lock is currently held by someone else (this
    /// process or another) — contention, not an error. `owner`, when
    /// `Some((uid, gid))`, is applied via `fchown` on the opened file
    /// descriptor once the lock is held (unix; Windows ignores it), and an
    /// existing lock file must already be owned by `uid` or by this process;
    /// `None` leaves ownership alone and does not check it (the root-owned
    /// `--service` daemon case).
    ///
    /// An existing lock file that is not a regular file with exactly one link
    /// (or has another owner, above) is refused with an `InvalidData` error
    /// holding a [`Refused`]; it is never re-permissioned.
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

    /// Acquire the lock, blocking until it is available.
    ///
    /// No `Held`/contention arm: a blocking acquisition cannot observe
    /// contention, only eventually succeed or fail with an I/O error. Every
    /// caller of this function must be a **leaf** with respect to whatever
    /// invariant its own newtype documents (see `TargetExclusive` in
    /// `crates/bridge/src/target.rs` for the one leaf-lock contract this
    /// core currently ships with) — `Exclusive` itself does not and cannot
    /// enforce that; it is a per-newtype contract, not a core one.
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
        // The OS releases the flock/LockFileEx lock when the last handle to
        // this open file description/handle closes, which happens when
        // `self.file` drops right after this. No explicit unlock call.
        on_token_drop();
    }
}

#[cfg(test)]
#[path = "exclusive_tests.rs"]
mod exclusive_tests;
