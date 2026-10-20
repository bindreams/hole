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
//! **Open discipline (security-relevant, applies to both platforms
//! wherever the mechanism exists):** the lock file is opened with the
//! symlink-attack defense native to the platform (`O_NOFOLLOW` on unix,
//! reparse-point rejection on Windows — see `open_locked` in each
//! platform module below), its permissions are set explicitly at open
//! rather than trusted to umask/ACL defaults, and ownership is transferred
//! on the open file descriptor/handle, never by path — a path-based chown
//! after the fact is a TOCTOU window on a user-writable directory (the
//! elevation-mode state dir this exists to protect). None of the three is
//! simplified away for either platform.
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

use std::fs::File;
use std::io;
use std::path::Path;

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
    /// descriptor/handle once the lock is held; `None` leaves ownership
    /// alone (the root-owned `--service` daemon case).
    pub fn try_acquire(path: &Path, owner: Option<(u32, u32)>) -> io::Result<Option<Self>> {
        on_acquire_entry();
        match platform::open_locked(path, false)? {
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
        on_acquire_entry();
        let file = platform::open_locked(path, true)?.expect("blocking open_locked always returns Some");
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

// Platform: unix ======================================================================================================

#[cfg(unix)]
mod platform {
    use super::*;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::os::unix::io::AsRawFd;

    /// Open (creating if absent) with `O_NOFOLLOW` — refuses to follow a
    /// symlink planted at `path`, the defense against a user-writable state
    /// directory being used to redirect this open elsewhere — then take an
    /// exclusive `flock` on the resulting file description, blocking or not
    /// per `block`. `Ok(None)` only when `block` is false and the lock is
    /// held elsewhere; a blocking open always resolves to `Ok(Some(_))` or
    /// `Err`.
    pub(super) fn open_locked(path: &Path, block: bool) -> io::Result<Option<File>> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;

        // Set the mode explicitly and unconditionally rather than trust the
        // create-time mode above to survive umask — same discipline
        // `target.rs::save` uses for the state file itself.
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

    /// `fchown` on the file descriptor, never on the path — a path-based
    /// chown after `open_locked` returns would re-open the TOCTOU window
    /// `O_NOFOLLOW` just closed on the initial open. No-op when `owner` is
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
}

// Platform: windows ===================================================================================================

#[cfg(windows)]
mod platform {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY};

    /// Windows has no direct `O_NOFOLLOW`; the equivalent defense is to open
    /// with `FILE_FLAG_OPEN_REPARSE_POINT` (so `CreateFileW` does not
    /// transparently follow a symlink/junction planted at `path`) and then
    /// reject the open outright if the resulting handle turns out to be a
    /// reparse point — refusing to follow it, same intent as `O_NOFOLLOW`.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

    pub(super) fn open_locked(path: &Path, block: bool) -> io::Result<Option<File>> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;

        // Reject a reparse point the same open_locked call would otherwise
        // have silently traversed — see the const doc above.
        {
            use std::os::windows::fs::MetadataExt;
            let attrs = file.metadata()?.file_attributes();
            if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(io::Error::other("refusing to lock through a reparse point"));
            }
        }

        // No POSIX mode to set here — the owner-only DACL for this file is
        // applied by the caller's existing service/task-scheduler install
        // path, same as `target.rs::save`'s Windows arm.

        let handle = HANDLE(file.as_raw_handle());
        let flags = if block {
            LOCKFILE_EXCLUSIVE_LOCK
        } else {
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY
        };
        let mut overlapped = windows::Win32::System::IO::OVERLAPPED::default();
        // SAFETY: `handle` is a valid, open file handle for the duration of
        // this call; `overlapped` is a local, live for the same duration; the
        // lock region (0..=u32::MAX twice) covers the whole file, which is
        // never more than a few hundred bytes of JSON.
        let result = unsafe { LockFileEx(handle, flags, None, u32::MAX, u32::MAX, &mut overlapped) };
        match result {
            Ok(()) => Ok(Some(file)),
            Err(e) => {
                if !block && e.code() == windows::Win32::Foundation::ERROR_LOCK_VIOLATION.to_hresult() {
                    return Ok(None);
                }
                Err(io::Error::from(e))
            }
        }
    }

    /// Windows has no `fchown` equivalent; ownership here is a POSIX-only
    /// concept (NTFS ownership is a DACL/SID, set by the caller's install
    /// path — see `target.rs::save`'s Windows arm for the same split).
    /// Always a no-op.
    pub(super) fn chown_fd(_file: &File, _owner: Option<(u32, u32)>) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "exclusive_tests.rs"]
mod exclusive_tests;
