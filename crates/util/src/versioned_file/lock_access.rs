//! Who may open a lock file: exactly the principals that may write the file
//! it guards.
//!
//! Holding the lock takes read access to its file, so anyone who can open the
//! lock file can stall every writer of the guarded file for as long as they
//! like. A principal that can write the guarded file can already corrupt it,
//! so giving it the lock adds no power; a principal that can only read it must
//! not be able to open the lock at all.
//!
//! The lock file is created in place, by one call that fails when the name is
//! taken, and never through a temp file and a rename. It has no instant at
//! which its name is visible and its access is wrong: on Windows it is made
//! with its final DACL, on unix owner-only and then widened. An existing lock
//! is opened without following a link, and anything that is not a regular file
//! is refused.
//!
//! The owner can change the guarded file's mode or DACL, and so write it,
//! whatever they say now: it keeps the lock. On unix the lock is also owned by
//! the guarded file's owner, so only that owner, or root, can create it; a
//! principal that writes the file through the group or a POSIX or macOS ACL
//! entry cannot create the lock, and cannot open one whose mode its ACL entry,
//! rather than its mode bits, makes it a writer for.

#[cfg(unix)]
#[path = "lock_access/unix.rs"]
mod imp;
#[cfg(windows)]
#[path = "lock_access/windows.rs"]
mod imp;

pub(super) use imp::{open_existing, Writers};
