//! Who may open a lock file: exactly the principals that may write the file
//! it guards.
//!
//! Holding the lock takes read access to its file, so anyone who can open the
//! lock file can stall every writer of the guarded file for as long as they
//! like. A principal that can write the guarded file can already corrupt it,
//! so giving it the lock adds no power; a principal that can only read it must
//! not be able to open the lock at all.
//!
//! The owner always keeps the lock: it can change the guarded file's mode or
//! DACL, and so write it, whatever they say now.

#[cfg(unix)]
#[path = "lock_access/unix.rs"]
mod imp;
#[cfg(windows)]
#[path = "lock_access/windows.rs"]
mod imp;

pub(super) use imp::Writers;
