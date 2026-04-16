//! macOS handle-holder enumeration via Darwin's `libproc`.
//!
//! `libproc::processes::pids_by_path` is the thin Rust wrapper around
//! `proc_listpidspath`, which answers "which PIDs have this path open"
//! directly in the kernel — no handle-table walking, no privilege
//! escalation beyond what `lsof` already requires for foreign
//! processes. The caller's own process is filtered out.
//!
//! # macOS quirks
//!
//! - `proc_listpidspath` matches paths literally (no symlink
//!   resolution in the kernel lookup), so we canonicalize first to
//!   dodge macOS's `/var -> /private/var` tempdir alias.
//! - On "no matches" the underlying syscall returns `ESRCH` (3) rather
//!   than writing an empty buffer, and libproc propagates that as an
//!   `io::Error`. We intercept and convert to `Ok(vec![])` since the
//!   public contract is "returns empty when nothing holds the file,
//!   errors only on actual enumeration failure."

use super::FileHolder;
use std::io;
use std::path::{Path, PathBuf};

pub(super) fn find_holders_impl(path: &Path) -> io::Result<Vec<FileHolder>> {
    // Canonicalize first so we match against the kernel's resolved path
    // (tempdir on macOS sits under `/private/var/...` but is accessed
    // via the `/var/...` symlink).
    let path = std::fs::canonicalize(path)?;

    let pids = match libproc::processes::pids_by_path(&path, false, false) {
        Ok(v) => v,
        // ESRCH — libproc's way of saying "no processes matched". Not
        // an error for our contract.
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => return Ok(Vec::new()),
        Err(e) => return Err(io::Error::other(format!("pids_by_path({path:?}) failed: {e}"))),
    };

    let me = std::process::id();
    Ok(pids
        .into_iter()
        .filter(|&p| p != me)
        .map(|pid| FileHolder {
            pid,
            image: libproc::proc_pid::pidpath(pid as i32).ok().map(PathBuf::from),
        })
        .collect())
}
