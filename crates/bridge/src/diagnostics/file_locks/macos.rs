//! macOS handle-holder enumeration via Darwin's `libproc`.
//!
//! `libproc::processes::pids_by_path` is the thin Rust wrapper around
//! `proc_listpidspath`, which answers "which PIDs have this path open"
//! directly in the kernel — no handle-table walking, no privilege
//! escalation beyond what `lsof` already requires for foreign
//! processes. The caller's own process is filtered out.

use super::FileHolder;
use std::io;
use std::path::{Path, PathBuf};

pub(super) fn find_holders_impl(path: &Path) -> io::Result<Vec<FileHolder>> {
    let pids = libproc::processes::pids_by_path(path, false, false)
        .map_err(|e| io::Error::other(format!("pids_by_path failed: {e:?}")))?;
    let me = std::process::id();
    Ok(pids
        .into_iter()
        .filter(|&p| p != me)
        .map(|pid| FileHolder {
            pid,
            image: libproc::proc_pid::pidpath(pid as i32).ok().map(PathBuf::from),
            verified: true,
        })
        .collect())
}
