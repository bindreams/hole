//! Enumerate the host's Windows user profiles, so the uninstall cover release
//! can find the liveness lock of a bridge running under an account that is not
//! its own (bindreams/hole#1003).
//!
//! The MSI's custom actions run as SYSTEM (`Impersonate="no"`), and Windows
//! elevation keeps a process in the *invoking* user's profile rather than
//! switching to root's the way `sudo` does. So the two never coincide: the
//! bridge a user started holds its lock under `C:\Users\<name>\AppData\Local`,
//! while `default_state_dir()` in the release's own process resolves to
//! `%SystemRoot%\System32\config\systemprofile\AppData\Local`. Without this
//! enumeration the peer probe has nothing to look at and the liveness check
//! passes unconditionally — the release then clears machine-wide WFP filters
//! out from under a live bridge whose posture still claims them.
//!
//! `ProfileList` is the OS's own record of where each account's profile lives
//! (`ProfileImagePath`), which is why it is read rather than `C:\Users` being
//! walked: a profile directory can be anywhere, and the registry is what the
//! profile service itself resolves against.

use std::path::PathBuf;

const PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

/// Every local profile directory `ProfileList` records, in enumeration order.
///
/// Includes the service profiles (SYSTEM, LocalService, NetworkService) — they
/// are real profiles a `--service` bridge could be using, and the caller
/// already skips a path it has probed.
///
/// Errors from an individual subkey are logged and skipped rather than
/// propagated: one unreadable profile must not blind the probe to the rest.
/// A failure to open `ProfileList` itself IS propagated — that is the case
/// where the probe knows nothing, and the caller has to say so out loud
/// instead of reporting an empty peer set that reads like "no other bridges".
pub fn profile_dirs() -> std::io::Result<Vec<PathBuf>> {
    let list = windows_registry::LOCAL_MACHINE
        .open(PROFILE_LIST)
        .map_err(|e| std::io::Error::other(format!("could not open HKLM\\{PROFILE_LIST}: {e}")))?;

    let sids = list
        .keys()
        .map_err(|e| std::io::Error::other(format!("could not enumerate HKLM\\{PROFILE_LIST}: {e}")))?;

    let mut dirs = Vec::new();
    for sid in sids {
        match list.open(&sid).and_then(|k| k.get_string("ProfileImagePath")) {
            Ok(path) => dirs.push(PathBuf::from(path)),
            Err(e) => tracing::debug!(%sid, error = %e, "profile entry has no readable ProfileImagePath"),
        }
    }
    Ok(dirs)
}
