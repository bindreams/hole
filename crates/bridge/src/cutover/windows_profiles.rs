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
//!
//! Every outcome an entry can have is a [`ProfileEntry`] variant, and each one
//! is answered in a single exhaustive match ([`ProfileEntry::into_dir`]). That
//! shape is the point: the defect this module exists to fix is an enumeration
//! that yields no peer being read as "no other bridges", and the way it
//! recurs is an entry leaving the peer set down a branch that says nothing.
//! Nothing here shrinks the peer set quietly.

use std::path::PathBuf;

#[cfg(target_os = "windows")]
const PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

/// What one `ProfileList` entry resolved to.
#[derive(Debug, PartialEq, Eq)]
enum ProfileEntry {
    /// A profile directory that is on disk.
    Present(PathBuf),
    /// `ProfileImagePath` was read and expanded, but nothing is at the path it
    /// names. Kept, not dropped: the registry says a profile lives there, and
    /// the probe is not the judge of whether the OS is lying.
    Absent(PathBuf),
    /// The subkey, its value, or its environment references could not be read.
    /// This is the one outcome that has no path to offer.
    Unreadable(String),
}

impl ProfileEntry {
    /// The directory to hand the caller, and the only place the warn-vs-keep
    /// answer for each outcome is chosen.
    ///
    /// Both losing outcomes warn rather than `debug!`: the bridge's default
    /// filter is a global `info`, so a `debug!` here is invisible in the
    /// output of the uninstall that this probe gates.
    fn into_dir(self, sid: &str) -> Option<PathBuf> {
        match self {
            ProfileEntry::Present(dir) => Some(dir),
            ProfileEntry::Absent(dir) => {
                tracing::warn!(
                    %sid,
                    profile = %dir.display(),
                    "a profile directory ProfileList records is not on disk; a bridge running under \
                     that account would not be seen by the liveness probe"
                );
                Some(dir)
            }
            ProfileEntry::Unreadable(e) => {
                tracing::warn!(
                    %sid,
                    error = %e,
                    "a profile entry could not be resolved; a bridge running under that account \
                     would not be seen by the liveness probe"
                );
                None
            }
        }
    }
}

/// Classify one `ProfileList` entry's `ProfileImagePath`.
///
/// `expand` is injected so the classification — which is the policy — is
/// provable off Windows; production always passes [`expand_env_string`].
fn resolve_entry(raw: Result<String, String>, expand: impl FnOnce(&str) -> std::io::Result<String>) -> ProfileEntry {
    let raw = match raw {
        Ok(raw) => raw,
        Err(e) => return ProfileEntry::Unreadable(e),
    };
    // A failed expansion knows nothing about where the profile is. Falling
    // back to the unexpanded bytes would put a literal `%systemroot%\...` in
    // the peer set and call it a profile directory.
    let expanded = match expand(&raw) {
        Ok(expanded) => expanded,
        Err(e) => return ProfileEntry::Unreadable(e.to_string()),
    };
    let dir = PathBuf::from(expanded);
    if dir.is_dir() {
        ProfileEntry::Present(dir)
    } else {
        ProfileEntry::Absent(dir)
    }
}

/// Every local profile directory `ProfileList` records, in enumeration order.
///
/// Includes the service profiles (SYSTEM, LocalService, NetworkService) — they
/// are real profiles a `--service` bridge could be using, and the caller
/// already skips a path it has probed.
///
/// An individual entry that cannot be resolved warns and is skipped rather
/// than propagated: one unreadable profile must not blind the probe to the
/// rest. A failure to open `ProfileList` itself IS propagated — that is the case
/// where the probe knows nothing, and the caller has to say so out loud
/// instead of reporting an empty peer set that reads like "no other bridges".
#[cfg(target_os = "windows")]
pub fn profile_dirs() -> std::io::Result<Vec<PathBuf>> {
    let list = windows_registry::LOCAL_MACHINE
        .open(PROFILE_LIST)
        .map_err(|e| std::io::Error::other(format!("could not open HKLM\\{PROFILE_LIST}: {e}")))?;

    let sids = list
        .keys()
        .map_err(|e| std::io::Error::other(format!("could not enumerate HKLM\\{PROFILE_LIST}: {e}")))?;

    let mut dirs = Vec::new();
    for sid in sids {
        let raw = list
            .open(&sid)
            .and_then(|k| k.get_string("ProfileImagePath"))
            .map_err(|e| e.to_string());
        if let Some(dir) = resolve_entry(raw, expand_env_string).into_dir(&sid) {
            dirs.push(dir);
        }
    }
    Ok(dirs)
}

/// Expand the environment references in a registry string against this
/// process's environment block.
///
/// `windows-registry`'s `get_string` accepts `REG_SZ` and `REG_EXPAND_SZ`
/// alike and returns either verbatim — it records the type and never acts on
/// it. All three service SIDs store `ProfileImagePath` unexpanded
/// (`%systemroot%\system32\config\systemprofile`,
/// `%systemroot%\ServiceProfiles\...`), so skipping this step drops from the
/// peer set exactly the profile an elevated non-`--service` bridge under a
/// SYSTEM token resolves `default_state_dir()` to.
///
/// `ExpandEnvironmentStringsW` rather than rewriting a leading `%VAR%`: it is
/// what the profile service itself resolves against, and it handles a
/// reference anywhere in the string. A reference to an unset variable is left
/// standing by design — the caller classifies the answer by whether it is on
/// disk, which is the honest verdict either way.
#[cfg(target_os = "windows")]
fn expand_env_string(raw: &str) -> std::io::Result<String> {
    use windows::core::HSTRING;
    use windows::Win32::System::Environment::ExpandEnvironmentStringsW;

    let src = HSTRING::from(raw);
    let mut buf: Vec<u16> = Vec::new();
    loop {
        // SAFETY: `src` is a NUL-terminated wide string that outlives the
        // call, and the destination is either absent or a uniquely borrowed
        // slice whose length the binding itself passes as `nSize`.
        let needed = unsafe {
            if buf.is_empty() {
                // Sizing pass: with no destination the call returns the
                // length it needs, terminating NUL included.
                ExpandEnvironmentStringsW(&src, None)
            } else {
                ExpandEnvironmentStringsW(&src, Some(buf.as_mut_slice()))
            }
        } as usize;

        if needed == 0 {
            let cause = std::io::Error::last_os_error();
            return Err(std::io::Error::other(format!(
                "could not expand the environment references in {raw:?}: {cause}"
            )));
        }
        if needed <= buf.len() {
            buf.truncate(needed - 1); // drop the terminating NUL
            return String::from_utf16(&buf)
                .map_err(|e| std::io::Error::other(format!("expansion of {raw:?} is not valid UTF-16: {e}")));
        }
        // Short buffer. No retry budget: the only way round again is the
        // environment block growing between two calls, and the loop just
        // re-sizes to whatever the OS now asks for.
        buf.resize(needed, 0);
    }
}

#[cfg(test)]
#[path = "windows_profiles_tests.rs"]
mod windows_profiles_tests;
