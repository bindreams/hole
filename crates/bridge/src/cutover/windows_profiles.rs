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
//! Every outcome an entry can have is a [`ProfileEntry`] variant, and every
//! way the pass over `ProfileList` can end is an [`EnumEnd`] variant; each is
//! answered in a single exhaustive match ([`ProfileEntry::into_dir`],
//! [`EnumEnd::disclose`]). That shape is the point: the defect this module
//! exists to fix is an enumeration that yields no peer being read as "no other
//! bridges", and the way it recurs is an entry leaving the peer set down a
//! branch that says nothing. Nothing here shrinks the peer set quietly.
//!
//! Which is why the subkey pass is written out rather than taken from
//! `windows-registry`'s `Key::keys()`. That iterator ends on ANY non-zero
//! `RegEnumKeyExW` status as if it were a normal end-of-list — the
//! `debug_assert_eq!` guarding the assumption is compiled out of the builds
//! Hole ships — and it bounds the pass by the `cSubKeys` it sampled before
//! starting, so a profile created mid-pass is never read. Both shorten the
//! peer set and return `Ok`.

use std::path::PathBuf;

#[cfg(target_os = "windows")]
const PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

/// The `RegEnumKeyExW` statuses this module acts on.
///
/// Spelled as numbers rather than taken from `windows::Win32::Foundation` so
/// the classification — which is the policy — compiles, and is provable, on a
/// host with no Win32. The Windows leg asserts them against the crate's own
/// constants (`the_enum_status_constants_are_the_win32_ones`).
const ERROR_SUCCESS: u32 = 0;
const ERROR_MORE_DATA: u32 = 234;
const ERROR_NO_MORE_ITEMS: u32 = 259;

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

// Subkey enumeration --------------------------------------------------------------------------------------------------

/// What one `RegEnumKeyExW` call answered, keyed on the CAUSE it reported.
///
/// Three statuses mean three different things and the fourth arm means the
/// call said nothing at all; `windows-registry`'s `KeyIterator` folds all four
/// into "the iterator ended", behind a `debug_assert_eq!` that ships compiled
/// out. That fold is why this module does not use it.
#[derive(Debug, PartialEq, Eq)]
enum EnumAnswer {
    /// A subkey name (`ERROR_SUCCESS`).
    Name(String),
    /// The name did not fit the buffer (`ERROR_MORE_DATA`). `RegEnumKeyExW`
    /// leaves the required size undefined on this status, so the only way
    /// forward is a bigger buffer against the SAME index.
    TooLong,
    /// The key holds no subkey at this index (`ERROR_NO_MORE_ITEMS`).
    End,
    /// Any other status. Nothing is known about this index, or any after it.
    Failed(String),
}

/// Classify one `RegEnumKeyExW` status.
///
/// `name` and `error` are lazy so neither is materialised down a branch with
/// no use for it — on the hot arm the name is a UTF-16 decode, and on every
/// other arm there is no name to decode.
fn enum_answer(status: u32, name: impl FnOnce() -> String, error: impl FnOnce() -> String) -> EnumAnswer {
    match status {
        ERROR_SUCCESS => EnumAnswer::Name(name()),
        ERROR_MORE_DATA => EnumAnswer::TooLong,
        ERROR_NO_MORE_ITEMS => EnumAnswer::End,
        _ => EnumAnswer::Failed(error()),
    }
}

/// How a pass over a key's subkeys ended, and therefore what its name list is
/// worth.
///
/// One variant per cause, and [`EnumEnd::disclose`] is the single exhaustive
/// match that chooses warn-vs-silent — the same shape as
/// [`ProfileEntry::into_dir`], for the same reason.
#[derive(Debug, PartialEq, Eq)]
enum EnumEnd {
    /// End-of-list, having yielded at least as many names as the key held when
    /// the pass began. Nothing was lost.
    Exhausted,
    /// A status that was neither a name nor end-of-list. Every index from here
    /// up is unread.
    Stopped { index: u32, error: String },
    /// End-of-list, but short. `RegEnumKeyExW` addresses subkeys by index, so a
    /// subkey deleted mid-pass shifts its successors down and carries one of
    /// them past the reader; the count taken before the pass is what notices.
    /// An addition cannot lose an entry — the pass runs to end-of-list, never
    /// to a sampled count — so a lone deletion is what lands here.
    ///
    /// Disclosed residual: a deletion AND an addition in the same pass net the
    /// count back to where it started, so a skip they produce together reads
    /// as [`EnumEnd::Exhausted`]. Closing that needs `RegNotifyChangeKeyValue`
    /// over the pass — a change token rather than a count — and an unbounded
    /// re-read when it signals. Not done here: it is two concurrent
    /// `ProfileList` mutations inside one pass of an uninstall.
    Shrank { yielded: usize, at_start: u32 },
}

impl EnumEnd {
    /// Say what the pass lost, and the only place that answer is chosen.
    ///
    /// `warn!`, not `debug!`, for the reason [`ProfileEntry::into_dir`] gives:
    /// the bridge's default filter is a global `info`, and this runs inside
    /// the uninstall the peer probe gates.
    fn disclose(self) {
        match self {
            EnumEnd::Exhausted => {}
            EnumEnd::Stopped { index, error } => tracing::warn!(
                index,
                error = %error,
                "the profile list could not be read past this entry; a bridge running under any \
                 account beyond it would not be seen by the liveness probe"
            ),
            EnumEnd::Shrank { yielded, at_start } => tracing::warn!(
                yielded,
                at_start,
                "the profile list shrank while it was being read; a bridge running under an \
                 account the pass skipped would not be seen by the liveness probe"
            ),
        }
    }
}

/// Every subkey name a key holds, read by index from an injected reader.
///
/// `read(index, capacity)` is one `RegEnumKeyExW` call against a buffer of
/// `capacity` UTF-16 units. Injected so the loop's policy is provable off
/// Windows: grow on a name that does not fit, stop on a status that answers
/// nothing, and never bound the pass by a sampled count.
///
/// `at_start` is the subkey count `RegQueryInfoKeyW` reported before the pass.
/// It is a shortfall detector, never a bound — bounding the pass by it is how
/// the shipped iterator loses a subkey the Profile Service adds mid-pass.
///
/// A pass that lost something warns and returns what it did read, rather than
/// erroring: the caller turns an `Err` into an EMPTY peer set, and a short
/// list still sees more live bridges than no list at all.
fn enumerate_subkeys(at_start: u32, capacity: usize, mut read: impl FnMut(u32, usize) -> EnumAnswer) -> Vec<String> {
    let mut names = Vec::new();
    let mut capacity = capacity.max(1);
    let mut index = 0u32;
    let end = loop {
        match read(index, capacity) {
            EnumAnswer::Name(name) => {
                names.push(name);
                index += 1;
            }
            // No retry budget: the only way round again is a name longer than
            // the buffer, and every turn doubles it.
            EnumAnswer::TooLong => capacity *= 2,
            EnumAnswer::End if names.len() < at_start as usize => {
                break EnumEnd::Shrank {
                    yielded: names.len(),
                    at_start,
                };
            }
            EnumAnswer::End => break EnumEnd::Exhausted,
            EnumAnswer::Failed(error) => break EnumEnd::Stopped { index, error },
        }
    };
    end.disclose();
    names
}

/// `(subkey count, longest subkey name in UTF-16 units)` as of this call.
#[cfg(target_os = "windows")]
fn subkey_info(key: &windows_registry::Key) -> std::io::Result<(u32, u32)> {
    use windows::Win32::System::Registry::{RegQueryInfoKeyW, HKEY};

    let mut count = 0u32;
    let mut max_len = 0u32;
    // SAFETY: `key` owns a live `HKEY` for the whole call; the two out-params
    // are uniquely borrowed for it, and every other pointer is absent.
    let status = unsafe {
        RegQueryInfoKeyW(
            HKEY(key.as_raw()),
            None,
            None,
            None,
            Some(&mut count),
            Some(&mut max_len),
            None,
            None,
            None,
            None,
            None,
            None,
        )
    };
    if status.0 != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status.0 as i32));
    }
    Ok((count, max_len))
}

/// One `RegEnumKeyExW` call, classified.
#[cfg(target_os = "windows")]
fn read_subkey_name(key: &windows_registry::Key, index: u32, capacity: usize) -> EnumAnswer {
    use windows::core::PWSTR;
    use windows::Win32::System::Registry::{RegEnumKeyExW, HKEY};

    let mut buf: Vec<u16> = vec![0; capacity];
    // `lpcchName` counts the terminating NUL in, and receives the name length
    // without it.
    let mut len = u32::try_from(capacity).unwrap_or(u32::MAX);
    // SAFETY: `key` owns a live `HKEY` for the whole call, and `buf` is a
    // uniquely borrowed allocation whose length in UTF-16 units is what `len`
    // passes. The remaining out-params are absent.
    let status = unsafe {
        RegEnumKeyExW(
            HKEY(key.as_raw()),
            index,
            Some(PWSTR(buf.as_mut_ptr())),
            &mut len,
            None,
            None,
            None,
            None,
        )
    }
    .0;
    enum_answer(
        status,
        || String::from_utf16_lossy(&buf[..len as usize]),
        || std::io::Error::from_raw_os_error(status as i32).to_string(),
    )
}

/// Every local profile directory `ProfileList` records, in enumeration order.
///
/// Includes the service profiles (SYSTEM, LocalService, NetworkService) — they
/// are real profiles a `--service` bridge could be using, and the caller
/// already skips a path it has probed.
///
/// An individual entry that cannot be resolved warns and is skipped rather
/// than propagated: one unreadable profile must not blind the probe to the
/// rest. A pass that ends early or comes back short warns the same way and
/// keeps what it read. Only a failure to open or size `ProfileList` itself is
/// propagated — that is the case where the probe knows nothing at all, and the
/// caller has to say so out loud instead of reporting an empty peer set that
/// reads like "no other bridges".
#[cfg(target_os = "windows")]
pub fn profile_dirs() -> std::io::Result<Vec<PathBuf>> {
    let list = windows_registry::LOCAL_MACHINE
        .open(PROFILE_LIST)
        .map_err(|e| std::io::Error::other(format!("could not open HKLM\\{PROFILE_LIST}: {e}")))?;

    let (at_start, max_len) =
        subkey_info(&list).map_err(|e| std::io::Error::other(format!("could not size HKLM\\{PROFILE_LIST}: {e}")))?;

    let sids = enumerate_subkeys(at_start, max_len as usize + 1, |index, capacity| {
        read_subkey_name(&list, index, capacity)
    });

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
