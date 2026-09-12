// Default paths for per-user log/state directories.

use std::path::PathBuf;

/// Shared helper: `<state_or_data_local_dir>/hole/<leaf>`.
///
/// Falls back to `data_local_dir` when `state_dir` is not available
/// (macOS and Windows don't define a distinct state dir).
pub(crate) fn default_user_subdir(leaf: &str) -> PathBuf {
    dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .expect("no state/data directory found")
        .join("hole")
        .join(leaf)
}

/// Default state directory: `<state>/hole/state`.
///
/// Used to persist the bridge's crash-recovery state files
/// (`bridge-routes.json`, `bridge-dns.json`, `bridge-plugins.json`) between
/// runs. Resolved against the current
/// effective user's profile — under `sudo` on macOS this is
/// `/var/root/Library/Application Support/hole/state`, so dev tooling
/// must pass an explicit `--state-dir` to place it somewhere the
/// invoking user can observe.
pub fn default_state_dir() -> PathBuf {
    default_user_subdir("state")
}

/// State directory for a named user's home, rather than for whoever the
/// process's effective user happens to be.
///
/// An elevated, non-`--service` bridge run resolves its state dir this way,
/// against the real interactive user behind `sudo`. Anything that has to find
/// that bridge's state after the fact — `cutover::peer_state_dirs`, looking for
/// its liveness lock — must resolve it the same way, so the mapping lives here
/// rather than at either call site.
///
/// The layout is macOS's, and so are both callers; the function itself is a
/// pure path join and is compiled everywhere so its unit test does not need a
/// platform of its own.
pub fn user_state_dir(home: &std::path::Path) -> PathBuf {
    home.join("Library/Application Support/hole/state")
}

/// State directory inside a named Windows user profile, rather than the
/// profile of whoever the process's token happens to belong to.
///
/// Windows' elevation does not switch profiles the way `sudo` does, so a
/// foreground or elevated non-`--service` bridge resolves
/// [`default_state_dir`] against the interactive user's own
/// `%LOCALAPPDATA%`. `cutover::peer_state_dirs`, which runs as SYSTEM under
/// the MSI and must find *that* bridge's liveness lock, cannot get there
/// through `dirs` — SYSTEM has a profile of its own — so it enumerates the
/// host's profiles and maps each one through here.
///
/// `%LOCALAPPDATA%` is `<profile>\AppData\Local`: `FOLDERID_LocalAppData` is
/// not a redirectable known folder (unlike its roaming sibling), which is what
/// makes this join equal to what `dirs::data_local_dir` returns for the user
/// who owns `profile`. Pinned against the real resolver by
/// `the_windows_peer_mapping_matches_what_a_bridge_resolves`.
///
/// A pure path join, compiled everywhere so its unit test needs no platform of
/// its own — the same arrangement as [`user_state_dir`] above.
pub fn windows_profile_state_dir(profile: &std::path::Path) -> PathBuf {
    profile.join("AppData").join("Local").join("hole").join("state")
}
