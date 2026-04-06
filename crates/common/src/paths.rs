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
/// Used to persist the bridge's route-recovery state file
/// (`bridge-routes.json`) between runs. Resolved against the current
/// effective user's profile — under `sudo` on macOS this is
/// `/var/root/Library/Application Support/hole/state`, so dev tooling
/// must pass an explicit `--state-dir` to place it somewhere the
/// invoking user can observe.
pub fn default_state_dir() -> PathBuf {
    default_user_subdir("state")
}
