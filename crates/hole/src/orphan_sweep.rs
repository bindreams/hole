// Best-effort sweep of `hole-install-*` / `hole-update-*` temp directories
// left over from failed installs.
//
// `crate::setup::run_elevated` allocates a per-invocation `TempDir` and,
// when the elevation fails, detaches it from auto-cleanup so the user can
// attach the contained `gui-cli.log` to a support email. `hole-update-*`
// dirs are MSI downloads persisted past process exit for the detached
// installer (#468); the install helper deletes them on success, and this
// sweep collects failed and cancelled installs. macOS's `/tmp` is cleaned
// on reboot, but Windows `%TEMP%` is not — without an explicit sweep,
// repeated failures leak forever.
//
// This module enumerates `std::env::temp_dir()` at GUI startup, looks for
// entries matching [`PREFIXES`], and deletes any whose mtime is older
// than [`MAX_AGE`]. Bounded to [`MAX_DELETE_PER_SWEEP`] entries per call
// so a misbehaving filesystem can't stall startup.

use std::path::Path;
use std::time::{Duration, SystemTime};

const PREFIXES: [&str; 2] = ["hole-install-", "hole-update-"];
const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60); // 7 days
const MAX_DELETE_PER_SWEEP: usize = 100;

/// Spawn the default sweep against `std::env::temp_dir()` on a background
/// std thread. Non-blocking; failures are logged at `warn`.
pub(crate) fn spawn_default() {
    std::thread::Builder::new()
        .name("hole-orphan-sweep".into())
        .spawn(|| {
            sweep(&std::env::temp_dir(), MAX_AGE, MAX_DELETE_PER_SWEEP);
        })
        .map(|_| ())
        .unwrap_or_else(|e| {
            tracing::warn!("could not spawn orphan-sweep thread: {e}");
        });
}

/// Walk `dir` and delete child entries that:
///   1. have a file name beginning with one of [`PREFIXES`], AND
///   2. have an mtime older than `max_age` ago.
///
/// Deletes at most `max_delete` entries before returning (so a directory
/// with thousands of stale entries doesn't stall startup; the next launch
/// continues the sweep).
///
/// Returns the number of entries actually deleted. Errors are swallowed
/// (this is best-effort), but a `read_dir` failure is logged at `warn`.
pub(crate) fn sweep(dir: &Path, max_age: Duration, max_delete: usize) -> usize {
    let now = SystemTime::now();
    let cutoff = now.checked_sub(max_age).unwrap_or(SystemTime::UNIX_EPOCH);

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("orphan_sweep: read_dir({}) failed: {e}", dir.display());
            return 0;
        }
    };

    let mut deleted = 0usize;
    for entry in entries.flatten() {
        if deleted >= max_delete {
            break;
        }
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else { continue };
        if !PREFIXES.iter().any(|p| name_str.starts_with(p)) {
            continue;
        }
        // symlink_metadata so a symlink whose target is fresh doesn't
        // shield an old link (and so we never follow into the wider FS).
        let meta = match entry.path().symlink_metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let mtime = match meta.modified() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if mtime >= cutoff {
            continue;
        }
        let path = entry.path();
        let result = if meta.file_type().is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        if let Err(e) = result {
            tracing::warn!("orphan_sweep: failed to remove {}: {e}", path.display());
            continue;
        }
        deleted += 1;
    }
    deleted
}

#[cfg(test)]
#[path = "orphan_sweep_tests.rs"]
mod orphan_sweep_tests;
