// The plugin reap.
//
// Reads `bridge-plugins.json` (written by `plugin_state`) and kills every
// process it records, by exact cosca identity — `(pid, raw kernel start
// token)` compared exactly, so a recycled pid is never mistaken for the
// recorded process.
//
// One function, three callers: bridge startup (after the IPC socket binds,
// same ordering as `routing::recover_routes`), plugin-chain stop
// (`PluginChain::kill_tracked`), and the test harness's teardown.
//
// The invariant this exists to hold: the state file may be deleted only by a
// component that has just accounted for every record it contains. Deleting it
// after a failed load would forget plugins that are still running, and they
// hold a server connection and a local port forever.
//
// Best-effort — errors are logged, nothing unwinds. `Drop` in the test harness
// calls this, and a panic there while a test is already unwinding would abort
// the whole test binary.

use crate::plugin_state::{self, Loaded};
use cosca::identity::{ProcessId, Resolved};
use std::path::Path;

/// Kill every plugin process recorded under `state_dir`, then clear the record.
pub fn reap_recorded_plugins(state_dir: &Path) {
    reap_loaded(plugin_state::load(state_dir), state_dir);
}

/// The reap's dispositions, over an already-loaded state. Taking `Loaded` by
/// value makes every arm drivable from a test without a fixture that has to
/// defeat a real `fs::read`.
pub(crate) fn reap_loaded(loaded: Loaded, state_dir: &Path) {
    reap_loaded_with(loaded, state_dir, |id| cosca::Process::from_id(id).kill());
}

/// [`reap_loaded`] with the per-record kill injected. cosca returns `Err` only
/// for a target it could not open or assess, which a test cannot manufacture
/// for its own child, so the accounting rule's failure leg needs this seam.
pub(crate) fn reap_loaded_with(
    loaded: Loaded,
    state_dir: &Path,
    kill: impl Fn(ProcessId) -> Result<(), cosca::error::Error>,
) {
    let state = match loaded {
        Loaded::Absent => return,
        Loaded::Unreadable(e) => {
            tracing::error!(
                error = %e,
                path = %state_dir.join(plugin_state::STATE_FILE_NAME).display(),
                "plugin state file could not be read; keeping it so the next start retries"
            );
            return;
        }
        Loaded::Unusable => {
            tracing::error!(
                path = %state_dir.join(plugin_state::STATE_FILE_NAME).display(),
                "plugin state file is not usable at this schema; discarding it and accepting a one-time orphan leak"
            );
            clear_or_log(state_dir);
            return;
        }
        Loaded::State(state) => state,
    };

    // The file may be deleted only once every record in it is accounted for:
    // killed, provably gone, or provably unrestorable on this host.
    let mut all_accounted = true;
    for record in &state.plugins {
        let id = match ProcessId::try_from(record) {
            // Accounted: a foreign-platform / foreign-boot-session record can
            // never name a killable process on this host, so keeping the file
            // for it would litter forever.
            Err(e) => {
                tracing::error!(
                    pid = record.pid,
                    error = %e,
                    "recorded plugin identity cannot be restored on this host; nothing here can name it"
                );
                continue;
            }
            Ok(id) => id,
        };

        // Diagnostic only. `Process::kill` answers `Ok` for a killed process,
        // for a recycled pid it deliberately spared, and for one already gone,
        // so the return value alone collapses three outcomes into one. A race
        // between this read and the kill can mislabel a log line and can never
        // misroute a kill — the kill is cosca's own identity-checked call.
        let observation = observe(id);
        match kill(id) {
            Ok(()) => tracing::info!(
                pid = record.pid,
                token = record.token,
                observation,
                "reaped recorded plugin"
            ),
            // Unaccounted: cosca fails a kill only for a target it could not
            // open or assess, i.e. exactly when it may still be running.
            Err(e) => {
                all_accounted = false;
                tracing::warn!(
                    pid = record.pid,
                    token = record.token,
                    observation,
                    error = %e,
                    "failed to kill recorded plugin"
                );
            }
        }
    }

    if all_accounted {
        clear_or_log(state_dir);
    } else {
        tracing::warn!(
            path = %state_dir.join(plugin_state::STATE_FILE_NAME).display(),
            "keeping the plugin state file: a record could not be accounted for"
        );
    }
}

/// A dropped `clear` failure leaves the file in place forever, which is the
/// same litter bug one layer down — so state the disposition at every call.
fn clear_or_log(state_dir: &Path) {
    if let Err(e) = plugin_state::clear(state_dir) {
        tracing::warn!(error = %e, "failed to clear plugin state file");
    }
}

/// What the pid names right now, relative to the record.
fn observe(id: ProcessId) -> &'static str {
    match ProcessId::of(id.pid()) {
        Resolved::Found(live) if live == id => "match",
        Resolved::Found(_) => "recycled",
        Resolved::Gone => "gone",
        Resolved::Unknown => "unassessable",
    }
}

#[cfg(test)]
#[path = "plugin_recovery_tests.rs"]
mod plugin_recovery_tests;
