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
    let state = match loaded {
        Loaded::Absent => return,
        Loaded::Unusable => return,
        Loaded::State(state) => state,
    };

    for record in &state.plugins {
        let id = match ProcessId::try_from(record) {
            Ok(id) => id,
            Err(e) => {
                tracing::error!(
                    pid = record.pid,
                    error = %e,
                    "recorded plugin identity cannot be restored on this host; nothing here can name it"
                );
                continue;
            }
        };

        // Diagnostic only. `Process::kill` answers `Ok` for a killed process,
        // for a recycled pid it deliberately spared, and for one already gone,
        // so the return value alone collapses three outcomes into one. A race
        // between this read and the kill can mislabel a log line and can never
        // misroute a kill — the kill is cosca's own identity-checked call.
        let observation = observe(id);
        match cosca::Process::from_id(id).kill() {
            Ok(()) => tracing::info!(
                pid = record.pid,
                token = record.token,
                observation,
                "reaped recorded plugin"
            ),
            Err(e) => tracing::warn!(
                pid = record.pid,
                token = record.token,
                observation,
                error = %e,
                "failed to kill recorded plugin"
            ),
        }
    }

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
