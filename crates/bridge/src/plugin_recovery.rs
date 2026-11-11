// The plugin reap.
//
// Reads `bridge-plugins.json` (written by `plugin_state`) and kills every
// process it records, by exact cosca identity — `(pid, raw kernel start
// token)` compared exactly, so a recycled pid is never mistaken for the
// recorded process.
//
// One function, three callers: bridge startup (`boot::recover_then_reconcile`),
// session teardown (`Session::teardown`), and the test harness's
// teardown.
//
// The invariant this exists to hold: a record may be removed only by the
// component that accounted for it, and the file goes when none remain. Removing
// a record after a failed load would forget a plugin that is still running, and
// it holds a server connection and a local port forever. A record appended
// while the reap ran is not one it accounted for, so it stays.
//
// Best-effort — errors are logged, nothing unwinds. `Drop` in the test harness
// calls this, and a panic there while a test is already unwinding would abort
// the whole test binary.

use crate::plugin_state::{self, PluginState};
use cosca::identity::{ProcessId, Resolved};
use std::path::Path;
use util::versioned_file::Loaded;

/// Kill every plugin process recorded under `state_dir`, then remove the records
/// that were accounted for.
pub fn reap_recorded_plugins(state_dir: &Path) {
    reap_loaded(plugin_state::load(state_dir), state_dir);
}

/// [`reap_recorded_plugins`] on a blocking thread, so an async caller does not hold a runtime worker. A panic in the
/// reap is logged, not propagated; a blocking task the runtime cancelled never ran, so the reap runs here instead.
pub async fn reap_recorded_plugins_blocking(state_dir: &Path) {
    let owned = state_dir.to_path_buf();
    let joined = tokio::task::spawn_blocking(move || reap_recorded_plugins(&owned)).await;
    settle_blocking_reap(joined, state_dir);
}

/// What follows the join of the blocking reap: a panic is logged as one, and a cancelled task, which never ran, is
/// replaced by an inline reap, because the reap must happen.
fn settle_blocking_reap(joined: Result<(), tokio::task::JoinError>, state_dir: &Path) {
    let Err(e) = joined else { return };
    if e.is_panic() {
        tracing::warn!(
            error = &e as &dyn std::error::Error,
            "reap_recorded_plugins task panicked"
        );
        return;
    }
    tracing::warn!(
        error = &e as &dyn std::error::Error,
        "reap_recorded_plugins task was cancelled before it ran; reaping inline"
    );
    reap_recorded_plugins(state_dir);
}

/// The reap's dispositions, over an already-loaded state. Taking `Loaded` by
/// value makes every arm drivable from a test without a fixture that has to
/// defeat a real `fs::read`.
pub(crate) fn reap_loaded(loaded: Loaded<PluginState>, state_dir: &Path) {
    reap_loaded_with(
        loaded,
        state_dir,
        |record| ProcessId::try_from(record),
        |id| cosca::Process::from_id(id).kill(),
    );
}

/// [`reap_loaded`] with the per-record restore and kill injected. Both fail only
/// on states this host cannot be made to produce — a restore refused by the
/// host's own unreadable boot session, a kill on a target cosca could not open
/// or assess — so the accounting rule's failure legs need these seams.
pub(crate) fn reap_loaded_with(
    loaded: Loaded<PluginState>,
    state_dir: &Path,
    restore: impl Fn(&cosca::identity::ProcessIdRecord) -> Result<ProcessId, cosca::error::Error>,
    kill: impl Fn(ProcessId) -> Result<(), cosca::error::Error>,
) {
    let state = match loaded {
        Loaded::Absent => return,
        Loaded::Unreadable { error, .. } => {
            tracing::error!(
                error = &error as &dyn std::error::Error,
                file = plugin_state::STATE_FILE_NAME,
                "plugin state file could not be read; keeping it so the next start retries"
            );
            return;
        }
        // A newer or a corrupt record may name live plugins nobody here can interpret: forgetting it would leak them
        // untraceably.
        Loaded::Newer { .. } => {
            tracing::error!(
                file = plugin_state::STATE_FILE_NAME,
                "plugin state file is from a newer release; keeping it, its plugins cannot be accounted for"
            );
            return;
        }
        Loaded::Corrupt { .. } => {
            tracing::error!(
                file = plugin_state::STATE_FILE_NAME,
                "plugin state file is corrupt; keeping it, its plugins cannot be accounted for"
            );
            return;
        }
        Loaded::Obsolete { .. } => {
            tracing::error!(
                file = plugin_state::STATE_FILE_NAME,
                "plugin state file is at an obsolete schema; discarding it and accepting a one-time orphan leak"
            );
            clear_obsolete_or_log(state_dir);
            return;
        }
        Loaded::Current { value, .. } => value,
    };

    // Kills run outside the record's lock. A record is accounted for once it is
    // killed, provably gone, or provably unrestorable on this host.
    let mut accounted = Vec::new();
    let mut all_accounted = true;
    for record in &state.plugins {
        let id = match restore(record) {
            Err(e) if settles_the_record(&e) => {
                // Accounted: a foreign-platform / foreign-boot-session record can
                // never name a killable process on this host, so keeping the file
                // for it would litter forever.
                tracing::error!(
                    pid = record.pid,
                    error = &e as &dyn std::error::Error,
                    "recorded plugin identity cannot be restored on this host; nothing here can name it"
                );
                accounted.push(record.clone());
                continue;
            }
            Err(e) => {
                // Unaccounted: the refusal is about THIS HOST, not the record, so
                // the record may still name a live plugin holding a server
                // connection and a local port.
                all_accounted = false;
                tracing::warn!(
                    pid = record.pid,
                    error = &e as &dyn std::error::Error,
                    "recorded plugin identity could not be checked on this host; keeping the file so the next start retries"
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
            Ok(()) => {
                tracing::info!(
                    pid = record.pid,
                    token = record.token,
                    observation,
                    "reaped recorded plugin"
                );
                accounted.push(record.clone());
            }
            // Unaccounted: cosca fails a kill only for a target it could not
            // open or assess, i.e. exactly when it may still be running.
            Err(e) => {
                all_accounted = false;
                tracing::warn!(
                    pid = record.pid,
                    token = record.token,
                    observation,
                    error = &e as &dyn std::error::Error,
                    "failed to kill recorded plugin"
                );
            }
        }
    }

    // A file it cannot read is named by `remove_accounted` itself.
    match plugin_state::remove_accounted(state_dir, &accounted) {
        Ok(_) => {}
        Err(e) => tracing::warn!(
            error = &e as &dyn std::error::Error,
            "failed to remove reaped records from the plugin state file"
        ),
    }
    if !all_accounted {
        tracing::warn!(
            file = plugin_state::STATE_FILE_NAME,
            "keeping the unaccounted records in the plugin state file for the next start"
        );
    }
}

/// Whether a failed restore SETTLES the record: the refusal is about the
/// record's own contents, so no later start on this host could restore it and
/// keeping the file for it would litter forever.
///
/// `ScopeUnreadable` is the one record error that is not about the contents —
/// this host's boot session momentarily could not be read, raised before the
/// record is validated at all — so an otherwise perfectly restorable record
/// lands here. It, and any error that is not a record error, leave the record
/// unsettled. Both `Error` and `RecordErrorKind` are `#[non_exhaustive]`; a kind
/// cosca adds later reads as unsettled, which keeps the file rather than
/// forgetting a live plugin.
fn settles_the_record(e: &cosca::error::Error) -> bool {
    use cosca::error::RecordErrorKind as K;
    match e {
        cosca::error::Error::IdentityRecord { kind, .. } => matches!(
            kind,
            K::UnknownVersion
                | K::ForeignPlatform
                | K::InvalidPid
                | K::ForeignBootSession
                | K::MissingBootSession
                | K::ForeignPidNamespace
                | K::MissingPidNamespace
        ),
        _ => false,
    }
}

/// A dropped `clear` failure leaves the file in place forever, which is the
/// same litter bug one layer down — so state the disposition at every call.
fn clear_obsolete_or_log(state_dir: &Path) {
    if let Err(e) = plugin_state::clear_obsolete(state_dir) {
        tracing::warn!(
            error = &e as &dyn std::error::Error,
            "failed to clear plugin state file"
        );
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
