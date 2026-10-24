//! Persisted plugin process identities for crash recovery.
//!
//! The bridge writes each plugin child's `ProcessIdRecord` to a JSON file when
//! a plugin chain starts and reads it back on startup to reap processes leaked
//! by a previous crashed run. Mirrors the `routing::state` crash-recovery
//! pattern. `plugin_recovery` owns the reap and is the only component allowed
//! to remove records from the file.
//!
//! Every read-modify-write of the file, and every [`load`], runs under [`LOCK`],
//! an in-process leaf lock. Appends come from plugin spawns on tokio workers (a sink from an
//! aborted attempt can outlive the attempt), the reap from the stop path; an
//! unordered load/modify/save would lose a record or resurrect a reaped one.
//!
//! A record pairs the pid with the kernel's own start token, so a recycled pid
//! never restores to the recorded process — see `cosca::identity`.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use tun_engine::exclusive::RecordLock;

// Types ===============================================================================================================

pub const SCHEMA_VERSION: u32 = 2;

/// Filename of the persisted state file under `state_dir`. Exported so
/// external tooling can reference the single source of truth.
pub const STATE_FILE_NAME: &str = "bridge-plugins.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginState {
    pub version: u32,
    pub plugins: Vec<cosca::identity::ProcessIdRecord>,
}

/// What [`load`] found. Deliberately no `PartialEq`: a variant carrying an
/// `io::Error` joins this set, so callers and tests match with `matches!`.
#[derive(Debug)]
pub enum Loaded {
    /// No state file — nothing was ever recorded, or a reap already cleared it.
    Absent,
    /// Present, but the read itself failed: a sharing violation, an EACCES, a
    /// short read. The records may be perfectly valid and name live processes,
    /// so this is not "worthless". The io error travels with the variant
    /// because this is the one arm that deliberately leaves the file behind
    /// for a human, and the remedy depends on why.
    Unreadable(std::io::Error),
    /// Present and read, but provably worthless: an old schema, malformed
    /// JSON, or an unknown field. Nothing in it can name a process.
    Unusable,
    /// Parsed at the current schema version.
    State(PluginState),
}

/// Serializes every read-modify-write of the state file in this process. A leaf
/// lock ([`RecordLock`]): the sections below do file I/O and nothing else, and
/// the reap's kills run outside it.
static LOCK: RecordLock = RecordLock::new(());

/// Whether a critical section is open right now. Tests use it to prove a
/// section holds the lock, or that a slow call does not.
#[cfg(test)]
pub(crate) fn lock_is_held() -> bool {
    LOCK.try_acquire().is_none()
}

fn state_file(state_dir: &Path) -> PathBuf {
    state_dir.join(STATE_FILE_NAME)
}

// Ownership ===========================================================================================================

/// The file ownership a rewrite reads and sets, split out so a test can see
/// what a rewrite asked for on a host where it cannot observe a chown.
trait Ownership {
    fn owner_of(&self, path: &Path) -> Option<(u32, u32)>;
    fn chown(&self, path: &Path, owner: Option<(u32, u32)>);
}

struct RealOwnership;

impl Ownership for RealOwnership {
    fn owner_of(&self, path: &Path) -> Option<(u32, u32)> {
        util::ownership::owner_of(path)
    }

    fn chown(&self, path: &Path, owner: Option<(u32, u32)>) {
        util::ownership::chown_if_some(path, owner);
    }
}

// I/O =================================================================================================================

/// Write `state` to `<state_dir>/bridge-plugins.json` atomically.
/// Same atomic-write pattern as `routing::state::write`. Private: a write
/// outside [`LOCK`] could lose a concurrent append.
fn save(state_dir: &Path, state: &PluginState, owner: Option<(u32, u32)>) -> std::io::Result<()> {
    save_with(state_dir, state, owner, &RealOwnership)
}

/// [`save`] over an injected [`Ownership`]. The replacement file takes `owner`;
/// with none requested it takes the owner of the file it replaces, because a
/// rename-replace otherwise hands a user-owned file to whoever rewrites it.
fn save_with(
    state_dir: &Path,
    state: &PluginState,
    owner: Option<(u32, u32)>,
    ownership: &impl Ownership,
) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    ownership.chown(state_dir, owner);

    let json = serde_json::to_vec_pretty(state).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let path = state_file(state_dir);
    let file_owner = owner.or_else(|| ownership.owner_of(&path));
    let mut tmp = tempfile::NamedTempFile::new_in(state_dir)?;
    tmp.write_all(&json)?;
    tmp.as_file().sync_all()?;
    tmp.persist(&path).map_err(|e| e.error)?;
    ownership.chown(&path, file_owner);
    Ok(())
}

/// Append a single record to the state file. Creates the file if missing.
/// Reads existing records, merges, atomically writes the result, all under
/// [`LOCK`].
pub fn append_record(
    state_dir: &Path,
    record: cosca::identity::ProcessIdRecord,
    owner: Option<(u32, u32)>,
) -> std::io::Result<()> {
    append_record_with(state_dir, record, owner, || {})
}

/// [`append_record`] with a hook that runs inside the critical section,
/// between the load and the save.
fn append_record_with(
    state_dir: &Path,
    record: cosca::identity::ProcessIdRecord,
    owner: Option<(u32, u32)>,
    in_section: impl FnOnce(),
) -> std::io::Result<()> {
    let _guard = LOCK.acquire();
    let loaded = read(state_dir);
    in_section();
    append_loaded(loaded, state_dir, record, owner)
}

/// The append's dispositions, over an already-loaded state (read under
/// [`LOCK`] by the caller). Taking `Loaded` by value makes every arm drivable
/// from a test without a fixture that has to defeat a real `fs::read`.
///
/// Called at plugin spawn, where a file that will not parse is already dead
/// weight, so `Absent` and `Unusable` both start a fresh state. A file that
/// could not be *read* is not dead weight: rewriting it with a single record
/// would drop the previously-tracked plugins permanently, so the read error is
/// returned and nothing is written.
pub(crate) fn append_loaded(
    loaded: Loaded,
    state_dir: &Path,
    record: cosca::identity::ProcessIdRecord,
    owner: Option<(u32, u32)>,
) -> std::io::Result<()> {
    let mut state = match loaded {
        Loaded::State(state) => state,
        Loaded::Unreadable(e) => return Err(e),
        Loaded::Absent | Loaded::Unusable => PluginState {
            version: SCHEMA_VERSION,
            plugins: Vec::new(),
        },
    };
    state.plugins.push(record);
    save(state_dir, &state, owner)
}

/// Load the state file, distinguishing "nothing recorded" from "could not be
/// read" from "recorded but worthless". Logs the schema/JSON detail where it
/// is detected; a failed read is reported to the caller instead, because the
/// caller is the one that knows the consequence.
///
/// Runs under [`LOCK`]: an append's rename-replace can fail a concurrent read
/// on Windows, and a failed read keeps the whole file unreaped.
pub fn load(state_dir: &Path) -> Loaded {
    load_with(state_dir, || {})
}

/// [`load`] with a hook that runs inside the critical section, after the read.
fn load_with(state_dir: &Path, in_section: impl FnOnce()) -> Loaded {
    let _guard = LOCK.acquire();
    let loaded = read(state_dir);
    in_section();
    loaded
}

/// The read itself. Callers already inside [`LOCK`] use this, never [`load`].
fn read(state_dir: &Path) -> Loaded {
    let path = state_file(state_dir);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Loaded::Absent,
        Err(e) => return Loaded::Unreadable(e),
    };
    match serde_json::from_slice::<PluginState>(&bytes) {
        Ok(state) if state.version == SCHEMA_VERSION => Loaded::State(state),
        Ok(other) => {
            tracing::warn!(
                got = other.version,
                want = SCHEMA_VERSION,
                "plugin-state schema mismatch, discarding"
            );
            Loaded::Unusable
        }
        Err(e) => {
            tracing::warn!(error = %util::error_chain::error_chain(&e), path = %path.display(), "plugin-state parse failed");
            Loaded::Unusable
        }
    }
}

/// Remove exactly the `accounted` records, deleting the file when none remain.
///
/// The caller loaded the file earlier and settled those records (killed, gone,
/// or unrestorable here); the file may have grown since, and what grew is not
/// the caller's to touch. A file that is absent or has become unusable holds
/// nothing to remove.
pub(crate) fn remove_accounted(
    state_dir: &Path,
    accounted: &[cosca::identity::ProcessIdRecord],
    owner: Option<(u32, u32)>,
) -> std::io::Result<()> {
    remove_accounted_with(state_dir, accounted, owner, &RealOwnership, || {})
}

/// [`remove_accounted`] with a hook that runs inside the critical section,
/// between the load and the write.
fn remove_accounted_with(
    state_dir: &Path,
    accounted: &[cosca::identity::ProcessIdRecord],
    owner: Option<(u32, u32)>,
    ownership: &impl Ownership,
    in_section: impl FnOnce(),
) -> std::io::Result<()> {
    let _guard = LOCK.acquire();
    let loaded = read(state_dir);
    in_section();
    let mut state = match loaded {
        Loaded::State(state) => state,
        Loaded::Unreadable(e) => return Err(e),
        Loaded::Absent | Loaded::Unusable => return Ok(()),
    };
    let before = state.plugins.len();
    state.plugins.retain(|r| !accounted.contains(r));
    if state.plugins.is_empty() {
        return remove_file(state_dir);
    }
    if state.plugins.len() == before {
        return Ok(());
    }
    save_with(state_dir, &state, owner, ownership)
}

/// Delete the state file iff it is still unusable. The caller classified it
/// earlier; an append may have rewritten it with live records since.
pub(crate) fn clear_if_unusable(state_dir: &Path) -> std::io::Result<()> {
    let _guard = LOCK.acquire();
    match read(state_dir) {
        Loaded::Unusable => remove_file(state_dir),
        Loaded::Absent | Loaded::Unreadable(_) | Loaded::State(_) => Ok(()),
    }
}

/// Delete the state file. Tolerates a missing file. Callers hold [`LOCK`].
fn remove_file(state_dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(state_file(state_dir)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
#[path = "plugin_state_tests.rs"]
mod plugin_state_tests;
