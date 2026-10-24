//! macOS-only persisted state for the STANDING lockdown cover. Distinct file
//! from `bridge-failclosed.json` (the transient cover): the lockdown cover has
//! an independent lifetime, and the cutover engages no transient cover. Records the
//! pf enable token (replayed to `pfctl -X` on Sweep) and the pre-lockdown
//! filter (`pfctl -sr`) and translation (`pfctl -sn`) snapshots (re-loaded on
//! Sweep to restore the host without `-Fa`, matching the engaged-without-flush
//! contract).

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{PfRecord, StateFile, Swap};
use crate::exclusive::RecordLock;

pub const SCHEMA_VERSION: u32 = 1;
pub const STATE_FILE_NAME: &str = "bridge-lockdown-pf.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockdownPfState {
    pub version: u32,
    /// Opaque enable token from `pfctl -E`, replayed to `pfctl -X` on Sweep.
    pub pf_token: String,
    /// The host's filter ruleset (`pfctl -sr`) captured before we replaced the
    /// main ruleset with the lockdown policy. Re-loaded on Sweep so the host
    /// returns to its pre-lockdown policy (NOT a blind `/etc/pf.conf` reload).
    pub main_snapshot: String,
    /// The host's translation rules (`pfctl -sn`: nat/rdr) captured alongside
    /// `main_snapshot`. Carried forward into the lockdown ruleset (so the
    /// session does not flush NAT) and re-loaded on Sweep for restore.
    pub nat_snapshot: String,
    /// `false` when the host's filter ruleset at engage time was our OWN cover,
    /// so there was no pre-lockdown baseline to capture; a restore then reloads
    /// `/etc/pf.conf` instead of `main_snapshot`. Read by `disengage_lockdown`
    /// and by `release_all_with`'s standing `Present` arm.
    ///
    /// A bool, not `main_snapshot.is_empty()`: a host really can have an empty
    /// filter ruleset, and that IS its policy — keying on emptiness would
    /// silently reload `/etc/pf.conf` over it.
    ///
    /// Defaults `true` (NO schema bump) so a file written before this field
    /// existed reads as the captured baseline it was. Bumping
    /// [`SCHEMA_VERSION`] instead would make every existing file `Unusable`,
    /// which [`load`] collapses to `None`, which makes `disengage_lockdown`
    /// early-return `Ok(())` over a still-blocked host — silently breaking
    /// `hole bridge unlock` and the tray's Unblock item on the ordinary macOS
    /// upgrade path. `deny_unknown_fields` rejects EXTRA fields, not missing
    /// ones, so the default applies cleanly.
    #[serde(default = "default_true")]
    pub main_snapshot_captured: bool,
}

fn default_true() -> bool {
    true
}

/// Serializes every read-modify-write of this record in this process, so an
/// engage's compare-and-set and a release's clear cannot interleave. A leaf
/// lock ([`RecordLock`]): only file I/O runs under it, never a `pfctl` call.
static LOCK: RecordLock = RecordLock::new(());

impl PfRecord for LockdownPfState {
    fn pf_token(&self) -> &str {
        &self.pf_token
    }
}

fn state_file(state_dir: &Path) -> PathBuf {
    state_dir.join(STATE_FILE_NAME)
}

fn save(state_dir: &Path, state: &LockdownPfState, owner: Option<(u32, u32)>) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    util::ownership::chown_if_some(state_dir, owner);
    let json = serde_json::to_vec_pretty(state).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let path = state_file(state_dir);
    let mut tmp = tempfile::NamedTempFile::new_in(state_dir)?;
    tmp.write_all(&json)?;
    tmp.as_file().sync_all()?;
    tmp.persist(&path).map_err(|e| e.error)?;
    util::ownership::chown_if_some(&path, owner);
    Ok(())
}

/// Trichotomy read distinguishing "no cover was ever engaged" (`Absent`) from
/// "a cover's evidence exists but we cannot read it" (`Unusable`) — a corrupt,
/// unparseable, or version-skewed file. Collapsing `Unusable` into `Absent`
/// would make a release read a live, blocking cover as nothing to clear (see
/// `release_all`'s doc). `Absent` is ONLY `ErrorKind::NotFound`; every other
/// read/parse/version failure is `Unusable` (keeps the existing `warn!` lines).
pub fn load_presence(state_dir: &Path) -> super::StateFile<LockdownPfState> {
    use super::StateFile;
    let path = state_file(state_dir);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return StateFile::Absent,
        Err(e) => {
            tracing::warn!(error = %util::error_chain::error_chain(&e), path = %path.display(), "lockdown-pf-state read failed");
            // No bytes, so nothing to salvage a token from.
            return StateFile::Unusable { pf_token: None };
        }
    };
    match serde_json::from_slice::<LockdownPfState>(&bytes) {
        Ok(s) if s.version == SCHEMA_VERSION => StateFile::Present(s),
        Ok(other) => {
            tracing::warn!(
                got = other.version,
                want = SCHEMA_VERSION,
                "lockdown-pf-state schema mismatch, discarding the record but salvaging its pf token"
            );
            StateFile::unusable(&bytes)
        }
        Err(e) => {
            // Converted immediately, never held as a `serde_json::Error`:
            // `main_snapshot` is a captured `pfctl -sr` ruleset, which
            // contains the server IP whenever the ruleset it captured was
            // Hole's own cover, and `serde_json::Error`'s `Display` quotes
            // the offending bytes back. Shadowing `e` with the source-free
            // `ParseFailure` here, rather than only calling
            // `describe_parse_error` where it's logged, means there is no
            // live `serde_json::Error` left in scope for a later edit to
            // reach for with `%e`.
            let e = util::parse_error::ParseFailure::from(&e);
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "lockdown-pf-state parse failed"
            );
            StateFile::unusable(&bytes)
        }
    }
}

/// Load the state file, or `None` on any error (absent / corrupt / unknown
/// field / version mismatch). Thin wrapper over [`load_presence`], collapsing
/// `Unusable` into `None` alongside `Absent` — every existing caller treats
/// the two identically.
pub fn load(state_dir: &Path) -> Option<LockdownPfState> {
    match load_presence(state_dir) {
        super::StateFile::Present(s) => Some(s),
        super::StateFile::Absent | super::StateFile::Unusable { .. } => None,
    }
}

/// Unconditional delete, tolerating absence. Callers hold [`LOCK`].
fn remove_file(state_dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(state_file(state_dir)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Persist `new` iff the record still reads as `expected` (what the caller read
/// when it started), as one critical section. [`Swap::Superseded`] writes
/// nothing: a release cleared or replaced the record since, and writing from the
/// caller's older view would resurrect it or stack a second record on a host the
/// release already restored.
///
/// `expected` is the [`StateFile`] as [`load_presence`] returned it, not a
/// collapsed `Option`: an `Unusable` record compares by its salvaged token, so
/// an engage that found one overwrites exactly that file and no other.
pub fn swap(
    state_dir: &Path,
    expected: &StateFile<LockdownPfState>,
    new: &LockdownPfState,
    owner: Option<(u32, u32)>,
) -> std::io::Result<Swap> {
    swap_with(state_dir, expected, new, owner, || {})
}

/// [`swap`] with a hook that runs inside the critical section, between the
/// compare and the write: the one place a test can observe the lock held.
fn swap_with(
    state_dir: &Path,
    expected: &StateFile<LockdownPfState>,
    new: &LockdownPfState,
    owner: Option<(u32, u32)>,
    in_section: impl FnOnce(),
) -> std::io::Result<Swap> {
    let _guard = LOCK.acquire();
    let current = load_presence(state_dir);
    in_section();
    if current != *expected {
        return Ok(Swap::Superseded);
    }
    save(state_dir, new, owner)?;
    Ok(Swap::Applied)
}

/// Delete the record iff it still names `token` (`None`: iff it is a record that
/// names none), tolerating absence. For a caller that settled the cover under
/// `token` and must not take down a record a later engage wrote under another.
pub fn clear_if_token(state_dir: &Path, token: Option<&str>) -> std::io::Result<()> {
    let _guard = LOCK.acquire();
    let current = load_presence(state_dir);
    if current == StateFile::Absent || current.pf_token() != token {
        return Ok(());
    }
    remove_file(state_dir)
}

/// Delete the record iff it still names `token`, and say whether it did. For an
/// engage backing out: it drops the pf refcount only when this returned `true`,
/// because a record that is gone or is another engage's had its token dropped (or
/// never held it) by whoever removed or wrote it. The compare and the delete are
/// one critical section, so a release cannot land between them.
pub fn clear_if_holds(state_dir: &Path, token: &str) -> std::io::Result<bool> {
    let _guard = LOCK.acquire();
    if load_presence(state_dir).pf_token() != Some(token) {
        return Ok(false);
    }
    remove_file(state_dir)?;
    Ok(true)
}

/// Whether the record is a readable one naming `token`: the check an engage
/// makes after its ruleset loads, to learn that no release removed or replaced
/// the record it wrote (or reused) while it ran.
pub fn holds(state_dir: &Path, token: &str) -> bool {
    matches!(load_presence(state_dir), StateFile::Present(r) if r.pf_token == token)
}

/// Test-only unconditional write, for fixtures that need a record the engage
/// paths would never produce (a deliberately broken one). Production writers
/// go through [`swap`].
#[cfg(test)]
pub(crate) fn seed(state_dir: &Path, state: &LockdownPfState) {
    let _guard = LOCK.acquire();
    save(state_dir, state, None).expect("seed the record");
}

#[cfg(test)]
#[path = "lockdown_pf_state_tests.rs"]
mod lockdown_pf_state_tests;
