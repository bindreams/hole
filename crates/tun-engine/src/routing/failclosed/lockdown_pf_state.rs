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

use util::ownership::{Ownership, RealOwnership};

use super::pf_claim::{self, Cleared, Held};
use super::release_epoch::ReleaseWatch;
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
    /// Set by a release that has claimed this record and not yet cleared it: a
    /// tombstone. Absent from every ordinary record, so those serialize as
    /// before and a rolled-back binary, which denies unknown fields, reads a
    /// tombstone as `Unusable` with its token salvaged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub releasing: bool,
}

fn default_true() -> bool {
    true
}

/// Orders this record's engage compare-and-set against a release's clear. A [`RecordLock`] leaf.
static LOCK: RecordLock = RecordLock::new(());

impl PfRecord for LockdownPfState {
    fn pf_token(&self) -> &str {
        &self.pf_token
    }

    fn releasing(&self) -> bool {
        self.releasing
    }

    fn with_releasing(&self, releasing: bool) -> Self {
        Self {
            releasing,
            ..self.clone()
        }
    }
}

fn state_file(state_dir: &Path) -> PathBuf {
    state_dir.join(STATE_FILE_NAME)
}

fn save(state_dir: &Path, state: &LockdownPfState, owner: Option<(u32, u32)>) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    util::ownership::chown_if_some(state_dir, owner);
    write_record(state_dir, state)?;
    util::ownership::chown_if_some(&state_file(state_dir), owner);
    Ok(())
}

/// Replace the record file atomically, leaving its owner to the caller.
fn write_record(state_dir: &Path, state: &LockdownPfState) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(state).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut tmp = tempfile::NamedTempFile::new_in(state_dir)?;
    tmp.write_all(&json)?;
    #[cfg(not(test))]
    tmp.as_file().sync_all()?;
    tmp.persist(state_file(state_dir)).map_err(|e| e.error)?;
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
/// when it started) and no release has begun since `watch` opened, as one
/// critical section. [`Swap::Superseded`] writes nothing: a release cleared,
/// replaced or claimed the record since, or is about to, and a record the
/// release is settling is never written over (it would orphan the release's
/// token), however much it reads like `expected`.
///
/// `expected` is the [`StateFile`] as [`load_presence`] returned it, not a
/// collapsed `Option`: an `Unusable` record compares by its salvaged token, so
/// an engage that found one overwrites exactly that file and no other.
pub fn swap(
    state_dir: &Path,
    expected: &StateFile<LockdownPfState>,
    new: &LockdownPfState,
    owner: Option<(u32, u32)>,
    watch: &ReleaseWatch,
) -> std::io::Result<Swap> {
    swap_with(state_dir, expected, new, owner, watch, || {})
}

/// [`swap`] with a hook that runs inside the critical section, between the
/// compare and the write: the one place a test can observe the lock held.
fn swap_with(
    state_dir: &Path,
    expected: &StateFile<LockdownPfState>,
    new: &LockdownPfState,
    owner: Option<(u32, u32)>,
    watch: &ReleaseWatch,
    in_section: impl FnOnce(),
) -> std::io::Result<Swap> {
    let _guard = LOCK.acquire();
    let current = load_presence(state_dir);
    in_section();
    // Under the lock, so a release's claim, which takes it, either follows this
    // write or finds the epoch moved here.
    if watch.check().is_err() || current != *expected {
        return Ok(Swap::Superseded);
    }
    save(state_dir, new, owner)?;
    Ok(Swap::Applied)
}

/// Delete the record iff it names `token` (`None`: iff it is an unusable file that
/// yielded none), and say whether it did. For a caller that has dropped the token it
/// settled the cover under: no record may go on naming it, tombstone or not.
pub fn clear_if_token(state_dir: &Path, token: Option<&str>) -> std::io::Result<bool> {
    let _guard = LOCK.acquire();
    if !pf_claim::names(&load_presence(state_dir), token) {
        return Ok(false);
    }
    remove_file(state_dir)?;
    Ok(true)
}

/// Claim the record for a release: rewrite a live one as its tombstone, under the
/// lock and before any pf call. Returns the record as it now stands, so
/// `Present(r)` with `r.releasing` is a claim on disk. A record that cannot be
/// claimed (absent, already a tombstone, unusable) is returned as read, and so
/// is one whose write failed: the release goes on unclaimed, because the restore
/// matters more than the bookkeeping.
pub fn claim_for_release(state_dir: &Path, owner: Option<(u32, u32)>) -> StateFile<LockdownPfState> {
    claim_with(state_dir, owner, &RealOwnership, write_record)
}

/// [`claim_for_release`] over an injected [`Ownership`] and write.
///
/// The tombstone replaces a file this process did not necessarily create, so it
/// keeps that file's owner (read before the replace) unless a caller asked for
/// one. The state directory is never touched: a rewrite of a record is not a
/// reason to hand its directory to whoever owns the record.
fn claim_with(
    state_dir: &Path,
    owner: Option<(u32, u32)>,
    ownership: &impl Ownership,
    write: impl FnOnce(&Path, &LockdownPfState) -> std::io::Result<()>,
) -> StateFile<LockdownPfState> {
    let _guard = LOCK.acquire();
    let current = load_presence(state_dir);
    let Some(claimed) = pf_claim::tombstone(&current) else {
        return current;
    };
    let file = state_file(state_dir);
    let file_owner = owner.or_else(|| ownership.owner_of(&file));
    match write(state_dir, &claimed) {
        Ok(()) => {
            ownership.chown(&file, file_owner);
            StateFile::Present(claimed)
        }
        Err(e) => {
            tracing::warn!(
                error = %util::error_chain::error_chain(&e),
                "lockdown-pf-state could not be claimed for release; releasing it unclaimed"
            );
            current
        }
    }
}

/// A release's final clear: remove the record only if it is the tombstone the
/// release claimed (or an unusable file naming `token`), and say what it found
/// ([`Cleared`]).
pub fn clear_released(state_dir: &Path, token: Option<&str>) -> std::io::Result<Cleared> {
    let _guard = LOCK.acquire();
    let cleared = pf_claim::release_clear(&load_presence(state_dir), token);
    if cleared == Cleared::Removed {
        remove_file(state_dir)?;
    }
    Ok(cleared)
}

/// Put `record` back after an engage's restore failed, but only over nothing or
/// over its own tombstone (see [`pf_claim::reasserts`]). Whether it did.
pub fn reassert(state_dir: &Path, record: &LockdownPfState, owner: Option<(u32, u32)>) -> std::io::Result<bool> {
    let _guard = LOCK.acquire();
    if !pf_claim::reasserts(&load_presence(state_dir), &record.pf_token) {
        return Ok(false);
    }
    save(state_dir, record, owner)?;
    Ok(true)
}

/// What the engage's commit check found: whether the record is still the live
/// one naming `token` ([`Held`]).
pub fn holds(state_dir: &Path, token: &str) -> Held {
    Held::of(&load_presence(state_dir), token)
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
