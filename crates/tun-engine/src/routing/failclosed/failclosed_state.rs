//! Persisted fail-closed-cover state for crash recovery (macOS only).
//!
//! macOS engages the cover by enabling pf with `pfctl -E`, which returns a
//! reference-count token. We persist that token BEFORE loading the blocking
//! ruleset so a crashed update cutover can be cleanly reversed on the next
//! bridge start (`recover_cover`: restore `/etc/pf.conf` + `pfctl -X <token>`).
//! Windows needs no analogue: its WFP filters carry fixed GUIDs and are swept
//! by key, so there is nothing to persist.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use util::ownership::{Ownership, RealOwnership};

use super::pf_claim::{self, Cleared, Held};
use super::{PfRecord, StateFile, Swap};
use crate::exclusive::RecordLock;

/// Schema version for [`FailClosedState`]. Bumped on backwards-incompatible
/// changes; [`load`] discards a mismatched file rather than risk a corrupt
/// recovery.
pub const SCHEMA_VERSION: u32 = 1;

/// Filename under `state_dir`. Distinct from `bridge-routes.json` because the
/// cover lifecycle is independent of the route lifecycle (a cover is active
/// precisely while routes are down, mid-cutover).
pub const STATE_FILE_NAME: &str = "bridge-failclosed.json";

/// pf state captured at cover-engage time, persisted before the blocking
/// ruleset is loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailClosedState {
    pub version: u32,
    /// Opaque enable token returned by `pfctl -E`, replayed to `pfctl -X` on
    /// recovery. Stored as a string — it is an opaque handle, not arithmetic.
    pub pf_token: String,
    /// Whether pf reported `Status: Enabled` before we engaged; `false` also
    /// when that read failed (the engage warns and does not fail on it). Diagnostic
    /// only: recovery restores `/etc/pf.conf` and drops our refcount regardless.
    ///
    /// Stays a plain `bool`, never an `Option`: this file must parse under every
    /// release that may run the sweep after a crash, and a rolled-back binary's
    /// `bool` rejects `null` — `state::load` then reads the file as absent and
    /// leaves `block out all` on the host.
    pub pf_was_enabled: bool,
    /// Set by a release that has claimed this record and not yet cleared it: a
    /// tombstone. Absent from every ordinary record, so those serialize as
    /// before and a rolled-back binary, which denies unknown fields, reads a
    /// tombstone as `Unusable` with its token salvaged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub releasing: bool,
}

/// Orders this record's engage compare-and-set against a release's clear. A [`RecordLock`] leaf.
static LOCK: RecordLock = RecordLock::new(());

impl PfRecord for FailClosedState {
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

/// Atomically persist `state` to `<state_dir>/bridge-failclosed.json` (temp
/// file + same-dir rename, `sync_all` before persist). Creates `state_dir`.
fn save(state_dir: &Path, state: &FailClosedState, owner: Option<(u32, u32)>) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    util::ownership::chown_if_some(state_dir, owner);
    write_record(state_dir, state)?;
    util::ownership::chown_if_some(&state_file(state_dir), owner);
    Ok(())
}

/// Replace the record file atomically, leaving its owner to the caller.
fn write_record(state_dir: &Path, state: &FailClosedState) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(state).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut tmp = tempfile::NamedTempFile::new_in(state_dir)?;
    tmp.write_all(&json)?;
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
pub fn load_presence(state_dir: &Path) -> super::StateFile<FailClosedState> {
    use super::StateFile;
    let path = state_file(state_dir);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return StateFile::Absent,
        Err(e) => {
            tracing::warn!(error = %util::error_chain::error_chain(&e), path = %path.display(), "failclosed-state read failed");
            // No bytes, so nothing to salvage a token from.
            return StateFile::Unusable { pf_token: None };
        }
    };
    match serde_json::from_slice::<FailClosedState>(&bytes) {
        Ok(s) if s.version == SCHEMA_VERSION => StateFile::Present(s),
        Ok(other) => {
            tracing::warn!(
                got = other.version,
                want = SCHEMA_VERSION,
                "failclosed-state schema mismatch, discarding the record but salvaging its pf token"
            );
            StateFile::unusable(&bytes)
        }
        Err(e) => {
            tracing::warn!(error = %util::error_chain::error_chain(&e), path = %path.display(), "failclosed-state parse failed");
            StateFile::unusable(&bytes)
        }
    }
}

/// Load the state file, or `None` on any error (absent / corrupt / unknown
/// field / version mismatch); logs at `warn`. Recovery is best-effort. Thin
/// wrapper over [`load_presence`], collapsing `Unusable` into `None` alongside
/// `Absent` — every existing caller treats the two identically.
pub fn load(state_dir: &Path) -> Option<FailClosedState> {
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
/// nothing: a release cleared or replaced the record since.
///
/// `expected` is the [`StateFile`] as [`load_presence`] returned it, not a
/// collapsed `Option`: an `Unusable` record compares by its salvaged token, so
/// an engage that found one overwrites exactly that file and no other.
pub fn swap(
    state_dir: &Path,
    expected: &StateFile<FailClosedState>,
    new: &FailClosedState,
    owner: Option<(u32, u32)>,
) -> std::io::Result<Swap> {
    swap_with(state_dir, expected, new, owner, || {})
}

/// [`swap`] with a hook that runs inside the critical section, between the
/// compare and the write: the one place a test can observe the lock held.
fn swap_with(
    state_dir: &Path,
    expected: &StateFile<FailClosedState>,
    new: &FailClosedState,
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

/// Delete the record iff it names `token` (`None`: iff it is an unusable file that
/// yielded none), and say whether it did. For a caller that settled the cover under
/// `token` without a claim: it drops the token only if this removed the record.
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
pub fn claim_for_release(state_dir: &Path, owner: Option<(u32, u32)>) -> StateFile<FailClosedState> {
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
    write: impl FnOnce(&Path, &FailClosedState) -> std::io::Result<()>,
) -> StateFile<FailClosedState> {
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
                "failclosed-state could not be claimed for release; releasing it unclaimed"
            );
            current
        }
    }
}

/// A release's final clear: remove the record only if it is the tombstone the
/// release claimed (or an unusable file naming `token`), and say what it found
/// ([`Cleared`]). The token is the release's to drop only on `Removed`.
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
pub fn reassert(state_dir: &Path, record: &FailClosedState, owner: Option<(u32, u32)>) -> std::io::Result<bool> {
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
pub(crate) fn seed(state_dir: &Path, state: &FailClosedState) {
    let _guard = LOCK.acquire();
    save(state_dir, state, None).expect("seed the record");
}

#[cfg(test)]
#[path = "failclosed_state_tests.rs"]
mod failclosed_state_tests;
