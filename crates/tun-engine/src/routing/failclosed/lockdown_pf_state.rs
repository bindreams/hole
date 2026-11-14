//! macOS-only persisted state for the STANDING lockdown cover. Distinct file
//! from `bridge-failclosed.json` (the transient cover): the lockdown cover has
//! an independent lifetime, and the cutover engages no transient cover. Records the
//! pf enable token (replayed to `pfctl -X` on Sweep) and the pre-lockdown
//! filter (`pfctl -sr`) and translation (`pfctl -sn`) snapshots (re-loaded on
//! Sweep to restore the host without `-Fa`, matching the engaged-without-flush
//! contract).

use serde::{Deserialize, Serialize};
use util::versioned_file::{Obsolete, Role, Schema, VersionedState};

pub const STATE_FILE_NAME: &str = "bridge-lockdown-pf.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockdownPfState {
    /// Opaque enable token from `pfctl -E`, replayed to `pfctl -X` on Sweep.
    pub pf_token: String,
    /// The host's filter ruleset (`pfctl -sr`) captured before we replaced the
    /// main ruleset with the lockdown policy. Re-loaded on Sweep so the host
    /// returns to its pre-lockdown policy. A record with no captured baseline (below) reloads `/etc/pf.conf` instead
    /// (`StateFile::restore_choice`), and so does a snapshot that will not load (the restore falls back).
    pub main_snapshot: String,
    /// The host's translation rules (`pfctl -sn`: nat/rdr) captured alongside
    /// `main_snapshot`. Carried forward into the lockdown ruleset (so the
    /// session does not flush NAT) and re-loaded on Sweep for restore.
    pub nat_snapshot: String,
    /// `false` when the host's filter ruleset at engage time was our OWN cover,
    /// so there was no pre-lockdown baseline to capture; a restore then reloads
    /// `/etc/pf.conf` instead of `main_snapshot`. Read by
    /// `StateFile::restore_choice`, which every standing release asks.
    ///
    /// A bool, not `main_snapshot.is_empty()`: a host can have an empty filter ruleset, and that is its policy.
    ///
    /// Defaults `true` without a schema bump, so a file written before this field existed reads as the captured
    /// baseline it was. A bump would make every existing file `Unusable`, which a reader treating it as absent would
    /// answer with an early `Ok(())` from `disengage_lockdown` over a still-blocked host.
    #[serde(default = "default_true")]
    pub main_snapshot_captured: bool,
}

fn default_true() -> bool {
    true
}

impl Schema for LockdownPfState {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;

    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

/// A cover's evidence: one this release cannot read is moved aside by a clear and backed up by a store, and its
/// token is still salvaged for the sweep ([`super::StateFile::view`]).
impl VersionedState for LockdownPfState {
    const FILE_NAME: &'static str = STATE_FILE_NAME;
    const ROLE: Role = Role::Cover;
}

util::assert_contiguous!(LockdownPfState);

impl super::pf_record::PfRecord for LockdownPfState {
    fn pf_token(&self) -> &str {
        &self.pf_token
    }
}

impl super::StateFile<LockdownPfState> {
    /// The release's restore choice: the baseline a standing release loads, or `None` when it must reload
    /// `/etc/pf.conf`. Every release of the standing cover asks it, and an unusable or unreadable record says here that
    /// it has no snapshot to restore. That is a log line, so this is not a pure query: ask it once per release.
    ///
    /// A record with no captured baseline has none to load: its `main_snapshot` is empty, and loading that would leave
    /// a pass-all host. No record at all means presence was established by pf's label alone.
    pub(crate) fn restore_choice(&self) -> Option<&LockdownPfState> {
        use super::StateFile;
        match self {
            StateFile::Present(st) if st.main_snapshot_captured => Some(st),
            StateFile::Present(_) => None,
            StateFile::Absent => None,
            StateFile::Unusable { .. } => {
                tracing::warn!(
                    "standing lockdown-pf-state file is unusable; no snapshot to restore, falling back to the \
                     default ruleset"
                );
                None
            }
            StateFile::Unreadable => {
                tracing::warn!(
                    "standing lockdown-pf-state file could not be read; no snapshot to restore, falling back to \
                     the default ruleset"
                );
                None
            }
        }
    }
}
