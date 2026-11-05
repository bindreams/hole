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
    /// existed reads as the captured baseline it was. Bumping the schema
    /// version instead would make every existing file `Unusable`, which
    /// [`load`] collapses to `None`, which makes `disengage_lockdown`
    /// early-return `Ok(())` over a still-blocked host — silently breaking
    /// `hole bridge unlock` and the tray's Unblock item on the ordinary macOS
    /// upgrade path.
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
