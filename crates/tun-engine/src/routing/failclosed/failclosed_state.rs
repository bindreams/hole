//! Persisted fail-closed-cover state for crash recovery (macOS only).
//!
//! macOS engages the cover by enabling pf with `pfctl -E`, which returns a
//! reference-count token. We persist that token BEFORE loading the blocking
//! ruleset so a crashed update cutover can be cleanly reversed on the next
//! bridge start (`recover_cover`: restore `/etc/pf.conf` + `pfctl -X <token>`).
//! Windows needs no analogue: its WFP filters carry fixed GUIDs and are swept
//! by key, so there is nothing to persist.

use serde::{Deserialize, Serialize};
use util::versioned_file::{Obsolete, Role, Schema, VersionedState};

/// Filename under `state_dir`. Distinct from `bridge-routes.json` because the
/// cover lifecycle is independent of the route lifecycle (a cover is active
/// precisely while routes are down, mid-cutover).
pub const STATE_FILE_NAME: &str = "bridge-failclosed.json";

/// pf state captured at cover-engage time, persisted before the blocking
/// ruleset is loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailClosedState {
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
}

impl Schema for FailClosedState {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;

    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

/// A cover's evidence: one this release cannot read is moved aside by a clear and backed up by a store, and its
/// token is still salvaged for the sweep ([`super::StateFile::view`]).
impl VersionedState for FailClosedState {
    const FILE_NAME: &'static str = STATE_FILE_NAME;
    const ROLE: Role = Role::Cover;
}

util::assert_contiguous!(FailClosedState);

impl super::pf_record::PfRecord for FailClosedState {
    fn pf_token(&self) -> &str {
        &self.pf_token
    }
}

impl super::StateFile<FailClosedState> {
    /// The one place a transient release says that the record it read is no evidence there is no cover. Every release
    /// of the transient cover that holds the record as a `StateFile` calls it, so each logs the same.
    pub(crate) fn warn_if_not_evidence(&self) {
        use super::StateFile;
        match self {
            StateFile::Present(_) => {}
            StateFile::Absent => {}
            StateFile::Unusable { pf_token } => tracing::warn!(
                token_salvaged = pf_token.is_some(),
                "the transient cover's record is unusable, so it is no evidence there is no cover to clear"
            ),
            StateFile::Unreadable => tracing::warn!(
                "the transient cover's record could not be read, so it is no evidence there is no cover to clear"
            ),
        }
    }
}
