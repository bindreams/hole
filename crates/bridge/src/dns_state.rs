//! Persisted DNS state: a read-only escape hatch for a `bridge-dns.json` an
//! older build left behind. The bridge no longer writes this file; DNS egress
//! is confined by `tun_engine::dns_confine`, whose process-scoped session
//! persists nothing. What remains is [`load`], [`clear`] and [`supersede`],
//! used once per file by [`crate::dns::recovery`]'s upgrade sweep, and the
//! schema types, kept so an older build's file can still be parsed and, when
//! the evidence supports it, undone.
//!
//! Assumes one bridge at a time reads the file. The single-instance guarantee
//! behind that is not airtight; the read-once bound the sweep puts on this
//! module is what makes a second reader harmless (see [`crate::dns::recovery`]).
//! The sweep is described in `docs/contributing/architecture/crash-recovery.md`.

use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};
use util::versioned_file::{
    Change, DefaultPlacement, Loaded, Obsolete, Role, Schema, StoreError, UpdateOutcome, VersionedFile, VersionedState,
};

// Types ===============================================================================================================

/// Filename of the persisted state file under `state_dir`. Exported so
/// external tooling (notably `scripts/network-reset.py`) can reference the
/// single source of truth.
pub const STATE_FILE_NAME: &str = "bridge-dns.json";

/// Filename a file is renamed to after the upgrade sweep has evaluated it
/// once without deleting it (some family lacked evidence). The bridge reads
/// only [`STATE_FILE_NAME`], so the sweep never evaluates a file twice;
/// `scripts/network-reset.py` reads both names. See `crate::dns::recovery`
/// for why that bound is load-bearing.
pub const SUPERSEDED_FILE_NAME: &str = "bridge-dns.superseded.json";

// No `deny_unknown_fields`, here or in the types below: a v1 file from an older crashed run carries the obsolete
// `chosen_loopback` key. Tolerating it (ignore the unknown key, default `advertised` to empty) keeps crash+upgrade
// recovery working: `load` still returns the state and recovery restores from `adapters`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsState {
    /// The upstream resolver IPs the writing build advertised to its
    /// adapters. Not diagnostic-only: it is the upgrade sweep's only evidence
    /// that a live adapter's DNS is still what that build left behind (the
    /// gate is in `crate::dns::recovery`). A file carrying the obsolete
    /// `chosen_loopback` key may omit it; it then loads as empty, which means
    /// "no evidence", never a match.
    #[serde(default)]
    pub advertised: Vec<IpAddr>,
    pub adapters: Vec<DnsPriorAdapter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsPriorAdapter {
    pub id: AdapterId,
    /// Friendly adapter name captured at `capture` time, for diagnostic
    /// logging only. Not used by restore. Empty string is acceptable when
    /// the capture code cannot derive a name.
    pub name_at_capture: String,
    pub v4: DnsPrior,
    pub v6: DnsPrior,
}

/// OS-stable adapter identifier. Tagged so the on-disk format is
/// self-describing and `scripts/network-reset.py` can dispatch on `kind`
/// without inferring the platform. Every variant names its field `value`, so
/// a reader can extract it without branching on `kind`.
///
/// It is the adapter's friendly name, not a LUID or GUID: `netsh` and
/// `networksetup` both take the name, so restore needs no lookup. Names
/// survive reboots; a rename mid-session leaves the adapter unfound and
/// restore skips it silently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AdapterId {
    /// Windows adapter friendly name (alias), e.g. "Ethernet" or "Wi-Fi".
    /// Passed directly to `netsh interface ... name="<value>"`.
    WindowsAlias { value: String },
    /// macOS network service name, e.g. "Wi-Fi" or "Ethernet". Passed
    /// directly to `networksetup -setdnsservers <value>`.
    MacosServiceName { value: String },
}

/// Prior DNS configuration for a single adapter + address family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DnsPrior {
    /// No DNS was configured for this family (restore: clear to empty). On
    /// macOS the restore operation is identical to [`DnsPrior::Dhcp`] —
    /// `networksetup -setdnsservers <service> Empty` covers both — but the
    /// variants are kept distinct so Windows can dispatch precisely.
    None,
    /// DNS was DHCP-assigned (restore: re-enable DHCP for DNS).
    Dhcp,
    /// DNS was statically configured to `servers` (restore: re-apply list).
    Static { servers: Vec<IpAddr> },
}

/// Schema 1, the only one: no release has written this file since the bridge stopped saving it.
impl Schema for DnsState {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;

    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

/// A legacy record: a past release wrote it and none does now, so one this release cannot read is kept, never
/// overwritten, and never blocks a connect.
impl VersionedState for DnsState {
    const FILE_NAME: &'static str = STATE_FILE_NAME;
    const ROLE: Role = Role::LegacyRecord;
}

util::assert_contiguous!(DnsState);

// I/O =================================================================================================================
//
// No `save` — the bridge no longer writes this file (see the module doc).
// Only `load`, `clear`, and `supersede` remain, all for the upgrade sweep.

/// The legacy DNS record's file.
pub type DnsFile = VersionedFile<DnsState>;

pub fn file(state_dir: &Path) -> DnsFile {
    VersionedFile::new(state_dir)
}

/// Load the state file. Returns `None` for anything but a readable record — missing file, corrupt JSON, a newer or
/// obsolete version, a failed read — and the read logs the cause at `warn`. Crash recovery is best-effort and
/// should never fail the caller.
pub fn load(state_dir: &Path) -> Option<DnsState> {
    match file(state_dir).observe().loaded {
        Loaded::Current { value, .. } => Some(value),
        Loaded::Absent => None,
        Loaded::Obsolete { .. } => None,
        Loaded::Newer { .. } => None,
        Loaded::Corrupt { .. } => None,
        Loaded::Unreadable { .. } => None,
    }
}

/// Delete the state file. A missing file is [`UpdateOutcome::Absent`]; one this release cannot read is
/// [`UpdateOutcome::Kept`]. `Err` only on actual I/O errors (permissions, etc.).
pub fn clear(state_dir: &Path) -> Result<UpdateOutcome, StoreError> {
    file(state_dir)
        .update(&DefaultPlacement::default(), |_| (Change::Remove, ()))
        .map(|((), outcome)| outcome)
}

/// Filename for the `n`th superseded file: [`SUPERSEDED_FILE_NAME`] for `n == 1`, else an archive name, used only
/// when every earlier one is occupied. Archive names are forensic: neither this crate nor `scripts/network-reset.py`
/// reads one back. The script's lookup order (un-suffixed, then [`SUPERSEDED_FILE_NAME`]) lands on the oldest
/// superseded file, which this module keeps at the canonical name.
fn superseded_file_name(n: u64) -> String {
    match n {
        1 => SUPERSEDED_FILE_NAME.to_owned(),
        n => format!("bridge-dns.superseded.{n}.json"),
    }
}

/// Rename the state file to [`SUPERSEDED_FILE_NAME`]: the upgrade sweep's "evaluated once, not fully confirmed"
/// outcome. The bridge never reads the superseded name, so the sweep's value-equality gate cannot re-arm on a later,
/// unrelated coincidence; `scripts/network-reset.py` reads both names, so the escape survives the rename.
/// A missing source file is `Ok`.
///
/// Never clobbers an existing superseded file. The move is one rename that refuses to replace
/// ([`util::dir::Dir::rename_noreplace`]), so no probe-then-move race exists. When the canonical name is taken (this
/// ran twice without the first file being cleared: reinstall, rollback, a second crash), the older file keeps it
/// and the newer one goes to the first free [`superseded_file_name`]. A superseded file exists because an earlier
/// restore did not fully succeed, so the newer file's recorded priors may already be Hole's own dead resolver IPs;
/// the older one is closer to the user's original DNS. A volume with no no-replace rename answers `Unsupported` and
/// nothing is moved.
///
/// The bridge runs this as root/SYSTEM in a folder the user may own, so the directory is opened without following a
/// symlink and the rename goes by name through the handle
/// (`docs/contributing/architecture/privileged-folders.md`).
pub fn supersede(state_dir: &Path) -> std::io::Result<()> {
    use std::io::ErrorKind;

    let dir = match util::dir::Dir::open(state_dir, false, None) {
        Ok(dir) => dir,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let mut n = 1u64;
    loop {
        let to = superseded_file_name(n);
        match dir.rename_noreplace(STATE_FILE_NAME.as_ref(), to.as_ref()) {
            Ok(()) => {
                if n > 1 {
                    tracing::warn!(
                        kept = SUPERSEDED_FILE_NAME,
                        archived = to,
                        "dns_state: bridge-dns.superseded.json already existed; archived the newer file instead of overwriting it. The archive is forensic only — nothing reads it back."
                    );
                }
                return Ok(());
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => n += 1,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
#[path = "dns_state_tests.rs"]
mod dns_state_tests;
