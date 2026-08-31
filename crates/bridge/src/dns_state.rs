//! Persisted DNS state — read-only escape hatch for a `bridge-dns.json` an
//! older build left behind. The bridge itself no longer writes this file:
//! DNS egress is confined by `tun_engine::dns_confine`'s WFP confinement
//! instead, which persists nothing (see that module's doc for why a
//! process-scoped dynamic FWPM session needs no crash-recovery state at
//! all). What remains here is `load` + `clear`/`supersede`, used exactly
//! once per file by [`crate::dns::recovery`]'s evidence-gated upgrade
//! sweep, and the schema types themselves — kept so an older build's file
//! can still be parsed and, when the evidence supports it, undone.
//!
//! Single-reader assumption: only one bridge starts at a time reads this
//! file (the IPC socket bind's intended single-instance guarantee — see
//! bindreams/hole#936 for why that guarantee does not fully hold today, and
//! `crate::dns::recovery`'s doc for why this module's read-once bound makes
//! that gap harmless here).

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// Types ===============================================================================================================

/// Schema version for [`DnsState`]. Bump when the struct changes in a
/// backwards-incompatible way; [`load`] rejects mismatched versions to force
/// a fresh run rather than corrupt recovery.
pub const SCHEMA_VERSION: u32 = 1;

/// Filename of the persisted state file under `state_dir`. Exported so
/// external tooling (notably `scripts/network-reset.py`) can reference the
/// single source of truth.
pub const STATE_FILE_NAME: &str = "bridge-dns.json";

/// Filename a file is renamed to after the upgrade sweep has evaluated it
/// once, whenever it wasn't deleted outright (some family lacked evidence).
/// The bridge never reads this name — only ever the un-suffixed
/// [`STATE_FILE_NAME`] — so the sweep can never re-evaluate the same file
/// twice; `scripts/network-reset.py` reads both names, so the escape survives
/// the rename. See `crate::dns::recovery`'s doc for why that bound is
/// load-bearing.
pub const SUPERSEDED_FILE_NAME: &str = "bridge-dns.superseded.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// NOTE: NO `deny_unknown_fields` — a v1 file from an older crashed run
// carries the obsolete `chosen_loopback` key. Tolerating it (ignore the
// unknown key, default `advertised` to empty) keeps crash+upgrade recovery
// working: `load` still returns the state and recovery restores from
// `adapters`.
pub struct DnsState {
    pub version: u32,
    /// The upstream resolver IPs the writing build advertised to its
    /// adapters. NOT diagnostic-only: the upgrade sweep's ONLY evidence
    /// that a live adapter's current DNS is still what that old build left
    /// behind — see `crate::dns::recovery`'s doc for the exact gate.
    /// `#[serde(default)]` so a file old enough to carry the obsolete
    /// `chosen_loopback` key (never one that legitimately omits
    /// `advertised` — the field has been declared and serialized since
    /// schema version 1) still loads, defaulting to empty; an empty value
    /// is treated as "no evidence", never as a match.
    #[serde(default)]
    pub advertised: Vec<IpAddr>,
    pub adapters: Vec<DnsPriorAdapter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsPriorAdapter {
    pub id: AdapterId,
    /// Friendly adapter name captured at `capture` time, for diagnostic
    /// logging only. Not used by restore. Empty string is acceptable when
    /// the capture code cannot derive a name.
    pub name_at_capture: String,
    pub v4: DnsPrior,
    pub v6: DnsPrior,
}

/// OS-stable adapter identifier. Tagged to keep the on-disk format
/// self-describing so `scripts/network-reset.py` can dispatch on `kind`
/// without inferring from platform. Inner field is named `value` in every
/// variant so readers can extract it uniformly without branching on `kind`.
///
/// ## Why alias/name not LUID/GUID
///
/// `netsh` (Windows) and `networksetup` (macOS) both accept the adapter's
/// friendly *name* as their identifier. Going through LUID (Windows) or
/// service-GUID (macOS) would require an extra name-round-trip at restore
/// time. Stability: interface aliases survive reboots; macOS service
/// names survive reboots. Rename mid-session is the only failure mode,
/// matching the plan's "skip silently on restore" semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
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
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
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

fn state_file(state_dir: &Path) -> PathBuf {
    state_dir.join(STATE_FILE_NAME)
}

fn superseded_file(state_dir: &Path) -> PathBuf {
    state_dir.join(SUPERSEDED_FILE_NAME)
}

// I/O =================================================================================================================
//
// No `save` — the bridge no longer writes this file (see the module doc).
// Only `load`, `clear`, and `supersede` remain, all for the upgrade sweep.

/// Load the state file. Returns `None` for any error — missing file,
/// corrupted JSON, unknown fields, version mismatch — and logs at `warn`
/// level. Crash recovery is best-effort and should never fail the caller.
pub fn load(state_dir: &Path) -> Option<DnsState> {
    let path = state_file(state_dir);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "dns-state read failed");
            return None;
        }
    };
    match serde_json::from_slice::<DnsState>(&bytes) {
        Ok(state) if state.version == SCHEMA_VERSION => Some(state),
        Ok(other) => {
            tracing::warn!(
                got = other.version,
                want = SCHEMA_VERSION,
                "dns-state schema mismatch, discarding"
            );
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "dns-state parse failed");
            None
        }
    }
}

/// Delete the state file. Tolerates a missing file (returns `Ok`). Returns
/// `Err` only on actual I/O errors (permissions, etc.).
pub fn clear(state_dir: &Path) -> std::io::Result<()> {
    let path = state_file(state_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Rename the state file to [`SUPERSEDED_FILE_NAME`]. The upgrade sweep's
/// "evaluated once, not fully confirmed" outcome: the bridge never reads the
/// superseded name again (so the value-equality gate cannot re-arm on a
/// later, unrelated coincidence), but `scripts/network-reset.py` reads both
/// names, so the escape survives the rename rather than being hidden by it.
/// Tolerates a missing source file (returns `Ok`).
pub fn supersede(state_dir: &Path) -> std::io::Result<()> {
    let from = state_file(state_dir);
    let to = superseded_file(state_dir);
    match std::fs::rename(&from, &to) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
#[path = "dns_state_tests.rs"]
mod dns_state_tests;
