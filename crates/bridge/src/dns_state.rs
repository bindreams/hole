//! Persisted DNS state for crash recovery.
//!
//! The bridge writes the chosen loopback bind address and prior system-DNS
//! settings to a JSON file when the DNS forwarder starts, clears it on clean
//! shutdown, and reads it on startup to restore DNS leaked by a previous
//! crashed run. Mirrors the `route_state.rs` / `plugin_state.rs`
//! crash-recovery pattern.
//!
//! Single-writer assumption: the bridge is the only writer of this file
//! within a process, and only one bridge runs at a time (the IPC socket bind
//! enforces single-instance). Concurrent `save` calls are not supported.

use std::io::Write;
use std::net::{IpAddr, SocketAddr};
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsState {
    pub version: u32,
    pub chosen_loopback: SocketAddr,
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

// I/O =================================================================================================================

/// Write `state` to `<state_dir>/bridge-dns.json` atomically via a
/// same-directory temp file + rename. Contents are `sync_all`'d before
/// persist so a process crash sees either the old contents or the new
/// contents, never a truncated file. Creates `state_dir` if missing.
///
/// Does NOT fsync the parent directory after the rename — power-loss
/// durability is out of scope. The design target is process-crash recovery.
pub fn save(state_dir: &Path, state: &DnsState) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir)?;

    let json = serde_json::to_vec_pretty(state).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let mut tmp = tempfile::NamedTempFile::new_in(state_dir)?;
    tmp.write_all(&json)?;
    tmp.as_file().sync_all()?;
    tmp.persist(state_file(state_dir)).map_err(|e| e.error)?;
    Ok(())
}

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

#[cfg(test)]
#[path = "dns_state_tests.rs"]
mod dns_state_tests;
