//! The persisted TARGET both surfaces (lockdown, tunnel) reconcile toward.
//!
//! Distinct from `bridge-lockdown.json`'s `Intent` (a *preference* that
//! survives disconnects): this file records what the user last asked to
//! connect to, and is the one fact the bridge can read before any GUI
//! exists — the boot requirement forces it to be root-owned and
//! process-independent. See `CONTRIBUTING.md#fail-closed-cover` and this
//! plan's "Q1" for why the connection parameters live here rather than
//! being read from the user's own config file at reconcile time.
//!
//! Modeled on `crate::routing`'s sibling `lockdown_state.rs` (schema
//! version, atomic save, load-classifies-failure), imported here as
//! `tun_engine::routing::failclosed::lockdown_state` for the pattern this
//! module mirrors — but note the *opposite* lean on load failure: an
//! unreadable lockdown intent is conservatively read as armed (keep
//! protecting); an unreadable target is conservatively read as `Off` (not
//! authority to connect, and not authority to disarm either — see
//! [`Target::Unreadable`]).

use std::io::Write;
use std::path::Path;

use hole_common::protocol::ProxyConfig;
use serde::{Deserialize, Serialize};

// Schema ==============================================================================================================

/// Schema version. [`load`] discards a mismatched or corrupt file as
/// [`Target::Unreadable`] rather than risk acting on a partially-understood
/// record.
pub const SCHEMA_VERSION: u32 = 1;

/// Filename under the bridge's root-owned state directory.
pub const STATE_FILE_NAME: &str = "bridge-target.json";

/// On-disk shape. Only ever holds a *decided* target — [`Target::Unreadable`]
/// is a read-time classification, never a value written to disk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetFile {
    version: u32,
    target: PersistedTarget,
}

/// The two states that are ever actually persisted. Kept separate from
/// [`Target`] (which additionally has to represent "couldn't read it") so
/// this type can derive `Serialize`/`Deserialize` with no variant that would
/// need to reject being written.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum PersistedTarget {
    Off,
    Connected { config: Box<ProxyConfig> },
}

// Target ==============================================================================================================

/// What both surfaces reconcile toward. A closed classification rather than
/// a bool-plus-config, so "the user asked to connect to X" and "we could not
/// find out" cannot be confused — the same shape `Intent` already uses for
/// the sibling lockdown-preference file, and for the same reason: conflating
/// them is a policy bug, not a representation nicety.
///
/// Holds a [`ProxyConfig`], which transitively holds a `ServerAddress` — see
/// [`Dump`](dump::Dump) below and `CONTRIBUTING.md#server-address-redaction`.
#[derive(Debug, Clone, PartialEq)]
pub enum Target {
    /// The file parsed at the current schema and records no connection.
    Off,
    /// The file parsed at the current schema and records the connection the
    /// user asked for.
    Connected { config: Box<ProxyConfig> },
    /// No file at all, or a file that failed to read/parse/version-check.
    /// Authorises neither surface: not "connect" (there is nothing to
    /// connect to) and not "disarm" (losing the record is not the user
    /// asking to disconnect). See [`crate::reconciler::cover_step`] and
    /// [`crate::reconciler::tunnel_step`], both of which resolve this to
    /// `Hold`.
    Unreadable,
}

impl From<PersistedTarget> for Target {
    fn from(p: PersistedTarget) -> Self {
        match p {
            PersistedTarget::Off => Target::Off,
            PersistedTarget::Connected { config } => Target::Connected { config },
        }
    }
}

/// The one read+parse of the target file, mirroring `lockdown_state`'s
/// `read_state`/[`Intent`] split so a version mismatch and a missing file are
/// classified rather than collapsed together in the log.
fn read_target(state_dir: &Path) -> Target {
    let path = state_dir.join(STATE_FILE_NAME);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Target::Off,
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "target-state read failed; treating as no authority to connect");
            return Target::Unreadable;
        }
    };
    match serde_json::from_slice::<TargetFile>(&bytes) {
        Ok(f) if f.version == SCHEMA_VERSION => f.target.into(),
        Ok(other) => {
            tracing::warn!(
                got = other.version,
                want = SCHEMA_VERSION,
                "target-state schema mismatch; treating as no authority to connect"
            );
            Target::Unreadable
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "target-state parse failed; treating as no authority to connect");
            Target::Unreadable
        }
    }
}

/// Load the target. Absent reads [`Target::Off`] — an absent file is a fresh
/// install or a wiped state dir, not consent to connect. Corrupt or
/// schema-mismatched reads [`Target::Unreadable`] — deliberately NOT folded
/// into `Off`'s "no authority to connect" alone: `Unreadable` additionally
/// refuses to authorise a disarm, which a bare `Off` would not distinguish.
pub fn load(state_dir: &Path) -> Target {
    read_target(state_dir)
}

// Errors ==============================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum TargetError {
    #[error("failed to create target-state directory: {0}")]
    CreateDir(std::io::Error),
    #[error("failed to serialize target state: {0}")]
    Serialize(serde_json::Error),
    #[error("failed to write target-state file: {0}")]
    Write(std::io::Error),
    #[error("failed to set target-state file permissions: {0}")]
    SetPermissions(std::io::Error),
}

// Save ================================================================================================================

/// Atomically persist `target` (temp file + same-dir rename, `sync_all`
/// before persist — same discipline as `lockdown_state::save`). Creates
/// `state_dir` at 0700 and the file at 0600 (unix): this file holds a
/// shadowsocks password via `ProxyConfig`'s `ServerEntry`, the same secret
/// the user's own config already keeps at 0600 in a 0700 directory
/// (`CONTRIBUTING.md#server-address-redaction`; `config.rs`'s
/// `ensure_config_dir`). Unlike `lockdown_state::save`, this module does not
/// rely on the temp file's default mode: it sets both permissions
/// explicitly and unconditionally.
///
/// Passing [`Target::Unreadable`] is a caller error — there is no on-disk
/// representation for "couldn't read it", so this asserts in debug builds
/// and, in release, is treated as [`Target::Off`] rather than silently
/// writing nothing.
pub fn save(state_dir: &Path, target: &Target, owner: Option<(u32, u32)>) -> Result<(), TargetError> {
    let persisted = match target {
        Target::Off => PersistedTarget::Off,
        Target::Connected { config } => PersistedTarget::Connected { config: config.clone() },
        Target::Unreadable => {
            debug_assert!(
                false,
                "save() called with Target::Unreadable, which has no on-disk form"
            );
            PersistedTarget::Off
        }
    };

    std::fs::create_dir_all(state_dir).map_err(TargetError::CreateDir)?;
    util::ownership::chown_if_some(state_dir, owner);
    set_dir_mode(state_dir)?;

    let file = TargetFile {
        version: SCHEMA_VERSION,
        target: persisted,
    };
    let json = serde_json::to_vec_pretty(&file).map_err(TargetError::Serialize)?;

    let path = state_dir.join(STATE_FILE_NAME);
    let mut tmp = tempfile::NamedTempFile::new_in(state_dir).map_err(TargetError::Write)?;
    tmp.write_all(&json).map_err(TargetError::Write)?;
    tmp.as_file().sync_all().map_err(TargetError::Write)?;
    set_file_mode(tmp.path()).map_err(TargetError::SetPermissions)?;
    tmp.persist(&path).map_err(|e| TargetError::Write(e.error))?;
    util::ownership::chown_if_some(&path, owner);
    // The rename can, in principle, land the file at a mode other than what
    // was set on the temp name (some filesystems/rename semantics don't
    // guarantee preservation across a hardlink-then-unlink emulation); set
    // it again on the final path so the 0600 invariant does not depend on
    // that guarantee.
    set_file_mode(&path).map_err(TargetError::SetPermissions)?;

    Ok(())
}

#[cfg(unix)]
fn set_dir_mode(dir: &Path) -> Result<(), TargetError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(TargetError::SetPermissions)
}

#[cfg(not(unix))]
fn set_dir_mode(_dir: &Path) -> Result<(), TargetError> {
    Ok(())
}

#[cfg(unix)]
fn set_file_mode(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_file_mode(_path: &Path) -> std::io::Result<()> {
    // Windows: the owner-only DACL is applied by the caller's existing
    // service/task-scheduler install path (same as `bridge-lockdown.json`),
    // not by this module. No portable POSIX-mode equivalent exists here.
    Ok(())
}

// Dump ================================================================================================================

/// `Target::Connected` transitively holds a `ServerAddress` (via
/// `ProxyConfig` -> `ServerEntry` -> `ServerAddress`), so it needs its own
/// `Dump` impl — the same ladder trap `ServerEntry`'s and `ProxyConfig`'s
/// own `Dump` impls exist to close (see their doc comments in
/// `hole_common::config`/`hole_common::protocol`). `ProxyConfig` already
/// redacts the address and the password; this impl exists only to route a
/// `dump!(&target)` call down to it instead of silently falling through to
/// the (non-existent, since `Target` has no `Serialize`) derive ladder.
impl dump::Dump for Target {
    fn dump(&self) -> dump::DumpValue {
        use dump::DumpValue;
        match self {
            Target::Off => DumpValue::String("off".to_string()),
            Target::Unreadable => DumpValue::String("unreadable".to_string()),
            Target::Connected { config } => config.dump(),
        }
    }
}

// SessionEvent / target_after =========================================================================================

/// A named cause for a session ending or persisting, each mapped to a
/// deliberate target transition by [`target_after`]. Five variants, not
/// two: `decide_cover_recovery`'s idiom (`crate::routing`, `tun-engine`)
/// applies here too — an enum whose author must supply a case for every
/// cause is what stops a fresh transition site from picking an existing
/// variant "by elimination" (the defect `StopReason` had: two variants and
/// a non-`Cutover` one opened the host).
///
/// Do not collapse any two variants onto their shared consequence. `GaveUp`
/// and `UserStopped` both move the target to `Off`, but differ at the
/// user-facing surface (only `GaveUp` sets a death reason); `CutoverRestart`,
/// `Blipped`, and `ProcessExiting` all leave the target unchanged, but arise
/// from three unrelated events (an update cutover, a transient retry, and a
/// clean machine shutdown). Merging on shared consequence reproduces the
/// exact defect this type exists to remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// The user asked to disconnect (clean or unclean teardown — Q5: the
    /// target moves because the user asked, never because teardown
    /// succeeded or failed).
    UserStopped,
    /// The system gave up on the target: an unexpected session death
    /// observed by a health check.
    GaveUp,
    /// An update cutover: the new bridge process is expected to adopt this
    /// same target immediately, so it must survive across the restart.
    CutoverRestart,
    /// A transient retry/reconnect blip. Reconciliation working, not a
    /// decision to disconnect.
    Blipped,
    /// A clean machine shutdown (launchd SIGTERM / SCM Stop with no cutover
    /// marker present). Must NOT be confused with `UserStopped`: a user who
    /// asked for reconnect-on-boot never authorised a disconnect just
    /// because the machine is rebooting.
    ProcessExiting,
}

/// The single pure decision: given the current target and a named cause,
/// what should the target become? Exhaustive over both axes (no wildcard
/// arm) so a new `SessionEvent` variant, or a new `Target` variant, is a
/// compile error here — the same idiom `decide_cover_recovery` uses.
///
/// `CutoverRestart` and `Blipped` leave a `Connected` target unchanged; that
/// is the whole reason a cutover disarms rather than releases the cover
/// (see `crate::reconciler`), and it is what `StopReason::Cutover` used to
/// encode by itself, one call site at a time.
///
/// Over [`Target::Unreadable`]: there is no config to preserve, so an event
/// that would otherwise "leave the target unchanged" leaves it `Unreadable`
/// (nothing to lose by not deciding); an event that reaches a definite
/// outcome regardless of the prior value (`GaveUp`, `UserStopped`) still
/// lands on the same definite `Off` it would from a known `Connected`
/// target — the user's stop request, or the system's give-up, is not made
/// less real by the file having been corrupt.
pub fn target_after(current: Target, ev: SessionEvent) -> Target {
    match (current, ev) {
        (_, SessionEvent::UserStopped) => Target::Off,
        (_, SessionEvent::GaveUp) => Target::Off,
        (current, SessionEvent::CutoverRestart) => current,
        (current, SessionEvent::Blipped) => current,
        (current, SessionEvent::ProcessExiting) => current,
    }
}

#[cfg(test)]
#[path = "target_tests.rs"]
mod target_tests;
