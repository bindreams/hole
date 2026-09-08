//! The persisted TARGET both surfaces (lockdown, tunnel) reconcile toward.
//!
//! Distinct from `bridge-lockdown.json`'s `Intent` (a *preference* that
//! survives disconnects): this file records what the user last asked to
//! connect to, and is the one fact the bridge can read before any GUI
//! exists — the boot requirement forces it to be root-owned and
//! process-independent. See `CONTRIBUTING.md#fail-closed-cover` for why the
//! connection parameters live here rather than being read from the user's
//! own config file at reconcile time.
//!
//! Modeled on `crate::routing`'s sibling `lockdown_state.rs` (schema
//! version, atomic save, load-classifies-failure), imported here as
//! `tun_engine::routing::failclosed::lockdown_state` for the pattern this
//! module mirrors — but note the *opposite* lean on load failure: an
//! unreadable lockdown intent is conservatively read as armed (keep
//! protecting); an unreadable target is conservatively read as `Off` (not
//! authority to connect, and not authority to disarm either — see
//! [`Target::Unreadable`]).

use std::io;
use std::io::Write;
use std::marker::PhantomData;
use std::path::Path;

use hole_common::config::StartupBehavior;
use hole_common::protocol::ProxyConfig;
use serde::{Deserialize, Serialize};
use tun_engine::exclusive::Exclusive;

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
///
/// `pub(crate)`, not `pub`: [`apply`] is the only write surface, but a *read*
/// still has legitimate callers outside it (boot-time reporting, `Status`) —
/// only the write side is the thing multiple racing callers must not bypass.
pub(crate) fn load(state_dir: &Path) -> Target {
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
    #[error("failed to acquire the target-state lock: {0}")]
    Lock(std::io::Error),
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
///
/// `pub(crate)`, not `pub`: see [`load`]'s doc — [`apply`] is the only write
/// surface for the target file.
pub(crate) fn save(state_dir: &Path, target: &Target, owner: Option<(u32, u32)>) -> Result<(), TargetError> {
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

    let file = TargetFile {
        version: SCHEMA_VERSION,
        target: persisted,
    };
    let json = serde_json::to_vec_pretty(&file).map_err(TargetError::Serialize)?;
    write_state_file(state_dir, &state_dir.join(STATE_FILE_NAME), json, owner)
}

/// Atomic temp-file-then-rename write shared by [`save`] and
/// [`save_startup_preference`]: `create_dir_all` + chown + 0700 on the
/// directory, then a same-dir temp file written, `sync_all`'d, explicitly
/// 0600'd, persisted (renamed) over `path`, chowned and 0600'd again on the
/// final path — belt-and-braces because rename is not guaranteed to
/// preserve a temp file's mode on every filesystem.
fn write_state_file(
    state_dir: &Path,
    path: &Path,
    json: Vec<u8>,
    owner: Option<(u32, u32)>,
) -> Result<(), TargetError> {
    std::fs::create_dir_all(state_dir).map_err(TargetError::CreateDir)?;
    util::ownership::chown_if_some(state_dir, owner);
    set_dir_mode(state_dir)?;

    let mut tmp = tempfile::NamedTempFile::new_in(state_dir).map_err(TargetError::Write)?;
    tmp.write_all(&json).map_err(TargetError::Write)?;
    tmp.as_file().sync_all().map_err(TargetError::Write)?;
    set_file_mode(tmp.path()).map_err(TargetError::SetPermissions)?;
    tmp.persist(path).map_err(|e| TargetError::Write(e.error))?;
    util::ownership::chown_if_some(path, owner);
    set_file_mode(path).map_err(TargetError::SetPermissions)?;

    Ok(())
}

#[cfg(unix)]
fn set_dir_mode(dir: &Path) -> Result<(), TargetError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(TargetError::SetPermissions)
}

/// The SID of the user this process runs as, as an SDDL string.
///
/// Needed because `owner: Option<(u32, u32)>` carries unix ids, which say
/// nothing about a Windows principal. Under the `--service` daemon this is
/// SYSTEM (already in [`crate::ipc::SDDL_BASE`], so the extra ACE is
/// redundant and harmless); under elevation it is the invoking user, whose
/// access the unix arm preserves via `chown_if_some` and which a bare
/// SYSTEM+Administrators DACL would otherwise revoke on their own state dir.
#[cfg(windows)]
pub(crate) fn current_user_sid() -> std::io::Result<String> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = HANDLE::default();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no close;
    // `token` is an out-param the call fills on success.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(|e| std::io::Error::other(format!("OpenProcessToken failed: {e}")))?;

    // Size the buffer. This call is EXPECTED to fail with
    // ERROR_INSUFFICIENT_BUFFER and only exists to populate `len`, so its
    // result is deliberately discarded rather than checked.
    let mut len = 0u32;
    // SAFETY: passing a null buffer with zero length is the documented way to
    // query the required size.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut len) };

    // `Vec<u64>`, not `Vec<u8>`: `TOKEN_USER` has pointer alignment, and
    // forming a reference to it out of a byte vector (alignment 1) is
    // undefined behaviour even when the address happens to land aligned.
    let words = (len as usize).div_ceil(std::mem::size_of::<u64>()).max(1);
    let mut buf = vec![0u64; words];
    // SAFETY: `buf` is at least `len` bytes, which is the size the call above
    // reported for this token's `TOKEN_USER`.
    let info = unsafe { GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr().cast()), len, &mut len) };
    // SAFETY: `token` came from `OpenProcessToken` and is not used again.
    unsafe {
        let _ = CloseHandle(token);
    }
    info.map_err(|e| std::io::Error::other(format!("GetTokenInformation(TokenUser) failed: {e}")))?;

    // SAFETY: on success the buffer holds a `TOKEN_USER` whose `Sid` points
    // into that same allocation, which outlives this borrow.
    let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let mut raw = PWSTR::null();
    // SAFETY: `user.User.Sid` is a valid SID for the lifetime of `buf`; `raw`
    // receives a LocalAlloc'd string freed below.
    unsafe { ConvertSidToStringSidW(user.User.Sid, &mut raw) }
        .map_err(|e| std::io::Error::other(format!("ConvertSidToStringSidW failed: {e}")))?;
    // SAFETY: `raw` is a NUL-terminated wide string owned by us until LocalFree.
    let sid = unsafe { raw.to_string() };
    // Freed BEFORE propagating: an early `?` on the conversion would leak the
    // allocation on the one path where the string turns out to be unusable.
    // SAFETY: `raw` came from LocalAlloc inside `ConvertSidToStringSidW`.
    unsafe {
        let _ = LocalFree(Some(std::mem::transmute::<PWSTR, HLOCAL>(raw)));
    }
    sid.map_err(|e| std::io::Error::other(format!("SID was not valid UTF-16: {e}")))
}

/// SDDL for the state directory and its files: SYSTEM + Administrators (from
/// [`crate::ipc::SDDL_BASE`]) plus this process's own user.
///
/// Deliberately NOT `crate::ipc::build_sddl`, which unconditionally grants the
/// `hole` GROUP full control — that group exists so non-admin users can reach
/// the IPC socket, and these files hold the shadowsocks password. Reusing it
/// would grant the secret to exactly the population this DACL excludes.
///
/// A failed SID lookup degrades to SYSTEM + Administrators rather than
/// failing the write: losing the owner's own access is recoverable (they are
/// an administrator in both run modes), leaving the password world-readable
/// is not.
#[cfg(windows)]
fn state_sddl() -> String {
    match current_user_sid() {
        Ok(sid) => format!("{}(A;;GA;;;{sid})", crate::ipc::SDDL_BASE),
        Err(e) => {
            tracing::warn!(error = %e, "could not resolve this process's user SID; state DACL is admin-only");
            crate::ipc::SDDL_BASE.to_string()
        }
    }
}

/// `protect = true` is the load-bearing half: it detaches the object from its
/// parent's inheritance, which is what drops `C:\ProgramData`'s
/// `BUILTIN\Users` read ACE. Without it this call changes nothing that
/// matters.
#[cfg(windows)]
fn set_dir_mode(dir: &Path) -> Result<(), TargetError> {
    // `OICI` on every ACE: object- and container-inherit. Without it a
    // PROTECTED directory DACL leaves children inheriting NOTHING, so state
    // files written later by other modules (`bridge-routes.json`,
    // `bridge-lockdown.json`, the lock files) fall back to whatever default
    // the creating token supplies instead of the policy set here.
    let sddl = state_sddl().replace("(A;;", "(A;OICI;");
    crate::ipc::set_dacl_from_sddl(dir, &sddl, true).map_err(TargetError::SetPermissions)
}

#[cfg(not(any(unix, windows)))]
fn set_dir_mode(_dir: &Path) -> Result<(), TargetError> {
    Ok(())
}

#[cfg(unix)]
fn set_file_mode(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(windows)]
fn set_file_mode(path: &Path) -> std::io::Result<()> {
    crate::ipc::set_dacl_from_sddl(path, &state_sddl(), true)
}

#[cfg(not(any(unix, windows)))]
fn set_file_mode(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

// Locking / apply =====================================================================================================

/// Filename of the [`TargetExclusive`] lock file, alongside `STATE_FILE_NAME`
/// in the same root-owned state directory. Never itself holds any state —
/// its only role is `flock`/`LockFileEx`'s target.
const LOCK_FILE_NAME: &str = "bridge-target.json.lock";

/// The bridge's one leaf lock. Held only across [`apply`]'s
/// load-apply-save critical section — microseconds of pure file I/O, never
/// for a session's lifetime — over the shared [`tun_engine::exclusive::Exclusive`]
/// core (see its module doc for the open discipline: `O_NOFOLLOW` +
/// `mode(0o600)` at open + `fchown` on the fd, all security-relevant on the
/// user-writable elevation-mode state directory).
///
/// **Leaf-lock contract (1): nothing may be acquired while this is held, and
/// the critical section stays pure file I/O** — no `Routing`/OS/network/
/// subprocess call. This is what keeps a *blocking* acquisition safe: the
/// reconciler may hold another lock and then block on this one, `hole bridge
/// unlock` blocks on it holding nothing, and neither closes a deadlock cycle.
/// It is a contract on every future editor of `apply`'s body, not a property
/// of today's code — an edit that adds an OS call inside the critical section
/// would break this silently.
///
/// **Leaf-lock contract (2): no `.await` inside the critical section, and
/// this half is compiler-enforced.** The `PhantomData<*const ()>` field makes
/// this type `!Send`; holding a `!Send` value across an `.await` inside a
/// `Send` future is a compile error, so an `.await` later added inside
/// `apply`'s body fails the build instead of silently invalidating the
/// "blocking cannot wedge" argument. `apply` is a synchronous free function
/// that constructs and drops this token within one synchronous body, so the
/// non-`Send` token never crosses an `.await`; async callers reach `apply`
/// only via `spawn_blocking`, capturing `state_dir`/`owner`/`f` (all
/// `Send + 'static`) rather than the token itself. If an implementation
/// shape is ever found that needs to move a constructed token across a
/// boundary instead of building it in place, that is a stop-and-flag case —
/// tell the deputy — not a silent drop of this marker.
struct TargetExclusive {
    _inner: Exclusive,
    // !Send — see the doc above. Never constructed with a real pointer.
    _not_send: PhantomData<*const ()>,
}

impl TargetExclusive {
    /// Block until the lock is held. The only acquisition path on this type
    /// — no `try_acquire` counterpart, since every caller (`apply`) always
    /// wants to wait, never to poll; see the leaf-lock contract above for why
    /// blocking here cannot deadlock.
    fn acquire(state_dir: &Path, owner: Option<(u32, u32)>) -> io::Result<Self> {
        std::fs::create_dir_all(state_dir)?;
        let inner = Exclusive::acquire(&state_dir.join(LOCK_FILE_NAME), owner)?;
        Ok(TargetExclusive {
            _inner: inner,
            _not_send: PhantomData,
        })
    }
}

/// The only write surface for `bridge-target.json`. Acquires
/// [`TargetExclusive`], loads the current target *fresh* — never a value
/// captured before the lock, which is what makes a session-event write and
/// the `hole bridge unlock` escape's write compose correctly instead of
/// racing (a write that read its `current` before acquiring could overwrite
/// a concurrent write that landed inside the critical section) — applies
/// `f`, saves, and releases, all inside one synchronous critical section.
///
/// Every writer of the target goes through this: the session-event path
/// (`apply(state_dir, owner, |current| target_after(current, event))`, called
/// via `spawn_blocking` from the daemon's async contexts, since this function
/// is sync); the connect/disconnect IPC handlers; and the `hole bridge
/// unlock` escape (`apply(state_dir, owner, |_| Target::Off)`, unconditional,
/// called directly since it is already sync, off any runtime).
pub fn apply(
    state_dir: &Path,
    owner: Option<(u32, u32)>,
    f: impl FnOnce(Target) -> Target,
) -> Result<Target, TargetError> {
    apply_committing(state_dir, owner, f, || {})
}

/// [`apply`] plus `on_commit`, run only after the new target is durably saved
/// and while the exclusive lock is STILL held.
///
/// That placement is the point. A caller that needs to publish "this write
/// happened" — `handle_unblock` bumping the generation counter
/// `persist_after_start` compares against — cannot do it inside `f`, because
/// `f` runs before `save` and a save failure would leave the announcement
/// standing over a write that never landed, permanently declining every later
/// start's target write. Doing it after `apply` returns is equally wrong: the
/// lock is gone by then, so a concurrent reader can observe the commit without
/// the announcement.
pub fn apply_committing(
    state_dir: &Path,
    owner: Option<(u32, u32)>,
    f: impl FnOnce(Target) -> Target,
    on_commit: impl FnOnce(),
) -> Result<Target, TargetError> {
    let _lock = TargetExclusive::acquire(state_dir, owner).map_err(TargetError::Lock)?;
    let current = load(state_dir);
    let next = f(current);
    if next == Target::Unreadable {
        // `f` declined to decide (e.g. `target_after`'s `CutoverRestart`/
        // `Blipped`/`ProcessExiting` arms passing an already-unreadable
        // target through unchanged) — a real, reachable case, not a caller
        // error. `save` has no on-disk form for `Unreadable`; leave the file
        // untouched instead of downgrading it to `Off`.
        return Ok(next);
    }
    save(state_dir, &next, owner)?;
    on_commit();
    Ok(next)
}

// Startup preference ==================================================================================================

/// Pure launch-time decision (#458): should the bridge auto-connect at its
/// own next boot? Relocated verbatim from `crates/hole/src/tray.rs` (#979) —
/// same exhaustive match, same doc intent: `last_enabled` is the persisted
/// last-honored intent, and the exhaustive match makes a future
/// `StartupBehavior` variant a compile error here.
pub fn startup_should_connect(behavior: StartupBehavior, last_enabled: bool) -> bool {
    match behavior {
        StartupBehavior::DoNotConnect => false,
        StartupBehavior::RestoreLastState => last_enabled,
        StartupBehavior::AlwaysConnect => true,
    }
}

/// What the bridge should reconcile toward at its own boot, given the
/// persisted target and the GUI's pushed startup preference: one decider,
/// not two — the startup behaviour is applied first, to produce the
/// target, so reconciliation afterward has exactly one input.
///
/// - `DoNotConnect` always writes `Off`, regardless of what was persisted.
/// - `RestoreLastState` leaves the persisted target exactly as read —
///   `Connected`, `Off`, and `Unreadable` all pass through unchanged.
/// - `AlwaysConnect` keeps an already-`Connected` target as-is (its config is
///   already fully specified); over `Off`/`Unreadable` it substitutes
///   `candidate` — the last-connected config, pushed alongside `on_startup`
///   — when one was ever pushed, and otherwise leaves the target unchanged:
///   there is nothing to fabricate a connection from.
pub fn resolve_startup_target(
    persisted: Target,
    behavior: StartupBehavior,
    candidate: Option<Box<ProxyConfig>>,
) -> Target {
    match behavior {
        StartupBehavior::DoNotConnect => Target::Off,
        StartupBehavior::RestoreLastState => persisted,
        StartupBehavior::AlwaysConnect => match persisted {
            Target::Connected { .. } => persisted,
            Target::Off | Target::Unreadable => match candidate {
                Some(config) => Target::Connected { config },
                None => persisted,
            },
        },
    }
}

/// Schema version for [`STARTUP_PREFERENCE_FILE_NAME`], independent of
/// [`SCHEMA_VERSION`] — the two files are unrelated on disk and evolve
/// separately.
const STARTUP_PREFERENCE_SCHEMA_VERSION: u32 = 1;

/// Filename for the GUI-pushed startup preference, alongside
/// `STATE_FILE_NAME` in the same root-owned state directory. A separate file
/// rather than a field on the target file: unlike the target (governed by
/// [`TargetExclusive`]/[`apply`] because multiple writers race it),
/// this is written by exactly one path (`handle_start`, on every connect) and
/// read by exactly one (boot reconciliation), so it needs no shared lock.
const STARTUP_PREFERENCE_FILE_NAME: &str = "bridge-startup.json";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartupPreferenceFile {
    version: u32,
    on_startup: StartupBehavior,
    candidate: Option<Box<ProxyConfig>>,
}

/// The GUI-pushed startup preference: what to do at the bridge's own next
/// boot (`on_startup`), and the last connect config to fall back on for
/// `AlwaysConnect` when the persisted target itself carries none (`candidate`
/// — see [`resolve_startup_target`]). Holds a [`ProxyConfig`], so — like
/// [`Target`] — logging it must go through its (derived, safe: `ProxyConfig`
/// already redacts) `Debug`, never a raw field read.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StartupPreference {
    pub on_startup: StartupBehavior,
    pub candidate: Option<Box<ProxyConfig>>,
}

/// Load the startup preference. Absent, corrupt, or schema-mismatched all
/// read the default (`RestoreLastState`, no candidate) — the same
/// conservative lean as an absent target: no authority to always-connect
/// without an explicit push.
pub(crate) fn load_startup_preference(state_dir: &Path) -> StartupPreference {
    let path = state_dir.join(STARTUP_PREFERENCE_FILE_NAME);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return StartupPreference::default(),
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "startup-preference read failed; using defaults");
            return StartupPreference::default();
        }
    };
    match serde_json::from_slice::<StartupPreferenceFile>(&bytes) {
        Ok(f) if f.version == STARTUP_PREFERENCE_SCHEMA_VERSION => StartupPreference {
            on_startup: f.on_startup,
            candidate: f.candidate,
        },
        Ok(other) => {
            tracing::warn!(
                got = other.version,
                want = STARTUP_PREFERENCE_SCHEMA_VERSION,
                "startup-preference schema mismatch; using defaults"
            );
            StartupPreference::default()
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "startup-preference parse failed; using defaults");
            StartupPreference::default()
        }
    }
}

/// The only read-modify-write surface for `bridge-startup.json`.
///
/// Takes the SAME [`TargetExclusive`] lock the target file uses, because the
/// two records are read together by `resolve_startup_target` and a torn pair
/// is what lets an escape be undone: `handle_unblock` clearing the candidate
/// while a concurrent `persist_after_start` re-adds it leaves `Off` plus a
/// live candidate, which `AlwaysConnect` then reconnects from.
///
/// A single lock rather than a second one: these files are always mutated in
/// the same breath, and a second lock ordered against the first is a deadlock
/// waiting to be written. The leaf-lock contract in [`TargetExclusive`] still
/// applies — `f` must stay pure file I/O.
pub(crate) fn apply_startup_preference(
    state_dir: &Path,
    owner: Option<(u32, u32)>,
    f: impl FnOnce(&mut StartupPreference),
) -> Result<(), TargetError> {
    let _lock = TargetExclusive::acquire(state_dir, owner).map_err(TargetError::Lock)?;
    let mut pref = load_startup_preference(state_dir);
    f(&mut pref);
    save_startup_preference(state_dir, &pref, owner)
}

/// Persist the startup preference (same atomic-write + 0600/0700 discipline
/// as [`save`], via the same [`write_state_file`] helper).
pub(crate) fn save_startup_preference(
    state_dir: &Path,
    pref: &StartupPreference,
    owner: Option<(u32, u32)>,
) -> Result<(), TargetError> {
    let file = StartupPreferenceFile {
        version: STARTUP_PREFERENCE_SCHEMA_VERSION,
        on_startup: pref.on_startup,
        candidate: pref.candidate.clone(),
    };
    let json = serde_json::to_vec_pretty(&file).map_err(TargetError::Serialize)?;
    write_state_file(state_dir, &state_dir.join(STARTUP_PREFERENCE_FILE_NAME), json, owner)
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
    /// The user asked to disconnect (clean or unclean teardown — the
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

impl SessionEvent {
    /// Whether this event carries its own explanation of why the session
    /// ended, which teardown must therefore NOT clear.
    ///
    /// A classifier method rather than a comparison at the call site: that is
    /// the one place a sixth variant has to answer this question, instead of
    /// silently inheriting whichever side of an `!=` it happens to fall on.
    /// `check_health` sets `last_error`/`death_reason` to explain a `GaveUp`
    /// teardown; clearing them there would erase the explanation before
    /// the GUI toast ever reads it. Every other cause arrives with no
    /// explanation of its own, so the stale one from a previous failed start
    /// is cleared.
    pub fn preserves_death_reason(self) -> bool {
        match self {
            SessionEvent::GaveUp => true,
            SessionEvent::UserStopped
            | SessionEvent::CutoverRestart
            | SessionEvent::Blipped
            | SessionEvent::ProcessExiting => false,
        }
    }
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
