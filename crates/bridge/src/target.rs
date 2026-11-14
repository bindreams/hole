//! The persisted TARGET both surfaces (lockdown, tunnel) reconcile toward.
//!
//! Distinct from `bridge-lockdown.json`'s `Intent` (a *preference* that
//! survives disconnects): this file records what the user last asked to
//! connect to, and is the one fact the bridge can read before any GUI
//! exists — the boot requirement forces it to be root-owned and
//! process-independent. That is why the connection parameters live here rather
//! than being read from the user's own config file at reconcile time; see
//! `docs/contributing/architecture/kill-switch.md`.
//!
//! Both files here are `VersionedFile`s of role `Decision`, like the sibling
//! `lockdown_state.rs`, but with a different lean on load failure: an
//! unreadable lockdown intent is read as armed (keep protecting); an
//! unreadable target is read as [`Target::Unreadable`], which is neither `Off`
//! nor `Connected`: no authority to connect, and none to disarm either. A
//! file that is absent altogether reads as `Off`.

use std::fs::File;
use std::io;
use std::path::Path;

use hole_common::config::StartupBehavior;
use hole_common::protocol::ProxyConfig;
use serde::{Deserialize, Serialize};
use util::dir::Dir;
use util::versioned_file::{
    Change, Loaded, Obsolete, Placement, Role, Schema, StoreError, VersionedFile, VersionedState,
};

// Schema ==============================================================================================================

/// Filename under the bridge's root-owned state directory.
pub const STATE_FILE_NAME: &str = "bridge-target.json";

/// On-disk payload. Only ever holds a *decided* target — [`Target::Unreadable`]
/// is a read-time classification, never a value written to disk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct TargetFile {
    target: PersistedTarget,
}

impl Schema for TargetFile {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;

    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

/// The user's latest decision: a file this release cannot read is backed up, then replaced.
impl VersionedState for TargetFile {
    const FILE_NAME: &'static str = STATE_FILE_NAME;
    const ROLE: Role = Role::Decision;
}

util::assert_contiguous!(TargetFile);

fn target_file(state_dir: &Path) -> VersionedFile<TargetFile> {
    VersionedFile::new(state_dir)
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

/// [`Target`]'s `Dump` impl below exists because `Target` has no `Serialize`
/// to fall through to. These two do: a `dump!` on either would render the serde
/// tree and never reach `ProxyConfig::dump`, so each has its own impl. They are
/// private to this module, but visibility does not make a secret safe: a later
/// `pub` or a `dump!` inside the module would leak the config.
///
/// Destructured rather than field-accessed, here and in
/// [`StartupPreferenceFile`]'s impl below: a new field fails compilation
/// until someone decides whether it is a secret, where a `self.field` list
/// would let it vanish from the dump silently.
impl dump::Dump for TargetFile {
    fn dump(&self) -> dump::DumpValue {
        use dump::DumpValue;
        let TargetFile { target } = self;
        DumpValue::Map(vec![(DumpValue::String("target".into()), target.dump())])
    }
}

impl dump::Dump for PersistedTarget {
    fn dump(&self) -> dump::DumpValue {
        use dump::DumpValue;
        match self {
            PersistedTarget::Off => DumpValue::String("off".to_string()),
            PersistedTarget::Connected { config } => config.dump(),
        }
    }
}

// Target ==============================================================================================================

/// What both surfaces reconcile toward. A closed classification rather than
/// a bool-plus-config, so "the user asked to connect to X" and "we could not
/// find out" cannot be confused — the same shape `Intent` already uses for
/// the sibling lockdown-preference file, and for the same reason: conflating
/// them is a policy bug, not a representation nicety.
///
/// Holds a [`ProxyConfig`], which transitively holds a `ServerAddress` — see
/// [`Dump`](dump::Dump) below and `docs/contributing/architecture/redaction.md`.
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

/// The one `Loaded` -> [`Target`] match. A missing file is a fresh install or a wiped state dir, not consent to
/// connect (`Off`); every file this release cannot read is `Unreadable`, which additionally refuses to authorise a
/// disarm, as a bare `Off` would not.
fn target_of(loaded: &Loaded<TargetFile>) -> Target {
    match loaded {
        Loaded::Absent => Target::Off,
        Loaded::Current { value, .. } => value.target.clone().into(),
        Loaded::Obsolete { .. } => Target::Unreadable,
        Loaded::Newer { .. } => Target::Unreadable,
        Loaded::Corrupt { .. } => Target::Unreadable,
        Loaded::Unreadable { .. } => Target::Unreadable,
    }
}

/// Load the target. See [`target_of`] for how each failure reads.
///
/// `pub(crate)`, not `pub`: [`apply`] is the only write surface, but a *read*
/// still has legitimate callers outside it (boot-time reporting, `Status`) —
/// only the write side is the thing multiple racing callers must not bypass.
pub(crate) fn load(state_dir: &Path) -> Target {
    target_of(&target_file(state_dir).observe().loaded)
}

// Placement ===========================================================================================================

/// Passing [`Target::Unreadable`] is a caller error — there is no on-disk
/// representation for "couldn't read it", so this asserts in debug builds
/// and, in release, is treated as [`Target::Off`] rather than silently
/// writing nothing.
fn persisted(target: &Target) -> PersistedTarget {
    match target {
        Target::Off => PersistedTarget::Off,
        Target::Connected { config } => PersistedTarget::Connected { config: config.clone() },
        Target::Unreadable => {
            debug_assert!(false, "Target::Unreadable has no on-disk form");
            PersistedTarget::Off
        }
    }
}

/// Where the state files are written: the directory is handed to `owner` at 0700 (unix) or given the state DACL
/// (Windows, opened with the right to rewrite it), and each file is sealed through its own handle before the rename,
/// because the directory may belong to the interactive user.
struct TargetPlacement {
    owner: Option<(u32, u32)>,
}

impl Placement for TargetPlacement {
    fn owner(&self) -> Option<(u32, u32)> {
        self.owner
    }

    fn prepare_dir(&self, dir: &Dir) -> io::Result<()> {
        dir.secure(self.owner, Some(0o700))?;
        protect_dir(dir)
    }

    fn prepare_tmp(&self, tmp: &File) -> io::Result<()> {
        protect_file(tmp)
    }

    fn open_for_acl(&self) -> bool {
        true
    }
}

/// The SID of the user this process runs as, as an SDDL string.
///
/// Needed because `owner: Option<(u32, u32)>` carries unix ids, which say
/// nothing about a Windows principal. Under the `--service` daemon this is
/// SYSTEM (already in [`crate::ipc::SDDL_BASE`], so the extra ACE is
/// redundant and harmless); under elevation it is the invoking user, whose
/// access the unix arm preserves via `fchown` and which a bare
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
            tracing::warn!(
                error = &e as &dyn std::error::Error,
                "could not resolve this process's user SID; state DACL is admin-only"
            );
            crate::ipc::SDDL_BASE.to_string()
        }
    }
}

/// `protect = true` is the load-bearing half: it detaches the object from its
/// parent's inheritance, which is what drops `C:\ProgramData`'s
/// `BUILTIN\Users` read ACE. Without it this call changes nothing that
/// matters.
#[cfg(windows)]
fn protect_dir(dir: &util::dir::Dir) -> std::io::Result<()> {
    // `OICI` on every ACE: object- and container-inherit. Without it a
    // PROTECTED directory DACL leaves children inheriting NOTHING, so state
    // files written later by other modules (`bridge-routes.json`,
    // `bridge-lockdown.json`, the lock files) fall back to whatever default
    // the creating token supplies instead of the policy set here.
    let sddl = state_sddl().replace("(A;;", "(A;OICI;");
    crate::ipc::set_dacl_from_sddl_on_handle(dir.file(), &sddl, true)
}

/// The mode is the unix half of [`util::dir::Dir::secure`] and
/// [`util::dir::Dir::write_atomic`]; there is no ACL to set.
#[cfg(not(windows))]
fn protect_dir(_dir: &util::dir::Dir) -> std::io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn protect_file(file: &std::fs::File) -> std::io::Result<()> {
    crate::ipc::set_dacl_from_sddl_on_handle(file, &state_sddl(), true)
}

#[cfg(not(windows))]
fn protect_file(_file: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

// Apply ===============================================================================================================

/// The only write surface for `bridge-target.json`. Reads the current target
/// *fresh* under the file's in-process lock — never a value captured before
/// it, which is what makes a session-event write and the `hole bridge
/// unlock` escape's write compose correctly instead of racing — applies `f`,
/// and stores the result, all inside one `VersionedFile::update`. The lock is a
/// leaf: `f` does no I/O and takes no other lock. Another process is excluded
/// by `BridgeLiveness`, not here.
///
/// A target `f` leaves as it found it is not rewritten, and one it returns as
/// [`Target::Unreadable`] (e.g. `target_after`'s `CutoverRestart`/`Blipped`/
/// `ProcessExiting` arms passing an already-unreadable target through) leaves
/// the file untouched — a real, reachable case, not a caller error, and one
/// that has no on-disk form. A file this release cannot read is backed up
/// before a decided target replaces it.
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
) -> Result<Target, StoreError> {
    target_file(state_dir)
        .update(&TargetPlacement { owner }, |observed| {
            let current = target_of(&observed.loaded);
            let next = f(current.clone());
            let change = match (&next, &observed.loaded) {
                (Target::Unreadable, _) => Change::Keep,
                (_, Loaded::Current { .. }) if next == current => Change::Keep,
                _ => Change::Store(TargetFile {
                    target: persisted(&next),
                }),
            };
            (change, next)
        })
        .map(|(next, _)| next)
}

// Startup preference ==================================================================================================

/// Pure launch-time decision: should the bridge auto-connect at its own next
/// boot? `last_enabled` is the persisted last-honored intent.
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

/// Filename for the GUI-pushed startup preference, alongside
/// `STATE_FILE_NAME` in the same root-owned state directory. A separate file
/// rather than a field on the target file: it is written by exactly one path
/// (`handle_start`, on every connect) and read by exactly one (boot
/// reconciliation).
pub(crate) const STARTUP_PREFERENCE_FILE_NAME: &str = "bridge-startup.json";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct StartupPreferenceFile {
    on_startup: StartupBehavior,
    candidate: Option<Box<ProxyConfig>>,
}

impl Schema for StartupPreferenceFile {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;

    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

/// The user's latest decision: a file this release cannot read is backed up, then replaced.
impl VersionedState for StartupPreferenceFile {
    const FILE_NAME: &'static str = STARTUP_PREFERENCE_FILE_NAME;
    const ROLE: Role = Role::Decision;
}

util::assert_contiguous!(StartupPreferenceFile);

fn startup_file(state_dir: &Path) -> VersionedFile<StartupPreferenceFile> {
    VersionedFile::new(state_dir)
}

/// Same live trap as [`TargetFile`]'s: `Serialize` derived, `ProxyConfig`
/// inside.
impl dump::Dump for StartupPreferenceFile {
    fn dump(&self) -> dump::DumpValue {
        use dump::DumpValue;
        let StartupPreferenceFile { on_startup, candidate } = self;
        let candidate = match candidate {
            Some(config) => config.dump(),
            None => DumpValue::Null,
        };
        DumpValue::Map(vec![
            (DumpValue::String("on_startup".into()), dump::from_serialize(on_startup)),
            (DumpValue::String("candidate".into()), candidate),
        ])
    }
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

impl From<&StartupPreference> for StartupPreferenceFile {
    fn from(pref: &StartupPreference) -> Self {
        StartupPreferenceFile {
            on_startup: pref.on_startup,
            candidate: pref.candidate.clone(),
        }
    }
}

/// The one `Loaded` -> [`StartupPreference`] match. Absent and every file this release cannot read give the default
/// (`RestoreLastState`, no candidate) — the same conservative lean as an absent target: no authority to
/// always-connect without an explicit push.
fn preference_of(loaded: &Loaded<StartupPreferenceFile>) -> StartupPreference {
    match loaded {
        Loaded::Current { value, .. } => StartupPreference {
            on_startup: value.on_startup,
            candidate: value.candidate.clone(),
        },
        Loaded::Absent => StartupPreference::default(),
        Loaded::Obsolete { .. } => StartupPreference::default(),
        Loaded::Newer { .. } => StartupPreference::default(),
        Loaded::Corrupt { .. } => StartupPreference::default(),
        Loaded::Unreadable { .. } => StartupPreference::default(),
    }
}

/// Load the startup preference. See [`preference_of`] for how each failure reads.
pub(crate) fn load_startup_preference(state_dir: &Path) -> StartupPreference {
    preference_of(&startup_file(state_dir).observe().loaded)
}

/// The only read-modify-write surface for `bridge-startup.json`: reads the
/// preference fresh under the file's in-process lock, applies `f` and stores
/// the result. A file this release cannot read is backed up before it is
/// replaced.
///
/// The target and the preference are read together by `resolve_startup_target`,
/// and a torn pair is what lets an escape be undone: `handle_unblock` clearing
/// the candidate while a concurrent `persist_after_start` re-adds it leaves
/// `Off` plus a live candidate, which `AlwaysConnect` then reconnects from.
/// Each file has its own lock, so the pair is made atomic by the cover lock, which every writer of both holds
/// across them (`persist_after_start`, `handle_unblock`, `reconcile_once`).
pub(crate) fn apply_startup_preference(
    state_dir: &Path,
    owner: Option<(u32, u32)>,
    f: impl FnOnce(&mut StartupPreference),
) -> Result<(), StoreError> {
    startup_file(state_dir)
        .update(&TargetPlacement { owner }, |observed| {
            let mut pref = preference_of(&observed.loaded);
            f(&mut pref);
            (Change::Store(StartupPreferenceFile::from(&pref)), ())
        })
        .map(|_| ())
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
/// deliberate target transition by [`target_after`]. As with
/// `decide_cover_recovery` (`tun-engine`), an enum whose author must supply a
/// case for every cause is what stops a fresh transition site from picking an
/// existing variant "by elimination".
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
    /// the one place a new variant has to answer this question, instead of
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
/// (see `crate::reconciler`).
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
