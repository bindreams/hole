//! Route table management — platform-specific split routing.

pub mod failclosed;
pub mod state;

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use tracing::{debug, info, warn};

use crate::error::{CommandFailure, RouteCommandError, RoutingError};
use crate::gateway::{get_default_gateway_info, tun_ipv6_available, GatewayInfo};

/// Total number of routing subprocess spawns this process has performed.
/// Incremented once per command executed. Exposed so
/// `diagnostics` handlers and tests can assert the no-routing-subprocess
/// invariant. The one-instruction `fetch_add` has negligible production
/// cost — far below the millisecond-scale subprocess itself.
pub static ROUTING_SUBPROCESS_SPAWN_COUNT: AtomicU32 = AtomicU32::new(0);

// Command builders ====================================================================================================

/// One route-install command plus whether its failure aborts the install.
///
/// Fatality is per command, not per phase. The IPv4 splits and the server
/// bypass are always fatal — a missing one of those sends traffic outside the
/// tunnel. The two IPv6 splits are fatal only when the TUN interface they
/// target has an IPv6 binding ([`tun_ipv6_available`]):
/// where it does not, `netsh interface ipv6 add route` / `route add -inet6`
/// on the TUN can outright fail (`DisabledComponents`, or an EDR policy that
/// unbinds IPv6 from new adapters), and a host with no IPv6 stack emits no
/// IPv6 traffic to leak. Where the TUN's IPv6 IS bound every command is
/// fatal, because there a missing `::/1` route is exactly the #901 leak.
///
/// Non-fatal means *issued and tolerated*, never omitted. A bound TUN always
/// accepts the route regardless of upstream connectivity (it is a virtual
/// device), so an unbound TUN is the only case where the command can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupCommand {
    /// Program plus arguments.
    pub argv: Vec<String>,
    /// `false` means a non-zero exit is logged and the phase continues.
    pub fatal: bool,
}

impl SetupCommand {
    /// A command whose failure aborts the install.
    fn fatal(argv: Vec<String>) -> Self {
        Self { argv, fatal: true }
    }
}

/// Build the shell commands to set up split routing.
///
/// Creates four or five routes:
/// 1. `0.0.0.0/1` via TUN — captures first half of IPv4 space
/// 2. `128.0.0.0/1` via TUN — captures second half of IPv4 space
/// 3. `::/1` via TUN — captures first half of IPv6 space
/// 4. `8000::/1` via TUN — captures second half of IPv6 space
/// 5. Server bypass — `<server_ip>` via `gateway.gateway_ip` (IPv4 server) or
///    `gateway.interface_name` (IPv6 server)
///
/// Routes 3 and 4 are non-fatal when `tun_ipv6_available` is false — see
/// [`SetupCommand`].
///
/// The server bypass (#5) is omitted when `server_ip` is loopback (checked in
/// canonical form, so an IPv4-mapped `::ffff:127.0.0.1` counts too): a loopback
/// destination is reached via the kernel's on-link `127.0.0.0/8` route, which is
/// more specific than the `/1` splits, so it needs no bypass — and a `/32` (or
/// `/128`) gateway bypass for loopback would hijack all loopback traffic to a
/// gateway that cannot reach it.
///
/// When `server_ip` is IPv6, `gateway.gateway_ip` is unused — the bypass route is
/// interface-based because reliable IPv6 gateway detection is not available on all
/// platforms.
pub fn build_setup_commands(
    tun_name: &str,
    server_ip: IpAddr,
    gateway: &GatewayInfo,
    tun_ipv6_available: bool,
) -> Vec<SetupCommand> {
    platform_setup_commands(tun_name, server_ip, gateway, tun_ipv6_available)
}

/// Build the shell commands to tear down split routing (IPv4 + IPv6 splits and server bypass).
pub fn build_teardown_commands(tun_name: &str, server_ip: IpAddr, interface_name: &str) -> Vec<Vec<String>> {
    platform_teardown_commands(tun_name, server_ip, interface_name)
}

// Execution ===========================================================================================================
//
// Two phase runners with different return types: `setup_routes` below can fail
// install outright; `teardown_routes`/`recover_routes` cannot — see their doc
// comments.

mod phase_sealed {
    pub trait Sealed {}
}

/// A route-command phase. Classification is a property of the phase **type**,
/// and each runner accepts only its own type, so pairing a phase with the wrong
/// runner is a compile error rather than a convention. Sealed: the two families
/// below are the only ones.
pub(crate) trait Phase: phase_sealed::Sealed + Copy {
    /// Whether a non-zero exit in this phase is expected behavior rather than
    /// an anomaly. Picks the log level.
    const BEST_EFFORT: bool;
    /// Phase tag for structured logging.
    fn name(self) -> &'static str;
}

/// Phases whose command failures are ANOMALIES. Only [`run_setup_with`] takes
/// one; a failure aborts (unless the individual [`SetupCommand`] says
/// otherwise), because reporting routes that were never installed sends traffic
/// outside the tunnel while the UI says "protected".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FatalPhase {
    /// Initial split-route install.
    Setup,
    /// macOS pf cover engage. Runs through [`run_capturing`], not a route-command
    /// runner (Windows engages via FWPM FFI — no subprocess phase); gated so it is
    /// not dead code on a non-test Windows lib build under `-D warnings`.
    #[cfg(target_os = "macos")]
    CoverEngage,
}

/// Phases whose command failures are EXPECTED. Only [`run_cleanup_with`] takes
/// one; every command is issued and none can abort the rest, because stopping
/// at the first failure would strand routes and leave the user worse off than
/// if Hole had never run.
///
/// **Teardown** is here — not just crash recovery — because [`setup_routes`] is
/// NOT transactional: when a setup command fails midway, the defensive
/// [`teardown_routes`] call deletes routes that were never installed
/// (empirically `netsh interface ip delete route 0.0.0.0/1 <adapter>` exits
/// non-zero when the route is absent, and the bare `route delete <ip>` does the
/// same). Real teardown failures (e.g. "adapter unavailable") surface via the
/// bridge's post-teardown `Remove-NetAdapter` reporting and via state-file
/// persistence failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BestEffortPhase {
    Teardown,
    RecoverSplit,
    RecoverBypass,
    /// macOS-only, for the same reason as [`FatalPhase::CoverEngage`].
    #[cfg(target_os = "macos")]
    RecoverCover,
}

impl phase_sealed::Sealed for FatalPhase {}
impl Phase for FatalPhase {
    const BEST_EFFORT: bool = false;

    fn name(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            #[cfg(target_os = "macos")]
            Self::CoverEngage => "cover-engage",
        }
    }
}

impl phase_sealed::Sealed for BestEffortPhase {}
impl Phase for BestEffortPhase {
    const BEST_EFFORT: bool = true;

    fn name(self) -> &'static str {
        match self {
            Self::Teardown => "teardown",
            Self::RecoverSplit => "recover-split",
            Self::RecoverBypass => "recover-bypass",
            #[cfg(target_os = "macos")]
            Self::RecoverCover => "recover-cover",
        }
    }
}

// Classification is fixed per type, so a runtime test of it would be vacuous.
// Pinned here instead, which also stops a copy-paste of one `impl` block onto
// the other from landing.
const _: () = assert!(!<FatalPhase as Phase>::BEST_EFFORT);
const _: () = assert!(<BestEffortPhase as Phase>::BEST_EFFORT);

/// Execute route setup commands — the FATAL phase. Stops at the first command
/// that does not exit zero and is marked fatal, and returns it; the caller must
/// not treat the split routes as installed.
pub fn setup_routes(tun_name: &str, server_ip: IpAddr, gateway: &GatewayInfo) -> Result<(), RouteCommandError> {
    // Probed HERE, not read off `gateway`: the IPv6 splits target the TUN
    // (`tun_name`), which by this point already exists (`install` runs after
    // `Dispatcher::new`) — `gateway.ipv6_available` measures the UPSTREAM
    // interface instead, which the commands never name. See `SetupCommand`.
    let tun_ipv6 = tun_ipv6_available(tun_name);
    let commands = build_setup_commands(tun_name, server_ip, gateway, tun_ipv6);
    run_setup_commands(&commands, FatalPhase::Setup)
}

/// Execute route teardown commands — the BEST-EFFORT phase. Idempotent, and
/// safe to call even if routes don't exist: every command is issued, and a
/// failure (routinely, "route not found") neither stops the rest nor is
/// returned.
pub fn teardown_routes(tun_name: &str, server_ip: IpAddr, interface_name: &str) -> CleanupReport {
    let commands = build_teardown_commands(tun_name, server_ip, interface_name);
    run_cleanup_commands(&commands, BestEffortPhase::Teardown)
}

pub(crate) fn build_split_route_teardown_commands(tun_name: &str) -> Vec<Vec<String>> {
    platform_split_route_teardown_commands(tun_name)
}

/// What a best-effort phase did. Deliberately NOT a `Result`: cleanup has no
/// error channel, so no caller can `?` one command's failure into skipping the
/// deletions after it. The counts are for logging and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CleanupReport {
    /// Commands issued — always the full list the phase was handed.
    pub attempted: usize,
    /// How many did not exit zero. Routinely non-zero: a cleanup phase deletes
    /// routes that a healthy system never had.
    pub failed: usize,
}

/// The one site that logs a route command's argv.
///
/// Deliberately **not** hand-redacted: the argv carries the server IP and the
/// redacting log sink covers it, along with every other producer this crate
/// does not author. Extracted so recovery tests can drive the real log site
/// without spawning a subprocess.
pub(crate) fn log_route_command(phase: &str, cmd: &[String]) {
    info!(phase, cmd = cmd.join(" "), "running route command");
}

/// Spawn one command, log it, and report whether it exited zero. The unit both
/// phase runners are built from; injected in tests so each loop's failure
/// policy is assertable without spawning.
fn exec_one<P: Phase>(cmd: &[String], phase: P) -> Result<(), CommandFailure> {
    debug_assert!(!cmd.is_empty(), "route command must not be empty");
    let phase = phase.name();
    ROUTING_SUBPROCESS_SPAWN_COUNT.fetch_add(1, Ordering::SeqCst);
    log_route_command(phase, cmd);

    let output = match Command::new(&cmd[0]).args(&cmd[1..]).output() {
        Ok(output) => output,
        Err(e) => {
            // A missing `netsh`/`route` is never expected, in any phase.
            warn!(phase, cmd = cmd.join(" "), error = %e, "route command failed to spawn");
            return Err(CommandFailure::Spawn(e));
        }
    };
    let exit_code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    if output.status.success() {
        // Success log at debug level. Kept out of info to avoid drowning the
        // per-run log in route noise, but visible when an investigation turns
        // on hole_bridge=debug. stdout/stderr included because netsh sometimes
        // prints a non-empty stdout on success (e.g. "Ok.") that is still
        // worth having in the trace.
        debug!(phase, cmd = cmd.join(" "), exit_code,
               stdout = %stdout.trim(), stderr = %stderr.trim(),
               "route command succeeded");
        return Ok(());
    }

    if P::BEST_EFFORT {
        // Non-zero exits here are the unavoidable consequence of
        // non-transactional install + best-effort cleanup; warning would drown
        // legitimate signal.
        debug!(phase, cmd = cmd.join(" "), exit_code, stderr = %stderr,
               "best-effort command failed (expected if route absent)");
    } else {
        // A non-zero exit during initial route install IS a real anomaly. The
        // full argv and child output land here because the returned error's
        // `Display` is deliberately PII-free. Whether it aborts the start is
        // the caller's per-command call (`SetupCommand::fatal`).
        warn!(phase, cmd = cmd.join(" "), exit_code,
              stdout = %stdout.trim(), stderr = %stderr.trim(),
              "route command failed");
    }
    Err(CommandFailure::Exit(exit_code))
}

/// FATAL phase runner. Stops at the first fatal command that does not exit
/// zero, so no further route mutation is issued after it, and returns it.
fn run_setup_commands(commands: &[SetupCommand], phase: FatalPhase) -> Result<(), RouteCommandError> {
    run_setup_with(commands, phase, exec_one::<FatalPhase>)
}

/// BEST-EFFORT phase runner. Issues EVERY command it is handed; a failure
/// neither short-circuits the rest nor is returned.
fn run_cleanup_commands(commands: &[Vec<String>], phase: BestEffortPhase) -> CleanupReport {
    run_cleanup_with(commands, phase, exec_one::<BestEffortPhase>)
}

/// Test seam for [`run_setup_commands`] — injectable per-command executor.
fn run_setup_with<F>(commands: &[SetupCommand], phase: FatalPhase, mut exec: F) -> Result<(), RouteCommandError>
where
    F: FnMut(&[String], FatalPhase) -> Result<(), CommandFailure>,
{
    for (index, cmd) in commands.iter().enumerate() {
        let Err(failure) = exec(&cmd.argv, phase) else {
            continue;
        };
        if !cmd.fatal {
            // `exec` already logged the exit code and child output.
            warn!(
                cmd = cmd.argv.join(" "),
                "route command failed but is not fatal on this host — continuing"
            );
            continue;
        }
        return Err(RouteCommandError {
            program: cmd.argv.first().cloned().unwrap_or_default(),
            index,
            total: commands.len(),
            failure,
        });
    }
    Ok(())
}

/// Test seam for [`run_cleanup_commands`] — injectable per-command executor.
fn run_cleanup_with<F>(commands: &[Vec<String>], phase: BestEffortPhase, mut exec: F) -> CleanupReport
where
    F: FnMut(&[String], BestEffortPhase) -> Result<(), CommandFailure>,
{
    let mut report = CleanupReport::default();
    for cmd in commands {
        report.attempted += 1;
        if exec(cmd, phase).is_err() {
            report.failed += 1;
        }
    }
    debug!(
        phase = phase.name(),
        attempted = report.attempted,
        failed = report.failed,
        "best-effort phase complete"
    );
    report
}

/// Run a single command, feeding `stdin` if present and returning the full
/// `Output` so callers can parse stdout/stderr. Increments
/// [`ROUTING_SUBPROCESS_SPAWN_COUNT`] (the no-spawn invariant covers cover
/// engage too). Used by the macOS pf cover; not for route commands.
#[cfg(target_os = "macos")]
pub(crate) fn run_capturing<P: Phase>(
    cmd: &[String],
    stdin: Option<&[u8]>,
    phase: P,
) -> std::io::Result<std::process::Output> {
    use std::io::Write;
    use std::process::Stdio;
    debug_assert!(!cmd.is_empty(), "command must not be empty");
    ROUTING_SUBPROCESS_SPAWN_COUNT.fetch_add(1, Ordering::SeqCst);
    info!(phase = phase.name(), cmd = cmd.join(" "), "running cover command");
    let mut child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(bytes) = stdin {
        child.stdin.take().expect("piped stdin").write_all(bytes)?;
        // stdin dropped here -> EOF to the child.
    }
    child.wait_with_output()
}

// Crash recovery ======================================================================================================

/// Clean up routes left behind by a previous run.
///
/// Called at startup **after** the IPC socket bind succeeds (so a second
/// instance can't damage the first's routing state). Removes the fixed-CIDR
/// split routes (idempotent — harmless if absent); if a [`state::RouteState`]
/// file is present in `state_dir`, also removes the server bypass route
/// described by it; finally deletes the state file. Route errors are
/// best-effort and logged at `warn`.
///
/// Returns the standing-lockdown [`Recovery`] so the caller can record
/// "a standing cover is live this run" — the claim that keeps the escape
/// visible when the intent file cannot be read or repaired.
///
/// `owner` is the uid/gid every other bridge write into `state_dir` threads
/// (`SystemRouting::new`, `ProxyManager::set_lockdown_intent`). Recovery's
/// intent repair may CREATE both the directory and `bridge-lockdown.json` — a
/// wiped state dir is exactly the condition that produces the `Unset` intent —
/// so without it a user-scoped macOS bridge drops root-owned files into
/// `~/Library/Application Support/hole`.
///
/// `tun_name` is the caller's own configured TUN device name (the bridge's
/// `TUN_DEVICE_NAME` constant) — the fallback the TUN-permit reclaim uses when
/// no `bridge-routes.json` survived this startup to name one. See
/// [`recover_routes_with`]'s doc for why the file alone cannot be the only
/// source.
pub fn recover_routes(state_dir: &Path, owner: Option<(u32, u32)>, tun_name: &str) -> Recovery {
    let intent = failclosed::lockdown_state::load_intent(state_dir);
    recover_routes_with(
        state_dir,
        owner,
        tun_name,
        run_cleanup_commands,
        failclosed::recover_cover,
        intent,
        || failclosed::lockdown_cover_presence(state_dir),
        |decision, tun_name| failclosed::recover_lockdown(decision, state_dir, tun_name),
    )
}

/// What crash-recovery should do with a possibly-present standing lockdown
/// cover, given the recorded intent and what the OS says is installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverRecovery {
    /// A standing cover is live and nothing recorded says to remove it: KEEP
    /// the host fail-closed across the restart. Performs **no OS call that
    /// could clobber a RUNNING first bridge's cover** — its whole effect is
    /// that the bridge records "a standing cover is live this run", so the
    /// next connect re-engages through `install_lockdown`, which refreshes
    /// the volatile permits (the dead TUN LUID/utun and the possibly-changed
    /// server IP) itself.
    ///
    /// The one exception, Windows only: it also reclaims the volatile
    /// TUN-LUID permit pair when `hole-tun` no longer resolves — see
    /// `failclosed::reclaim_stale_tun_permit`. That is safe where deleting the
    /// server permit here is not: a genuinely running bridge's own `hole-tun`
    /// resolves successfully, so the reclaim can never touch a live bridge's
    /// permit, whereas the server IP has no equivalent liveness check.
    ///
    /// Disclosed cost of the remaining inertness: between an adopted cover and
    /// the next connect the stale server-IP permit stays installed rather than
    /// being dropped immediately (and, until `hole-tun` is confirmed gone, so
    /// does the TUN-LUID permit). Both are *permits* on an idle cover, and the
    /// App-ID permit already grants the bridge and plugin binaries unrestricted
    /// egress in that same window, so the added surface is one
    /// previously-configured server IP for other processes while nothing is
    /// connected. The alternative — deleting the server permit at recovery
    /// time — would let a second bridge with a fresh state dir delete a
    /// RUNNING first bridge's server permit while block-all stayed in force.
    ///
    /// This is also the crash-leak fix: a crash never runs `stop()`, so the
    /// persistent cover survives and Adopt holds it.
    Adopt,
    /// [`Intent::Off`](failclosed::lockdown_state::Intent::Off) with an
    /// actionable presence: fully disengage the leftover cover (Windows: delete
    /// all lockdown GUIDs; macOS: restore the pre-lockdown snapshot + drop the
    /// pf token). The only action that removes protection, and the only one
    /// that mutates the OS at all.
    Sweep,
    /// Nothing to do.
    Noop,
}

/// What the OS says about a standing lockdown cover — the presence axis of
/// [`decide_cover_recovery`]. Closed, because a bool made "the OS says no" and
/// "the OS could not answer" the same answer, and the second must never
/// authorise removing protection.
///
/// Each platform produces a strict subset:
///
/// - **Windows** produces `Live`, `Absent`, `Indeterminate`, `Unreachable`. It keeps no lockdown state file, so `Recorded` has no source there.
/// - **macOS** produces `Live`, `Recorded`, `Absent`, `Unreachable`. A `pfctl` that runs and prints a labels listing always yields a usable answer, so `Indeterminate` has no source there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverPresence {
    /// The OS confirmed Hole's own standing-lockdown cover, **or a residue of
    /// it**, is installed right now.
    ///
    /// "Any residue", not "the whole cover", is deliberate: the Windows sweeps
    /// loop delete-by-key over every lockdown GUID with no transaction and
    /// every return code discarded, over PERSISTENT filters. A sweep
    /// interrupted mid-loop survives a reboot as a partial cover, so probing
    /// one GUID would let that partial cover answer `Absent` forever. The probe
    /// asks about every swept GUID and `Live` means at least one was found.
    Live,
    /// The OS did not confirm one, but Hole's own state file says a cover was
    /// engaged and never confirmed released.
    Recorded,
    /// The OS was asked, answered no, and no local record contradicts it.
    Absent,
    /// The OS was reachable but its answer was unusable (Windows: a by-key
    /// query returned a code that is neither success nor "filter not found",
    /// e.g. a DACL-denied read).
    Indeterminate,
    /// The OS could not be asked at all (Windows: the Base Filtering Engine
    /// could not be reached; macOS: `pfctl` missing or non-executable with no
    /// state file to fall back on).
    Unreachable,
}

/// The outcome of [`decide_cover_recovery`]: one action, plus whether the
/// measured truth should be written back to the intent file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recovery {
    pub action: CoverRecovery,
    /// Repair the intent file to `enabled: true` before acting. Grounded in a
    /// positive OS measurement only — see rule 4.
    pub record_intent_on: bool,
    /// Echoes the `presence` this decision was made from. `action == Adopt`
    /// alone is not evidence the OS confirmed a live cover — it also covers
    /// [`CoverPresence::Recorded`] and [`CoverPresence::Indeterminate`], whose
    /// own docs say the OS did NOT confirm one. A caller recording "this run
    /// holds a live cover" (`route_recovery::recover_and_record`) must gate on
    /// `presence == CoverPresence::Live`, not on the action alone.
    pub presence: CoverPresence,
}

/// Pure recovery decision over the two measured axes. Performs **no I/O**: it
/// picks one [`CoverRecovery`], sets `record_intent_on`, and returns.
///
/// The four rules the table below encodes:
///
/// 1. [`CoverPresence::Absent`] and [`CoverPresence::Unreachable`] always yield `Noop` with `record_intent_on = false`.
/// 2. `Sweep` requires [`Intent::Off`](failclosed::lockdown_state::Intent::Off) and an actionable presence (`Live | Recorded | Indeterminate`). It is the only action that removes protection, and the only one that mutates the OS at all.
/// 3. `Adopt` requires an actionable presence and an intent of `On`, `Unreadable`, or `Unset` — with `Unset` additionally requiring positive evidence (`Live | Recorded`), because an unknown intent plus an unusable OS answer is no evidence in any direction.
/// 4. `record_intent_on` requires `Presence::Live` and an intent of `Unset` or `Unreadable`. The write is grounded in a positive OS measurement, never inferred.
///
/// The match is exhaustive on both axes with no wildcard, so a new variant of
/// either is a compile error rather than a silently inherited answer.
pub fn decide_cover_recovery(intent: failclosed::lockdown_state::Intent, presence: CoverPresence) -> Recovery {
    use failclosed::lockdown_state::Intent as I;
    use CoverPresence as P;
    use CoverRecovery::{Adopt, Noop, Sweep};

    let (action, record_intent_on) = match (intent, presence) {
        (I::On, P::Live) => (Adopt, false),
        (I::On, P::Recorded) => (Adopt, false),
        (I::On, P::Indeterminate) => (Adopt, false),
        (I::On, P::Absent) => (Noop, false),
        (I::On, P::Unreachable) => (Noop, false),

        (I::Off, P::Live) => (Sweep, false),
        (I::Off, P::Recorded) => (Sweep, false),
        (I::Off, P::Indeterminate) => (Sweep, false),
        (I::Off, P::Absent) => (Noop, false),
        (I::Off, P::Unreachable) => (Noop, false),

        (I::Unset, P::Live) => (Adopt, true),
        (I::Unset, P::Recorded) => (Adopt, false),
        // No intent AND no usable OS answer is no evidence in any direction.
        (I::Unset, P::Indeterminate) => (Noop, false),
        (I::Unset, P::Absent) => (Noop, false),
        (I::Unset, P::Unreachable) => (Noop, false),

        (I::Unreadable, P::Live) => (Adopt, true),
        (I::Unreadable, P::Recorded) => (Adopt, false),
        (I::Unreadable, P::Indeterminate) => (Adopt, false),
        (I::Unreadable, P::Absent) => (Noop, false),
        (I::Unreadable, P::Unreachable) => (Noop, false),
    };
    Recovery {
        action,
        record_intent_on,
        presence,
    }
}

/// Test seam for [`recover_routes`]: accepts an injected command runner, an
/// injected transient-cover sweep, and the standing-lockdown reconciliation
/// inputs (intent + presence probe + recover action) so unit tests can assert
/// behavior without shelling out to `netsh`/`route` or touching the host
/// firewall. Production passes [`run_cleanup_commands`], [`failclosed::recover_cover`],
/// the classified lockdown intent, [`failclosed::lockdown_cover_presence`], and
/// [`failclosed::recover_lockdown`]. `owner` is passed straight through to the
/// intent repair — see [`recover_routes`].
///
/// `tun_name` is the fallback TUN-permit-reclaim hint: `bridge-routes.json`'s
/// own `tun_name` wins when a route-state file was recovered THIS startup, but
/// that file's lifetime is anti-correlated with the condition the reclaim
/// needs — `SystemRoutes::drop` clears it on every CLEAN teardown, including
/// the `Cutover` stop that precedes the canonical Adopt path, so the file is
/// present exactly when the adapter probably still resolves and absent
/// exactly when it definitely does not. Falling back to the caller's own
/// configured name keeps the reclaim reachable on that path too; the resolve
/// check inside `should_reclaim_tun_permit` is what makes deleting on a
/// guessed name safe — a live `hole-tun` still blocks it.
#[allow(clippy::too_many_arguments)] // private test seam — bundling into a struct adds more noise than the warning.
pub(crate) fn recover_routes_with<R, S, P, L>(
    state_dir: &Path,
    owner: Option<(u32, u32)>,
    tun_name: &str,
    runner: R,
    sweep_cover: S,
    lockdown_intent: failclosed::lockdown_state::Intent,
    lockdown_present: P,
    lockdown_recover: L,
) -> Recovery
where
    R: Fn(&[Vec<String>], BestEffortPhase) -> CleanupReport,
    S: FnOnce(&Path, bool),
    P: FnOnce() -> CoverPresence,
    L: FnOnce(CoverRecovery, Option<&str>),
{
    info!(state_dir = %state_dir.display(), "starting route recovery");

    // Route recovery is guarded by the route-state file. Its absence means the
    // previous run installed no routes (the write-ordering contract persists
    // state BEFORE any route mutation), so we skip route teardown. Loaded once
    // and kept: its `tun_name` (when present) is also this bridge's own record
    // of which TUN device the standing lockdown cover, if any, was built for —
    // see the reclaim call below.
    //
    // State-file-driven recovery (not unconditional split-route teardown)
    // is required so concurrent bridge subprocesses don't rip routes out
    // from under each other: a SOCKS5-only bridge unconditionally issuing
    // `netsh delete route ... hole-tun` on startup would tear down the
    // routes of a concurrent TUN bridge mid-flight.
    let route_state = state::load(state_dir);
    if let Some(st) = &route_state {
        // Before the first `runner(...)`: the teardown argv carries the prior
        // run's server IP and `log_route_command` writes it out. Recovery has
        // no entry in hand, so the literal is armed under the fixed
        // `RECOVERED_TOKEN`; when the user reconnects to that same server,
        // last-wins arming re-points it at the entry's token and announces
        // the join, so a bundle reader can still join the two.
        util::redact::arm_ip(util::redact::RECOVERED_TOKEN, st.server_ip);
        info!(
            tun = %st.tun_name,
            server = util::redact::RECOVERED_TOKEN,
            server_family = util::redact::ip_family(st.server_ip),
            server_scope = util::redact::ip_scope(st.server_ip),
            iface = %st.interface_name,
            "recovering routes from crashed run"
        );

        // 1. Split routes (IPv4 + IPv6 halves). Idempotent — harmless if
        //    absent. Runs under state-file guard so this only fires when we
        //    have positive evidence of a prior route install. Uses the TUN
        //    name persisted in the state file (the caller controls this —
        //    tun-engine has no opinion on naming).
        let split_cmds = build_split_route_teardown_commands(&st.tun_name);
        let split = runner(&split_cmds, BestEffortPhase::RecoverSplit);

        // 2. Per-server bypass route recorded in the state file.
        let bypass_cmds = build_teardown_commands(&st.tun_name, st.server_ip, &st.interface_name);
        let bypass = runner(&bypass_cmds, BestEffortPhase::RecoverBypass);
        info!(?split, ?bypass, "route recovery command phases complete");

        // 3. Delete the state file regardless of command outcomes. Next
        //    startup re-runs the idempotent teardown if anything leaked
        //    past a failure.
        if let Err(e) = state::clear(state_dir) {
            warn!(error = %e, "failed to clear route-state file during recovery");
        }
    } else {
        debug!("no route-state file found, nothing to recover");
    }
    let tun_name_hint = route_state.map(|st| st.tun_name).unwrap_or_else(|| tun_name.to_owned());

    // Reconcile the standing lockdown cover FIRST. The presence is the
    // lockdown cover's OWN evidence (injected probe), NOT the route-state file,
    // whose lifetime is independent of the cover. Deciding/adopting before the
    // transient sweep means the subsequent sweep can be told a standing cover is
    // held and must not clobber it. The recover action keeps the host fail-closed
    // (Adopt) or disengages (Sweep).
    let presence = lockdown_present();
    let decision = decide_cover_recovery(lockdown_intent, presence);
    // Repair BEFORE acting, so a crash in between leaves an intent that reads
    // armed rather than one the next start would sweep on. A failed write costs
    // the persisted preference, never the action or the escape: this run's
    // adopted-cover claim carries the escape, and the bridge retries the write
    // the moment it honours that claim with a real cover install (see
    // `promote_adopted_claim`). Re-deriving it on a LATER start is not a
    // fallback — once the cover is torn down the measurement reads `Absent`.
    if decision.record_intent_on {
        if let Err(e) = failclosed::lockdown_state::set_enabled(state_dir, true, owner) {
            warn!(error = %e, "could not repair the lockdown intent over a measured live cover");
        }
    }
    let adopt = matches!(decision.action, CoverRecovery::Adopt);
    // `tun_name_hint` prefers THIS bridge's own last-known TUN device (from its
    // own `bridge-routes.json`) and falls back to the caller-supplied
    // `tun_name` otherwise — see this function's doc for why the file alone
    // is not a safe gate. `TUN_DEVICE_NAME` is a compile-time constant shared
    // by every install, so the fallback names the same device a different
    // install's cover would too; only the reclaim's server-IP counterpart is
    // scoped by the per-install identity gap CONTRIBUTING.md discloses
    // (#878), and this reclaim never touches that permit.
    lockdown_recover(decision.action, Some(tun_name_hint.as_str()));

    // Sweep any transient fail-closed cover left by a crashed update cutover.
    // Runs UNCONDITIONALLY (outside the route-state guard above): a crash can
    // leave a cover engaged with the routes already torn down, so there is no
    // bridge-routes.json, yet the cover persists. The cover is keyed
    // independently — Windows by fixed WFP GUIDs, macOS by bridge-failclosed.json
    // — and the sweep is idempotent when no cover is present. When a standing
    // lockdown cover is being adopted, the sweep must leave the lockdown ruleset
    // untouched (macOS: skip the `pfctl -f /etc/pf.conf` reload that would wipe
    // it) — passed as `adopt`. Note this is `adopt`, NOT the raw presence: on a
    // Sweep (intent off, cover present) the standing ruleset is being torn down,
    // so the transient restore SHOULD run.
    sweep_cover(state_dir, adopt);

    decision
}

// Routing trait =======================================================================================================

/// A cover RAII guard that can be DISARMED — consumed without disengaging — so
/// the persistent WFP/pf filters survive a cutover restart; the new bridge
/// re-adopts them via `decide_cover_recovery == Adopt`. A trait (not an inherent
/// method) because `RunningState.lockdown` holds the cover behind the
/// `Routing::Cover` associated type, and an inherent method is not callable
/// through that type parameter.
pub trait CoverGuard {
    /// Persist the underlying filters without disengaging: consume the guard so
    /// its `Drop` (the disengage) never runs.
    ///
    /// PRECONDITION: call only immediately before process exit. Skipping `Drop`
    /// also skips releasing the guard's other resources (e.g. the Windows WFP
    /// engine handle), which the kernel reclaims on exit but which a long-lived
    /// caller would leak per call.
    fn disarm(self);
}

/// OS routing: install split-tunnel routes and query routing state.
///
/// # Test-isolation contract
///
/// **All production I/O that mutates or queries the host's routing tables
/// MUST route through this trait.** Helper types whose `Drop` impls tear
/// down routes must do so through the associated [`Installed`](Self::Installed)
/// type's Drop, not by calling [`teardown_routes`] directly. The only
/// legitimate call sites of the free functions are inside this module:
/// [`SystemRouting::install`] and [`SystemRoutes::drop`] for the
/// install/teardown path, and [`recover_routes`] / [`recover_routes_with`]
/// for crash recovery.
///
/// The motivation is test isolation. Consumers (e.g. `hole_bridge::ProxyManager`)
/// are generic over `R: Routing` so unit tests can substitute a mock whose
/// `Installed` type counts teardown invocations. A helper that bypasses the
/// trait cannot be intercepted by the mock and will exercise real production
/// code from unit tests. See the bindreams/hole#165 incident.
pub trait Routing: Send + Sync {
    /// RAII guard returned by [`install`](Self::install). Dropping this
    /// value tears down the routes and clears the crash-recovery state
    /// file. The real implementation ([`SystemRoutes`]) calls
    /// [`teardown_routes`]; a mock implementation increments a counter.
    /// No production code outside `SystemRoutes` calls the free teardown
    /// function.
    type Installed: Send;

    /// Install the split routes for the given TUN device and upstream
    /// gateway. On success, returns an RAII guard whose Drop tears down
    /// the routes and clears the recovery state file. On failure, the
    /// implementation must leave the host in the pre-install state
    /// (no stale state file, no partially-installed routes).
    ///
    /// Takes the whole [`GatewayInfo`] that [`default_gateway`](Self::default_gateway)
    /// returned (not destructured fields): `gateway_ip`/`interface_name` build
    /// the server bypass route. IPv6 split-route fatality is decided
    /// separately, from the TUN's own IPv6 binding, not from anything on this
    /// struct — see [`SetupCommand`].
    fn install(
        &self,
        tun_name: &str,
        server_ip: IpAddr,
        gateway: &GatewayInfo,
    ) -> Result<Self::Installed, RoutingError>;

    /// Returns the current default gateway that the *next* call to
    /// [`install`](Self::install) will bypass the tunnel through.
    /// Lives on the trait (not as a free function) so mocks can stub a
    /// predictable gateway without calling the real OS — without this
    /// seam, every consumer unit test would depend on the host having a
    /// route to the Internet.
    fn default_gateway(&self) -> Result<GatewayInfo, RoutingError>;

    /// RAII guard returned by [`install_failclosed_cover`](Self::install_failclosed_cover).
    /// Dropping it disengages the fail-closed cover. `Send` so a cutover
    /// coordinator can hold it across `.await`; [`CoverGuard`] so a cutover stop
    /// can disarm it (persist-without-disengage).
    type Cover: Send + CoverGuard;

    /// Engage a fail-closed cover: block all egress except loopback, `server_ip`,
    /// and (when `Some`) `resolver_ip` — the address the caller's own
    /// `ech-doh` URL names (`hole_bridge::dns::ech::EchDoh::resolver`), scoped
    /// to TCP/443 (see `crate::dns::ech::DOH_PORT`). The caller authors that
    /// URL from its own configured resolver set, so config-authorship trust
    /// alone is judged sufficient — permitting it is never a claim that this
    /// exact attempt personally dialed the address (see `EchDoh`'s doc: that
    /// additionally holds for some `PinSource` variants but not all). `None`
    /// covers every case where nothing should be permitted: no plugin
    /// configured, a non-ECH-capable plugin, malformed plugin options, or an
    /// OPERATOR's own `ech-doh` winning instead of Hole's (an address Hole
    /// did not author, so the config-authorship trust does not extend to it
    /// — a disclosed residual, see CONTRIBUTING.md). `None` is never
    /// permitted as "no restriction". See CONTRIBUTING.md's "Transient
    /// cutover cover" section for the full retry-repair state machine (a
    /// resolver drift releases and re-engages the cover with the corrected
    /// value) and the disclosed residuals this trait's caller does not
    /// close.
    ///
    /// The cover survives a process crash (Windows: persistent WFP filters keyed by fixed
    /// GUID; macOS: pf enable token persisted to `bridge-failclosed.json`) and is
    /// swept by [`recover_routes`] on the next start. Does NOT permit the TUN
    /// interface — the block-until-connected connect gate holds it only until the
    /// tunnel comes up.
    fn install_failclosed_cover(
        &self,
        server_ip: IpAddr,
        resolver_ip: Option<IpAddr>,
    ) -> Result<Self::Cover, RoutingError>;

    /// Engage the STANDING lockdown cover for this connected session: permit
    /// loopback + the `tun_name` interface + the onward server connection (and,
    /// on Windows, the `app_ids` binaries by App-ID), block all else. Returns
    /// the SAME [`Cover`](Self::Cover) RAII guard
    /// [`install_failclosed_cover`](Self::install_failclosed_cover) returns —
    /// the platform guard is kind-aware, so its Drop disengages whichever cover
    /// it holds. Distinct from `install_failclosed_cover`, which does NOT permit
    /// the TUN. The LUID is re-resolved on every call (never persisted).
    /// Fail-FATAL: the bridge aborts the start on Err.
    fn install_lockdown(
        &self,
        server_ip: IpAddr,
        tun_name: &str,
        app_ids: &[PathBuf],
    ) -> Result<Self::Cover, RoutingError>;

    /// Clear every fail-closed cover this provider can install — both the
    /// transient block-until-connected cover and the standing lockdown cover
    /// — without asking whether either is present. See
    /// [`failclosed::release_all`] for the full contract. This is the escape
    /// from a stranded cover; a required method (no default) so every
    /// `Routing` implementation, including every test mock, commits to one.
    fn release_all_covers(&self) -> Result<(), RoutingError>;
}

// System (production) routing =========================================================================================

/// Production implementation of [`Routing`]. Calls `setup_routes` /
/// `teardown_routes` (which shell out to `netsh`/`route`) and owns the
/// `state_dir` where `bridge-routes.json` lives for crash recovery.
pub struct SystemRouting {
    state_dir: PathBuf,
    /// uid/gid to chown persisted state files to (an elevated user-scoped run
    /// hands the real user here); `None` leaves ownership as-is.
    owner: Option<(u32, u32)>,
}

impl SystemRouting {
    pub fn new(state_dir: PathBuf, owner: Option<(u32, u32)>) -> Self {
        Self { state_dir, owner }
    }

    /// Test seam for [`Routing::install`]: injectable setup and teardown so unit
    /// tests can drive the failure path without issuing real route commands
    /// (#165). Production passes [`setup_routes`] / [`teardown_routes`].
    ///
    /// # What the failure path does
    ///
    /// A partially-installed route set is a real state — `setup` is not
    /// transactional. When it reports a failed command this does exactly four
    /// things, and nothing else:
    ///
    /// 1. issues no further setup commands (`setup` already stopped at the
    ///    first failure, so route mutation ends there);
    /// 2. runs the COMPLETE teardown command set, every command attempted
    ///    regardless of the others' outcomes, deleting whatever did install —
    ///    most of those deletes are expected to exit non-zero, because the
    ///    route they name was never added;
    /// 3. clears the persisted route-state file, so the next start's
    ///    crash-recovery sweep is not handed a run that left nothing behind;
    /// 4. returns `Err(RoutingError::RouteSetup)`. No [`SystemRoutes`] guard is
    ///    constructed, so no caller can report the tunnel up.
    fn install_with<S, T>(
        &self,
        tun_name: &str,
        server_ip: IpAddr,
        gateway: &GatewayInfo,
        setup: S,
        teardown: T,
    ) -> Result<SystemRoutes, RoutingError>
    where
        S: FnOnce(&str, IpAddr, &GatewayInfo) -> Result<(), RouteCommandError>,
        T: FnOnce(&str, IpAddr, &str) -> CleanupReport,
    {
        let interface_name = gateway.interface_name.as_str();
        // CRITICAL ORDERING: persist the route-recovery state BEFORE any
        // routing mutation. A panic or SIGKILL between the setup phase and
        // `SystemRoutes` construction would otherwise leak routes with no
        // on-disk record, defeating crash recovery on next startup.
        let persisted = state::RouteState {
            version: state::SCHEMA_VERSION,
            tun_name: tun_name.to_owned(),
            server_ip,
            interface_name: interface_name.to_owned(),
        };
        state::save(&self.state_dir, &persisted, self.owner)
            .map_err(|e| RoutingError::RouteSetup(format!("failed to persist route-state: {e}")))?;

        if let Err(e) = setup(tun_name, server_ip, gateway) {
            warn!(error = %e, "route setup failed — rolling back");
            let rollback = teardown(tun_name, server_ip, interface_name);
            if let Err(ce) = state::clear(&self.state_dir) {
                warn!(error = %ce, "state-file clear failed during setup rollback");
            }
            info!(?rollback, "route setup rolled back — reporting the tunnel DOWN");
            return Err(RoutingError::RouteSetup(e.to_string()));
        }

        Ok(SystemRoutes {
            tun_name: tun_name.to_owned(),
            server_ip,
            interface_name: interface_name.to_owned(),
            state_dir: self.state_dir.clone(),
        })
    }
}

impl Routing for SystemRouting {
    type Installed = SystemRoutes;
    type Cover = failclosed::Cover;

    // `setup_routes`/`teardown_routes` are handed to `install_with` as the
    // production runners: this IS the `Routing` impl (#165).
    #[allow(clippy::disallowed_methods)]
    fn install(
        &self,
        tun_name: &str,
        server_ip: IpAddr,
        gateway: &GatewayInfo,
    ) -> Result<Self::Installed, RoutingError> {
        self.install_with(tun_name, server_ip, gateway, setup_routes, teardown_routes)
    }

    fn default_gateway(&self) -> Result<GatewayInfo, RoutingError> {
        get_default_gateway_info().map_err(|e| RoutingError::Gateway(e.to_string()))
    }

    fn install_failclosed_cover(
        &self,
        server_ip: IpAddr,
        resolver_ip: Option<IpAddr>,
    ) -> Result<Self::Cover, RoutingError> {
        failclosed::engage(server_ip, resolver_ip, &self.state_dir, self.owner)
    }

    fn install_lockdown(
        &self,
        server_ip: IpAddr,
        tun_name: &str,
        app_ids: &[PathBuf],
    ) -> Result<Self::Cover, RoutingError> {
        let resolver = failclosed::SystemLuidResolver;
        failclosed::engage_lockdown(server_ip, tun_name, &resolver, app_ids, &self.state_dir, self.owner)
    }

    fn release_all_covers(&self) -> Result<(), RoutingError> {
        failclosed::release_all(&self.state_dir)
    }
}

/// RAII guard returned by [`SystemRouting::install`]. Dropping this value
/// tears down the installed routes and clears the crash-recovery state
/// file. Teardown routes through the `Routing` trait, never a raw
/// free-function `netsh` call.
pub struct SystemRoutes {
    tun_name: String,
    server_ip: IpAddr,
    interface_name: String,
    state_dir: PathBuf,
}

impl Drop for SystemRoutes {
    fn drop(&mut self) {
        // Unconditional entry log so a reader can confirm this Drop
        // actually ran on Stop (teardown-skipped diagnosis).
        info!(
            tun = %self.tun_name,
            server_family = util::redact::ip_family(self.server_ip),
            server_scope = util::redact::ip_scope(self.server_ip),
            iface = %self.interface_name,
            "SystemRoutes::drop entered — tearing down routes"
        );
        #[allow(clippy::disallowed_methods)] // SystemRoutes IS Routing::Installed
        let report = teardown_routes(&self.tun_name, self.server_ip, &self.interface_name);
        info!(?report, "route teardown complete");
        // Always clear the state file — we only need it for *crash*
        // recovery, and reaching Drop means we took the normal shutdown
        // path. Per-command failures above are already logged; a stale
        // state file on the next run would just trigger an idempotent
        // no-op teardown during recover_routes, so clearing is safe.
        if let Err(e) = state::clear(&self.state_dir) {
            warn!(error = %e, "state-file clear failed in SystemRoutes::drop");
        }
        // Belt-and-suspenders post-teardown wintun adapter cleanup.
        // `bridge::Dispatcher::drop` synchronously drains the engine task
        // so wintun's own Drop runs; this is the safety net for paths that
        // bypass it (panic, current-thread runtime tests, Drop 2s-timeout
        // fallback). PowerShell `Remove-NetAdapter` is idempotent on
        // missing adapters. See adapter_cleanup docs.
        crate::adapter_cleanup::remove_adapter(&self.tun_name);
        // Note: WFP/NDIS post-teardown snapshots live in bridge's Stop
        // path, not here — tun-engine can't depend on the bridge's
        // diagnostics module.

        info!("SystemRoutes::drop completed");
    }
}

// Platform-specific command builders ==================================================================================

#[cfg(target_os = "windows")]
fn platform_setup_commands(
    tun_name: &str,
    server_ip: IpAddr,
    gateway: &GatewayInfo,
    tun_ipv6_available: bool,
) -> Vec<SetupCommand> {
    let ipv6 = tun_ipv6_available;
    let mut cmds = vec![
        // IPv4 low half: 0.0.0.0/1 via TUN
        SetupCommand::fatal(vec![
            "netsh".into(),
            "interface".into(),
            "ip".into(),
            "add".into(),
            "route".into(),
            "0.0.0.0/1".into(),
            tun_name.into(),
        ]),
        // IPv4 high half: 128.0.0.0/1 via TUN
        SetupCommand::fatal(vec![
            "netsh".into(),
            "interface".into(),
            "ip".into(),
            "add".into(),
            "route".into(),
            "128.0.0.0/1".into(),
            tun_name.into(),
        ]),
        // IPv6 low half: ::/1 via TUN
        SetupCommand {
            argv: vec![
                "netsh".into(),
                "interface".into(),
                "ipv6".into(),
                "add".into(),
                "route".into(),
                "::/1".into(),
                tun_name.into(),
            ],
            fatal: ipv6,
        },
        // IPv6 high half: 8000::/1 via TUN
        SetupCommand {
            argv: vec![
                "netsh".into(),
                "interface".into(),
                "ipv6".into(),
                "add".into(),
                "route".into(),
                "8000::/1".into(),
                tun_name.into(),
            ],
            fatal: ipv6,
        },
    ];

    // Bypass: server IP via original gateway/interface. Skipped for loopback —
    // see `build_setup_commands` (loopback is on-link, a gateway bypass would
    // hijack it).
    if !server_ip.to_canonical().is_loopback() {
        let original_gateway = gateway.gateway_ip;
        match server_ip {
            IpAddr::V4(_) => cmds.push(SetupCommand::fatal(vec![
                "route".into(),
                "add".into(),
                format!("{server_ip}"),
                "mask".into(),
                "255.255.255.255".into(),
                format!("{original_gateway}"),
            ])),
            IpAddr::V6(_) => cmds.push(SetupCommand::fatal(vec![
                "netsh".into(),
                "interface".into(),
                "ipv6".into(),
                "add".into(),
                "route".into(),
                format!("{server_ip}/128"),
                gateway.interface_name.clone(),
            ])),
        }
    }

    cmds
}

#[cfg(target_os = "windows")]
fn platform_teardown_commands(tun_name: &str, server_ip: IpAddr, interface_name: &str) -> Vec<Vec<String>> {
    let mut cmds = vec![
        vec![
            "netsh".into(),
            "interface".into(),
            "ip".into(),
            "delete".into(),
            "route".into(),
            "0.0.0.0/1".into(),
            tun_name.into(),
        ],
        vec![
            "netsh".into(),
            "interface".into(),
            "ip".into(),
            "delete".into(),
            "route".into(),
            "128.0.0.0/1".into(),
            tun_name.into(),
        ],
        vec![
            "netsh".into(),
            "interface".into(),
            "ipv6".into(),
            "delete".into(),
            "route".into(),
            "::/1".into(),
            tun_name.into(),
        ],
        vec![
            "netsh".into(),
            "interface".into(),
            "ipv6".into(),
            "delete".into(),
            "route".into(),
            "8000::/1".into(),
            tun_name.into(),
        ],
    ];

    // No bypass was installed for a loopback server, so none to delete.
    if !server_ip.to_canonical().is_loopback() {
        match server_ip {
            IpAddr::V4(_) => cmds.push(vec![
                "route".into(),
                "delete".into(),
                format!("{server_ip}"),
                "mask".into(),
                "255.255.255.255".into(),
            ]),
            IpAddr::V6(_) => cmds.push(vec![
                "netsh".into(),
                "interface".into(),
                "ipv6".into(),
                "delete".into(),
                "route".into(),
                format!("{server_ip}/128"),
                interface_name.into(),
            ]),
        }
    }

    cmds
}

#[cfg(target_os = "macos")]
fn platform_setup_commands(
    tun_name: &str,
    server_ip: IpAddr,
    gateway: &GatewayInfo,
    tun_ipv6_available: bool,
) -> Vec<SetupCommand> {
    let ipv6 = tun_ipv6_available;
    let mut cmds = vec![
        // IPv4 low half: 0.0.0.0/1 via TUN
        SetupCommand::fatal(vec![
            "route".into(),
            "-n".into(),
            "add".into(),
            "-net".into(),
            "0.0.0.0/1".into(),
            "-interface".into(),
            tun_name.into(),
        ]),
        // IPv4 high half: 128.0.0.0/1 via TUN
        SetupCommand::fatal(vec![
            "route".into(),
            "-n".into(),
            "add".into(),
            "-net".into(),
            "128.0.0.0/1".into(),
            "-interface".into(),
            tun_name.into(),
        ]),
        // IPv6 low half: ::/1 via TUN
        SetupCommand {
            argv: vec![
                "route".into(),
                "-n".into(),
                "add".into(),
                "-inet6".into(),
                "::/1".into(),
                "-interface".into(),
                tun_name.into(),
            ],
            fatal: ipv6,
        },
        // IPv6 high half: 8000::/1 via TUN
        SetupCommand {
            argv: vec![
                "route".into(),
                "-n".into(),
                "add".into(),
                "-inet6".into(),
                "8000::/1".into(),
                "-interface".into(),
                tun_name.into(),
            ],
            fatal: ipv6,
        },
    ];

    // Bypass: server IP via original gateway/interface. Skipped for loopback —
    // see `build_setup_commands` (loopback is on-link, a gateway bypass would
    // hijack it).
    if !server_ip.to_canonical().is_loopback() {
        let original_gateway = gateway.gateway_ip;
        match server_ip {
            IpAddr::V4(_) => cmds.push(SetupCommand::fatal(vec![
                "route".into(),
                "-n".into(),
                "add".into(),
                "-host".into(),
                format!("{server_ip}"),
                format!("{original_gateway}"),
            ])),
            IpAddr::V6(_) => cmds.push(SetupCommand::fatal(vec![
                "route".into(),
                "-n".into(),
                "add".into(),
                "-inet6".into(),
                "-host".into(),
                format!("{server_ip}"),
                "-interface".into(),
                gateway.interface_name.clone(),
            ])),
        }
    }

    cmds
}

#[cfg(target_os = "macos")]
fn platform_teardown_commands(_tun_name: &str, server_ip: IpAddr, _interface_name: &str) -> Vec<Vec<String>> {
    let mut cmds = vec![
        vec![
            "route".into(),
            "-n".into(),
            "delete".into(),
            "-net".into(),
            "0.0.0.0/1".into(),
        ],
        vec![
            "route".into(),
            "-n".into(),
            "delete".into(),
            "-net".into(),
            "128.0.0.0/1".into(),
        ],
        vec![
            "route".into(),
            "-n".into(),
            "delete".into(),
            "-inet6".into(),
            "::/1".into(),
        ],
        vec![
            "route".into(),
            "-n".into(),
            "delete".into(),
            "-inet6".into(),
            "8000::/1".into(),
        ],
    ];

    // No bypass was installed for a loopback server, so none to delete.
    if !server_ip.to_canonical().is_loopback() {
        match server_ip {
            IpAddr::V4(_) => cmds.push(vec![
                "route".into(),
                "-n".into(),
                "delete".into(),
                "-host".into(),
                format!("{server_ip}"),
            ]),
            IpAddr::V6(_) => cmds.push(vec![
                "route".into(),
                "-n".into(),
                "delete".into(),
                "-inet6".into(),
                "-host".into(),
                format!("{server_ip}"),
            ]),
        }
    }

    cmds
}

#[cfg(target_os = "windows")]
fn platform_split_route_teardown_commands(tun_name: &str) -> Vec<Vec<String>> {
    vec![
        vec![
            "netsh".into(),
            "interface".into(),
            "ip".into(),
            "delete".into(),
            "route".into(),
            "0.0.0.0/1".into(),
            tun_name.into(),
        ],
        vec![
            "netsh".into(),
            "interface".into(),
            "ip".into(),
            "delete".into(),
            "route".into(),
            "128.0.0.0/1".into(),
            tun_name.into(),
        ],
        vec![
            "netsh".into(),
            "interface".into(),
            "ipv6".into(),
            "delete".into(),
            "route".into(),
            "::/1".into(),
            tun_name.into(),
        ],
        vec![
            "netsh".into(),
            "interface".into(),
            "ipv6".into(),
            "delete".into(),
            "route".into(),
            "8000::/1".into(),
            tun_name.into(),
        ],
    ]
}

#[cfg(target_os = "macos")]
fn platform_split_route_teardown_commands(_tun_name: &str) -> Vec<Vec<String>> {
    vec![
        vec![
            "route".into(),
            "-n".into(),
            "delete".into(),
            "-net".into(),
            "0.0.0.0/1".into(),
        ],
        vec![
            "route".into(),
            "-n".into(),
            "delete".into(),
            "-net".into(),
            "128.0.0.0/1".into(),
        ],
        vec![
            "route".into(),
            "-n".into(),
            "delete".into(),
            "-inet6".into(),
            "::/1".into(),
        ],
        vec![
            "route".into(),
            "-n".into(),
            "delete".into(),
            "-inet6".into(),
            "8000::/1".into(),
        ],
    ]
}

#[cfg(test)]
#[path = "routing_tests.rs"]
mod routing_tests;
