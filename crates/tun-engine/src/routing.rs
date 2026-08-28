//! Route table management — platform-specific split routing.

pub mod failclosed;
pub mod state;

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::error::RoutingError;
use crate::gateway::{get_default_gateway_info, GatewayInfo};

/// Total number of routing subprocess spawns this process has performed.
/// Incremented once per command in [`run_one_output`]. Exposed so
/// `diagnostics` handlers and tests can assert the no-routing-subprocess
/// invariant. The one-instruction `fetch_add` has negligible production
/// cost — far below the millisecond-scale subprocess itself.
pub static ROUTING_SUBPROCESS_SPAWN_COUNT: AtomicU32 = AtomicU32::new(0);

// Route identity ======================================================================================================

/// One of the routes an install creates. Recorded in [`state::RouteState`] so
/// teardown and crash recovery delete only the routes this run actually
/// installed — the only selectivity handle available, since no delete-side
/// qualifier can express "only if it is ours" (see CONTRIBUTING's
/// [Route ownership](../../../CONTRIBUTING.md#route-ownership) section) and
/// provenance is also the only handle that outlives the interface a crashed
/// or stopped run's utun took with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RouteId {
    /// `0.0.0.0/1` via the TUN — first half of IPv4 space.
    SplitV4Low,
    /// `128.0.0.0/1` via the TUN — second half of IPv4 space.
    SplitV4High,
    /// `::/1` via the TUN — first half of IPv6 space.
    SplitV6Low,
    /// `8000::/1` via the TUN — second half of IPv6 space.
    SplitV6High,
    /// Host route reaching the proxy server outside the tunnel.
    ServerBypass,
}

/// The four fixed split routes, in install order.
pub const SPLIT_ROUTES: [RouteId; 4] = [
    RouteId::SplitV4Low,
    RouteId::SplitV4High,
    RouteId::SplitV6Low,
    RouteId::SplitV6High,
];

/// The routes an install for `server_ip` attempts, in command order. The
/// server bypass is omitted for a loopback server — see
/// [`build_setup_commands`].
pub fn planned_routes(server_ip: IpAddr) -> Vec<RouteId> {
    let mut ids = SPLIT_ROUTES.to_vec();
    if !server_ip.to_canonical().is_loopback() {
        ids.push(RouteId::ServerBypass);
    }
    ids
}

/// A route command tagged with the route it acts on, so a setup command's
/// exit status can be recorded against the teardown command that undoes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCommand {
    pub id: RouteId,
    pub argv: Vec<String>,
}

impl RouteCommand {
    fn new(id: RouteId, argv: Vec<String>) -> Self {
        Self { id, argv }
    }
}

/// Drop the commands for routes absent from `installed` and hand back bare
/// argv. Deleting a route this run did not install is never cleanup: the
/// routing table holds one entry per key, so if the entry is not ours, ours
/// is already gone and the delete can only remove someone else's. Test-only:
/// production builds the same filter inline (see `teardown_routes`,
/// `recover_routes_with`) so it can keep the [`RouteId`] tag for checkpointing.
#[cfg(test)]
fn retain_installed(cmds: Vec<RouteCommand>, installed: &[RouteId]) -> Vec<Vec<String>> {
    cmds.into_iter()
        .filter(|c| installed.contains(&c.id))
        .map(|c| c.argv)
        .collect()
}

// Command builders ====================================================================================================

/// Build the shell commands to set up split routing.
///
/// Creates four or five routes:
/// 1. `0.0.0.0/1` via TUN — captures first half of IPv4 space
/// 2. `128.0.0.0/1` via TUN — captures second half of IPv4 space
/// 3. `::/1` via TUN — captures first half of IPv6 space
/// 4. `8000::/1` via TUN — captures second half of IPv6 space
/// 5. Server bypass — `<server_ip>` via `original_gateway` (IPv4 server) or `interface_name` (IPv6 server)
///
/// The server bypass (#5) is omitted when `server_ip` is loopback (checked in
/// canonical form, so an IPv4-mapped `::ffff:127.0.0.1` counts too): a loopback
/// destination is reached via the kernel's on-link `127.0.0.0/8` route, which is
/// more specific than the `/1` splits, so it needs no bypass — and a `/32` (or
/// `/128`) gateway bypass for loopback would hijack all loopback traffic to a
/// gateway that cannot reach it.
///
/// When `server_ip` is IPv6, `original_gateway` is unused — the bypass route is interface-based
/// because reliable IPv6 gateway detection is not available on all platforms.
pub fn build_setup_commands(
    tun_name: &str,
    server_ip: IpAddr,
    original_gateway: IpAddr,
    interface_name: &str,
) -> Vec<RouteCommand> {
    let cmds = platform_setup_commands(tun_name, server_ip, original_gateway, interface_name);
    debug_assert_eq!(
        cmds.iter().map(|c| c.id).collect::<Vec<_>>(),
        planned_routes(server_ip),
        "setup commands must match planned_routes — the state file records the latter before the former runs"
    );
    cmds
}

/// Build the shell commands to tear down split routing (IPv4 + IPv6 splits and
/// server bypass), for the subset of routes `installed` says this run created.
/// Test-only argv-shape helper — see [`retain_installed`].
#[cfg(test)]
pub(crate) fn build_teardown_commands(
    tun_name: &str,
    server_ip: IpAddr,
    interface_name: &str,
    installed: &[RouteId],
) -> Vec<Vec<String>> {
    let mut cmds = platform_split_teardown_commands(tun_name);
    cmds.extend(platform_bypass_teardown_command(server_ip, interface_name));
    retain_installed(cmds, installed)
}

/// The split-route half of [`build_teardown_commands`] — crash recovery runs
/// it separately from the bypass so the two get distinct phase tags.
/// Test-only argv-shape helper — see [`retain_installed`].
#[cfg(test)]
pub(crate) fn build_split_route_teardown_commands(tun_name: &str, installed: &[RouteId]) -> Vec<Vec<String>> {
    retain_installed(platform_split_teardown_commands(tun_name), installed)
}

// Execution ===========================================================================================================

// Phase tags used for structured logging and to classify expected failures.
// `is_recovery_phase` is the single source of truth for which phases are
// best-effort cleanup; adding a new `PHASE_RECOVER_*` here MUST be paired
// with a matching arm in `is_recovery_phase`.
pub(crate) const PHASE_SETUP: &str = "setup";
pub(crate) const PHASE_TEARDOWN: &str = "teardown";
pub(crate) const PHASE_RECOVER_SPLIT: &str = "recover-split";
pub(crate) const PHASE_RECOVER_BYPASS: &str = "recover-bypass";
pub(crate) const PHASE_RECOVER_COVER: &str = "recover-cover";
// macOS-only: the pf cover engages via `pfctl` subprocesses (Windows engages
// via FWPM FFI — no subprocess phase). Gated so it is not dead code on a
// non-test Windows lib build under `-D warnings`. `PHASE_RECOVER_COVER` stays
// all-targets because `is_recovery_phase` references it on every platform.
#[cfg(target_os = "macos")]
pub(crate) const PHASE_COVER: &str = "cover-engage";

/// Returns true if route command failures during this phase are *expected*
/// idempotent-cleanup behavior and should be logged at debug, not warn.
///
/// **Recovery** is best-effort: every clean startup tries to delete the four
/// fixed split routes, and on a healthy system all four of those calls fail
/// because nothing leaked.
///
/// **Teardown** is also best-effort: a delete this run's own provenance
/// record says should succeed can still race a concurrent actor (see
/// CONTRIBUTING's [Route ownership](../../../CONTRIBUTING.md#route-ownership)
/// section), and `run_teardown_commands` already narrows what it deletes to
/// the recorded [`RouteId`]s, so a non-zero exit here is cleanup noise, not
/// investigation material.
///
/// Adding a new `PHASE_*` constant that should silently tolerate non-zero
/// exit codes MUST be paired with a matching arm here.
fn is_recovery_phase(phase: &str) -> bool {
    matches!(
        phase,
        PHASE_RECOVER_SPLIT | PHASE_RECOVER_BYPASS | PHASE_TEARDOWN | PHASE_RECOVER_COVER
    )
}

// Success oracle ======================================================================================================
//
// route(8) on macOS exits 0 unconditionally for K_ADD/K_DELETE/K_CHANGE once
// `newroute()` returns at all (`network_cmds/route.tproj/route.c`'s dispatch
// in `main()`) — `output.status.success()` cannot tell "this route is now
// installed/gone" from "route(8) ran and printed a failure". The one
// deterministic signal is textual: `rtmsg()`'s only failure path is the
// routing-socket `write()` returning < 0, reported via
// `warnx("writing to routing socket: %s", route_strerror(errno))` on stderr
// — verified against Apple's current sources. `route_strerror` maps `ESRCH`
// (no such route) to the literal string "not in table"; every other errno
// (EEXIST, EBUSY, ENOBUFS, ...) means the routing table still disagrees with
// what we asked for. `getaddr()`'s own `errx`/`exit` aborts (unresolvable
// name) happen before `rtmsg()` runs and DO surface as a non-zero exit, so
// both signals are checked. Windows' `route.exe`/`netsh` exit non-zero on
// failure (verified empirically for add and delete), so no parsing is needed
// there.

/// True if macOS `route(8)`'s own text confirms the mutation went through —
/// used by [`run_one`] to decide whether a route actually went into the
/// table, and by `test_utils::route::OwnedRoute` (same route(8) exit-0
/// problem applies to the test harness's own probe routes). Compiled outside
/// macOS too — under `cfg(test)` so the parsing logic is unit-testable on
/// every host, and under `feature = "test-utils"` for `OwnedRoute`'s
/// cross-platform `cfg!()` branch — not only where it is actually wired up.
#[cfg(any(target_os = "macos", test, feature = "test-utils"))]
pub(crate) fn macos_route_command_succeeded(output: &std::process::Output) -> bool {
    output.status.success() && !String::from_utf8_lossy(&output.stderr).contains("writing to routing socket")
}

/// True if macOS `route(8)`'s own text confirms the route is now gone — used
/// by [`run_one_teardown`] to decide whether a delete may be dropped from the
/// persisted record, and by `test_utils::route::OwnedRoute`'s `Drop`.
/// Distinct from [`macos_route_command_succeeded`]: a delete that failed
/// because there was nothing to delete (`ESRCH`, printed as `"not in
/// table"`) still means the route is gone and may be dropped: any OTHER
/// failure text means the route is still there and must stay recorded.
///
/// `status.success()` is checked but NOT used to short-circuit to `true`:
/// route(8) exits 0 for K_DELETE whenever `newroute()` returns at all
/// (`rtmsg()`'s failure text still prints), so treating a bare exit-0 as
/// proof of absence would defeat the whole point of this function.
#[cfg(any(target_os = "macos", test, feature = "test-utils"))]
pub(crate) fn macos_route_confirmed_absent(output: &std::process::Output) -> bool {
    if !output.status.success() {
        // getaddr() aborted before rtmsg() ever ran — the command never
        // reached the kernel, so the route's fate is unchanged.
        return false;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("writing to routing socket") {
        return true; // no failure signal at all -> genuinely deleted
    }
    stderr.contains("writing to routing socket: not in table")
}

#[cfg(target_os = "macos")]
fn route_command_installed(output: &std::process::Output) -> bool {
    macos_route_command_succeeded(output)
}
#[cfg(not(target_os = "macos"))]
fn route_command_installed(output: &std::process::Output) -> bool {
    output.status.success()
}

#[cfg(target_os = "macos")]
fn route_confirmed_absent(output: &std::process::Output) -> bool {
    macos_route_confirmed_absent(output)
}
// A non-zero exit on Windows already means "already gone" — see
// `is_recovery_phase`'s doc — so no separate text parsing is needed there.
#[cfg(not(target_os = "macos"))]
fn route_confirmed_absent(_output: &std::process::Output) -> bool {
    true
}

/// Spawn one route command and log its outcome, handing back the raw
/// `Output` so [`run_one`] and [`run_one_teardown`] can each apply their own
/// success predicate to it. `recovery` selects the failure log level — see
/// [`is_recovery_phase`].
fn run_one_output(cmd: &[String], phase: &str, recovery: bool) -> std::io::Result<std::process::Output> {
    debug_assert!(!cmd.is_empty(), "route command must not be empty");
    ROUTING_SUBPROCESS_SPAWN_COUNT.fetch_add(1, Ordering::SeqCst);
    info!(phase, cmd = cmd.join(" "), "running route command");
    let output = Command::new(&cmd[0]).args(&cmd[1..]).output()?;
    let exit_code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if output.status.success() {
        // Success log at debug level. Kept out of info to avoid
        // drowning the per-run log in route noise, but visible when
        // an investigation turns on hole_bridge=debug.
        // stdout/stderr included because netsh sometimes prints a
        // non-empty stdout on success (e.g. "Ok.") that is still
        // worth having in the trace.
        debug!(phase, cmd = cmd.join(" "), exit_code,
               stdout = %stdout.trim(), stderr = %stderr.trim(),
               "route command succeeded");
    } else if recovery {
        // Recovery and teardown phases — see is_recovery_phase
        // doc-comment. Non-zero exits here are the unavoidable consequence
        // of non-transactional install + best-effort cleanup; warning would
        // drown legitimate signal.
        debug!(phase, cmd = cmd.join(" "), exit_code, stderr = %stderr,
               "best-effort command failed (expected if route absent)");
    } else {
        // PHASE_SETUP only. A non-zero exit during initial route install
        // IS a real anomaly — investigate.
        warn!(phase, cmd = cmd.join(" "), exit_code,
              stdout = %stdout.trim(), stderr = %stderr.trim(),
              "route command failed — investigate (setup phase only)");
    }
    Ok(output)
}

/// Spawn one route command and report whether it actually went into the
/// table — see the Success-oracle section above. Used by the install loop.
fn run_one(cmd: &[String], phase: &str, recovery: bool) -> std::io::Result<bool> {
    run_one_output(cmd, phase, recovery).map(|o| route_command_installed(&o))
}

/// Spawn one teardown/recovery command and report whether the route is now
/// confirmed gone — see the Success-oracle section above and
/// [`macos_route_confirmed_absent`]. Used by [`run_teardown_commands`].
fn run_one_teardown(cmd: &[String], phase: &str) -> std::io::Result<bool> {
    let recovery = is_recovery_phase(phase);
    run_one_output(cmd, phase, recovery).map(|o| route_confirmed_absent(&o))
}

// Execute (checkpointed) ==============================================================================================
//
// Both loops below persist `installed`/`still_installed` after EVERY command,
// not once per phase or once per install — see CONTRIBUTING's
// [Route ownership](../../../CONTRIBUTING.md#route-ownership) section. The
// on-disk record is therefore never a prediction (superset or otherwise): at
// any instant, including mid-loop, it names exactly what the accumulator in
// memory names, so a crash or a later command's spawn failure narrows the
// leak window to at most the single command in flight.

/// Execute route setup commands one at a time via `runner` (production:
/// [`run_one`]; tests inject a scripted closure so they can simulate a
/// specific command failing without touching the host — see #165 in
/// [`Routing`]'s doc). `installed` accumulates the [`RouteId`]s confirmed in
/// the table; `checkpoint` is called with it before AND after every command.
///
/// A pre-command checkpoint failure aborts immediately (mirrors the
/// write-before-mutate ordering contract: this codebase must not run a
/// mutation it failed to record first) and its `Err` propagates; the id is
/// popped back out first — the write never durably happened, so the command
/// is treated exactly like one that never ran. A post-command checkpoint
/// failure does not abort — the record it failed to write is a narrowing,
/// and the last successful checkpoint (naming a superset of at most one
/// extra route) still stands — so the caller is expected to log it.
///
/// On a runner `Err` (spawn failure), the in-flight command's id is likewise
/// popped back out of `installed` before the error propagates: the caller
/// uses `installed` to decide what to roll back, and a command that never
/// spawned must not be rolled back (that would delete whoever holds the
/// route now). The ON-DISK checkpoint from just before the failed spawn is
/// deliberately NOT corrected to match — it still names the speculative id,
/// which is the safe superset-of-one this design accepts (see CONTRIBUTING).
pub fn setup_routes<R>(
    tun_name: &str,
    server_ip: IpAddr,
    original_gateway: IpAddr,
    interface_name: &str,
    installed: &mut Vec<RouteId>,
    runner: R,
    mut checkpoint: impl FnMut(&[RouteId]) -> std::io::Result<()>,
) -> std::io::Result<()>
where
    R: Fn(&[String]) -> std::io::Result<bool>,
{
    let commands = build_setup_commands(tun_name, server_ip, original_gateway, interface_name);
    for cmd in &commands {
        installed.push(cmd.id);
        if let Err(e) = checkpoint(installed) {
            installed.pop();
            return Err(e);
        }
        match runner(&cmd.argv) {
            Ok(true) => {}
            Ok(false) => {
                installed.pop();
            }
            Err(e) => {
                installed.pop();
                return Err(e);
            }
        }
        if let Err(e) = checkpoint(installed) {
            warn!(error = %e, id = ?cmd.id, "failed to checkpoint route-state after install command");
        }
    }
    Ok(())
}

/// Execute route teardown/recovery commands one at a time via `runner`
/// (production: [`run_one_teardown`]; tests inject a scripted closure — same
/// #165 rationale as [`setup_routes`]). `still_installed` starts as the ids
/// believed installed and is narrowed as each command confirms its route
/// gone; `checkpoint` is called with the narrowed value after every command.
/// Best-effort per #907: every command in `cmds` is attempted regardless of
/// an earlier one's outcome — there is no error channel to abort through.
///
/// When `cmds` is empty, `runner` is still called once with an empty argv —
/// a "phase entered, nothing to do" signal tests can observe, distinguishing
/// it from the phase never running at all.
fn run_teardown_commands<R>(
    cmds: &[RouteCommand],
    phase: &str,
    still_installed: &mut Vec<RouteId>,
    runner: R,
    mut checkpoint: impl FnMut(&[RouteId]),
) where
    R: Fn(&[String], &str) -> std::io::Result<bool>,
{
    if cmds.is_empty() {
        let _ = runner(&[], phase);
        return;
    }
    for cmd in cmds {
        match runner(&cmd.argv, phase) {
            Ok(true) => still_installed.retain(|id| *id != cmd.id),
            Ok(false) => {
                warn!(
                    phase,
                    id = ?cmd.id,
                    "route-teardown command did not confirm the route is gone — keeping it recorded"
                );
            }
            Err(e) => {
                warn!(phase, id = ?cmd.id, error = %e, "route-teardown command failed to spawn — route may still be installed");
            }
        }
        checkpoint(still_installed);
    }
}

/// Execute route teardown commands for the routes `installed` records via
/// [`run_one_teardown`], checkpointing the persisted record after every
/// command through `checkpoint`. Idempotent — safe to call even if those
/// routes are already gone. Returns the ids still believed installed when
/// done (empty on full success) — the caller decides whether to clear or
/// keep the state file from that.
pub fn teardown_routes(
    tun_name: &str,
    server_ip: IpAddr,
    interface_name: &str,
    installed: &[RouteId],
    checkpoint: impl FnMut(&[RouteId]),
) -> Vec<RouteId> {
    let mut cmds = platform_split_teardown_commands(tun_name);
    cmds.extend(platform_bypass_teardown_command(server_ip, interface_name));
    let cmds: Vec<RouteCommand> = cmds.into_iter().filter(|c| installed.contains(&c.id)).collect();
    let mut still_installed = installed.to_vec();
    run_teardown_commands(
        &cmds,
        PHASE_TEARDOWN,
        &mut still_installed,
        run_one_teardown,
        checkpoint,
    );
    still_installed
}

/// Run a single command, feeding `stdin` if present and returning the full
/// `Output` so callers can parse stdout/stderr. Increments
/// [`ROUTING_SUBPROCESS_SPAWN_COUNT`] (the no-spawn invariant covers cover
/// engage too). Used by the macOS pf cover; not for route commands.
#[cfg(target_os = "macos")]
pub(crate) fn run_capturing(
    cmd: &[String],
    stdin: Option<&[u8]>,
    phase: &str,
) -> std::io::Result<std::process::Output> {
    use std::io::Write;
    use std::process::Stdio;
    debug_assert!(!cmd.is_empty(), "command must not be empty");
    ROUTING_SUBPROCESS_SPAWN_COUNT.fetch_add(1, Ordering::SeqCst);
    info!(phase, cmd = cmd.join(" "), "running cover command");
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
/// described by it; finally deletes the state file. Best-effort — all errors
/// are logged at `warn` level and the function returns `()` (there is no
/// meaningful caller recovery). `owner` is forwarded to the mid-recovery
/// checkpoint writes (same uid/gid-chown contract as [`SystemRouting::new`]).
pub fn recover_routes(state_dir: &Path, owner: Option<(u32, u32)>) {
    let intent = failclosed::lockdown_state::load_enabled(state_dir);
    recover_routes_with(
        state_dir,
        owner,
        run_one_teardown,
        failclosed::recover_cover,
        intent,
        || failclosed::lockdown_cover_present(state_dir),
        |decision| failclosed::recover_lockdown(decision, state_dir),
    );
}

/// What crash-recovery should do with a possibly-present standing lockdown
/// cover, given the persisted lockdown intent and whether a cover is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverRecovery {
    /// Intent ON + cover present: KEEP the host fail-closed across the restart.
    /// The fail-closed floor (block-all + loopback + App-ID) stays in force; the
    /// volatile permits — the stale TUN-interface permit (dead LUID/utun after
    /// teardown) and the server-IP permit (the server may change before the next
    /// connect) — are refreshed by the next connect's `install_lockdown`. Windows
    /// drops the volatile GUIDs at recovery so the re-add isn't a fixed-key
    /// no-op; macOS reloads the whole pf ruleset, refreshing them implicitly.
    /// This is the crash-leak fix: a crash never runs `stop()`, so the persistent
    /// cover survives and Adopt holds it.
    Adopt,
    /// Intent OFF + cover present: fully disengage the leftover cover (Windows:
    /// delete all lockdown GUIDs; macOS: restore the pre-lockdown snapshot +
    /// drop the pf token).
    Sweep,
    /// No cover present: nothing to do.
    Noop,
}

/// Pure recovery decision. `intent` is the persisted lockdown-enabled bool
/// (`bridge-lockdown.json`); `prior_present` is whether a lockdown cover from a
/// prior run is present, keyed on the cover's OWN evidence (NOT
/// `bridge-routes.json` — the cover's lifetime is independent of routes). See
/// `recover_routes_with` for how `prior_present` is derived per platform.
pub fn decide_cover_recovery(intent: bool, prior_present: bool) -> CoverRecovery {
    match (intent, prior_present) {
        (_, false) => CoverRecovery::Noop,
        (true, true) => CoverRecovery::Adopt,
        (false, true) => CoverRecovery::Sweep,
    }
}

/// Test seam for [`recover_routes`]: accepts an injected per-command route
/// runner, an injected transient-cover sweep, and the standing-lockdown
/// reconciliation inputs (intent + presence probe + recover action) so unit
/// tests can assert behavior without shelling out to `netsh`/`route` or
/// touching the host firewall. Production passes [`run_one_teardown`],
/// [`failclosed::recover_cover`], the persisted lockdown intent,
/// [`failclosed::lockdown_cover_present`], and [`failclosed::recover_lockdown`].
pub(crate) fn recover_routes_with<R, S, P, L>(
    state_dir: &Path,
    owner: Option<(u32, u32)>,
    runner: R,
    sweep_cover: S,
    lockdown_intent: bool,
    lockdown_present: P,
    lockdown_recover: L,
) where
    R: Fn(&[String], &str) -> std::io::Result<bool>,
    S: FnOnce(&Path, bool),
    P: FnOnce() -> bool,
    L: FnOnce(CoverRecovery),
{
    info!(state_dir = %state_dir.display(), "starting route recovery");

    // Route recovery is guarded by the route-state file. Its absence means the
    // previous run installed no routes (the write-ordering contract persists
    // state BEFORE any route mutation), so we skip route teardown.
    //
    // State-file-driven recovery (not unconditional split-route teardown)
    // is required so concurrent bridge subprocesses don't rip routes out
    // from under each other: a SOCKS5-only bridge unconditionally issuing
    // `netsh delete route ... hole-tun` on startup would tear down the
    // routes of a concurrent TUN bridge mid-flight.
    if let Some(loaded) = state::load(state_dir) {
        let tun_name = loaded.tun_name;
        let server_ip = loaded.server_ip;
        let interface_name = loaded.interface_name;

        // Defensive: an id with no possible teardown command (e.g. a
        // `ServerBypass` recorded against a now-loopback `server_ip` — only
        // reachable via a hand-edited or foreign-schema file, since every
        // production writer keeps `installed` a subset of
        // `planned_routes(server_ip)`) can never be attempted, so it can
        // never drain from `still_installed` below. Drop it up front instead
        // of leaving the state file stuck non-empty forever.
        let plannable = planned_routes(server_ip);
        let sanitized: Vec<RouteId> = loaded
            .installed
            .iter()
            .copied()
            .filter(|id| plannable.contains(id))
            .collect();
        if sanitized.len() != loaded.installed.len() {
            warn!(
                recorded = ?loaded.installed,
                plannable = ?plannable,
                "route-state names a route with no possible teardown command for this server_ip — dropping it"
            );
        }

        info!(
            tun = %tun_name,
            %server_ip,
            iface = %interface_name,
            installed = ?sanitized,
            "recovering routes from crashed run"
        );

        // `persisted` is a fresh checkpoint template, independent of
        // `tun_name`/`server_ip`/`interface_name` above (which stay free for
        // building the command lists below) — only `checkpoint`'s own copy
        // of those fields is mutated.
        let mut persisted = state::RouteState {
            version: state::SCHEMA_VERSION,
            tun_name: tun_name.clone(),
            server_ip,
            interface_name: interface_name.clone(),
            installed: sanitized.clone(),
        };
        let mut still_installed = sanitized;
        let mut checkpoint = |ids: &[RouteId]| {
            persisted.installed = ids.to_vec();
            if let Err(e) = state::save(state_dir, &persisted, owner) {
                warn!(error = %e, "failed to checkpoint route-state during recovery — recorded routes may be stale if this process now crashes");
            }
        };

        // 1. Split routes (IPv4 + IPv6 halves). Idempotent — harmless if
        //    absent. Runs under state-file guard so this only fires when we
        //    have positive evidence of a prior route install, and only for
        //    the routes that run recorded as installed. Uses the TUN name
        //    persisted in the state file (the caller controls this —
        //    tun-engine has no opinion on naming).
        let split_cmds: Vec<RouteCommand> = platform_split_teardown_commands(&tun_name)
            .into_iter()
            .filter(|c| still_installed.contains(&c.id))
            .collect();
        run_teardown_commands(
            &split_cmds,
            PHASE_RECOVER_SPLIT,
            &mut still_installed,
            &runner,
            &mut checkpoint,
        );

        // 2. Per-server bypass route recorded in the state file. The splits
        //    are NOT re-issued here: step 1 already deleted them, and a second
        //    delete of a now-free prefix could take out whatever claimed it in
        //    between.
        let bypass_cmds: Vec<RouteCommand> = platform_bypass_teardown_command(server_ip, &interface_name)
            .into_iter()
            .filter(|c| still_installed.contains(&c.id))
            .collect();
        run_teardown_commands(
            &bypass_cmds,
            PHASE_RECOVER_BYPASS,
            &mut still_installed,
            &runner,
            &mut checkpoint,
        );

        // 3. Clear the state file once nothing remains unaccounted for.
        //    `checkpoint` already persisted `still_installed` after every
        //    command above, so a non-empty remainder is already recorded —
        //    the next startup's recovery will retry exactly those ids.
        if still_installed.is_empty() {
            if let Err(e) = state::clear(state_dir) {
                warn!(error = %e, "failed to clear route-state file during recovery");
            }
        } else {
            warn!(
                remaining = ?still_installed,
                "routes may still be leaked; left recorded for the next start's recovery"
            );
        }
    } else {
        debug!("no route-state file found, nothing to recover");
    }

    // Reconcile the standing lockdown cover FIRST. `standing_held` is the
    // lockdown cover's OWN evidence (injected probe), NOT the route-state file,
    // whose lifetime is independent of the cover. Deciding/adopting before the
    // transient sweep means the subsequent sweep can be told a standing cover is
    // held and must not clobber it. The recover action keeps the host fail-closed
    // (Adopt) or disengages (Sweep).
    let standing_held = lockdown_present();
    let decision = decide_cover_recovery(lockdown_intent, standing_held);
    let adopt = matches!(decision, CoverRecovery::Adopt);
    lockdown_recover(decision);

    // Sweep any transient fail-closed cover left by a crashed update cutover.
    // Runs UNCONDITIONALLY (outside the route-state guard above): a crash can
    // leave a cover engaged with the routes already torn down, so there is no
    // bridge-routes.json, yet the cover persists. The cover is keyed
    // independently — Windows by fixed WFP GUIDs, macOS by bridge-failclosed.json
    // — and the sweep is idempotent when no cover is present. When a standing
    // lockdown cover is being adopted, the sweep must leave the lockdown ruleset
    // untouched (macOS: skip the `pfctl -f /etc/pf.conf` reload that would wipe
    // it) — passed as `adopt`. Note this is `adopt`, NOT `standing_held`: on a
    // Sweep (intent off, cover present) the standing ruleset is being torn down,
    // so the transient restore SHOULD run.
    sweep_cover(state_dir, adopt);
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
    /// (no stale state file, no partially-installed routes) — unless it
    /// could not run the rollback commands at all, in which case it keeps a
    /// state file naming exactly the routes it did install, so the next
    /// start's recovery removes them.
    fn install(
        &self,
        tun_name: &str,
        server_ip: IpAddr,
        gateway: IpAddr,
        interface_name: &str,
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
}

impl Routing for SystemRouting {
    type Installed = SystemRoutes;
    type Cover = failclosed::Cover;

    fn install(
        &self,
        tun_name: &str,
        server_ip: IpAddr,
        gateway: IpAddr,
        interface_name: &str,
    ) -> Result<Self::Installed, RoutingError> {
        // Checkpoint template: `setup_routes` calls `checkpoint(ids)` before
        // AND after every route command, so `persisted.installed` — and the
        // on-disk file it writes — is never a prediction. At any instant it
        // names exactly what `installed` below names, so a crash narrows the
        // leak window to at most the single command in flight. See
        // CONTRIBUTING's Route ownership section.
        let mut persisted = state::RouteState {
            version: state::SCHEMA_VERSION,
            tun_name: tun_name.to_owned(),
            server_ip,
            interface_name: interface_name.to_owned(),
            installed: Vec::new(),
        };
        let mut installed = Vec::new();
        #[allow(clippy::disallowed_methods)] // we ARE the Routing impl
        let setup_result = setup_routes(
            tun_name,
            server_ip,
            gateway,
            interface_name,
            &mut installed,
            |argv| run_one(argv, PHASE_SETUP, false),
            |ids| {
                persisted.installed = ids.to_vec();
                state::save(&self.state_dir, &persisted, self.owner)
            },
        );

        if let Err(e) = setup_result {
            // Roll back whatever went in. `installed` already excludes the
            // command that failed to spawn (see `setup_routes`'s doc) — the
            // in-flight route's on-disk checkpoint is left as-is
            // (deliberately not corrected here), which is the accepted
            // superset-of-one for this failure mode.
            #[allow(clippy::disallowed_methods)] // defensive rollback inside install
            let remaining = teardown_routes(tun_name, server_ip, interface_name, &installed, |ids| {
                persisted.installed = ids.to_vec();
                if let Err(e) = state::save(&self.state_dir, &persisted, self.owner) {
                    warn!(error = %e, "failed to checkpoint route-state during install rollback — recorded routes may be stale if this process now crashes");
                }
            });
            if remaining.is_empty() {
                if let Err(e) = state::clear(&self.state_dir) {
                    warn!(error = %e, "failed to clear route-state after rollback — a stale record will trigger a redundant idempotent teardown next start");
                }
            } else {
                warn!(
                    remaining = ?remaining,
                    "routes may be leaked; left recorded for the next start's recovery"
                );
            }
            return Err(RoutingError::RouteSetup(e.to_string()));
        }

        // `persisted.installed` already equals `installed` here — every
        // command's post-run checkpoint above kept it current — so there is
        // no separate narrowing write.
        Ok(SystemRoutes {
            tun_name: tun_name.to_owned(),
            server_ip,
            interface_name: interface_name.to_owned(),
            state_dir: self.state_dir.clone(),
            owner: self.owner,
            installed,
        })
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
    /// Forwarded to every checkpoint `state::save` in `Drop` — same
    /// uid/gid-chown contract as `SystemRouting.owner`.
    owner: Option<(u32, u32)>,
    /// The routes `install` got into the table — the only ones Drop may delete.
    installed: Vec<RouteId>,
}

impl Drop for SystemRoutes {
    fn drop(&mut self) {
        // Unconditional entry log so a reader can confirm this Drop
        // actually ran on Stop (teardown-skipped diagnosis).
        info!(
            tun = %self.tun_name,
            server_ip = %self.server_ip,
            iface = %self.interface_name,
            installed = ?self.installed,
            "SystemRoutes::drop entered — tearing down routes"
        );
        let mut persisted = state::RouteState {
            version: state::SCHEMA_VERSION,
            tun_name: self.tun_name.clone(),
            server_ip: self.server_ip,
            interface_name: self.interface_name.clone(),
            installed: self.installed.clone(),
        };
        #[allow(clippy::disallowed_methods)] // SystemRoutes IS Routing::Installed
        let remaining = teardown_routes(
            &self.tun_name,
            self.server_ip,
            &self.interface_name,
            &self.installed,
            |ids| {
                persisted.installed = ids.to_vec();
                if let Err(e) = state::save(&self.state_dir, &persisted, self.owner) {
                    warn!(error = %e, "failed to checkpoint route-state during teardown — recorded routes may be stale if this process now crashes");
                }
            },
        );
        // Clear the state file only once nothing remains unaccounted for.
        // The checkpoint above already persisted `remaining` after every
        // command, so a non-empty remainder is already recorded — the next
        // start's `recover_routes` will retry exactly those ids.
        if remaining.is_empty() {
            if let Err(e) = state::clear(&self.state_dir) {
                warn!(error = %e, "state-file clear failed in SystemRoutes::drop");
            }
        } else {
            warn!(
                remaining = ?remaining,
                "keeping route-state for the next start's recovery — some teardown commands did not confirm their route is gone"
            );
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
//
// Each platform contributes three builders: the setup commands, the four
// split-route deletes, and the optional server-bypass delete. Teardown is
// built from the same tagged commands as setup so the two can never drift
// apart on which route is which.

#[cfg(target_os = "windows")]
fn platform_setup_commands(
    tun_name: &str,
    server_ip: IpAddr,
    original_gateway: IpAddr,
    interface_name: &str,
) -> Vec<RouteCommand> {
    let mut cmds = vec![
        RouteCommand::new(
            RouteId::SplitV4Low,
            vec![
                "netsh".into(),
                "interface".into(),
                "ip".into(),
                "add".into(),
                "route".into(),
                "0.0.0.0/1".into(),
                tun_name.into(),
            ],
        ),
        RouteCommand::new(
            RouteId::SplitV4High,
            vec![
                "netsh".into(),
                "interface".into(),
                "ip".into(),
                "add".into(),
                "route".into(),
                "128.0.0.0/1".into(),
                tun_name.into(),
            ],
        ),
        RouteCommand::new(
            RouteId::SplitV6Low,
            vec![
                "netsh".into(),
                "interface".into(),
                "ipv6".into(),
                "add".into(),
                "route".into(),
                "::/1".into(),
                tun_name.into(),
            ],
        ),
        RouteCommand::new(
            RouteId::SplitV6High,
            vec![
                "netsh".into(),
                "interface".into(),
                "ipv6".into(),
                "add".into(),
                "route".into(),
                "8000::/1".into(),
                tun_name.into(),
            ],
        ),
    ];

    // Bypass: server IP via original gateway/interface. Skipped for loopback —
    // see `build_setup_commands` (loopback is on-link, a gateway bypass would
    // hijack it).
    if !server_ip.to_canonical().is_loopback() {
        cmds.push(RouteCommand::new(
            RouteId::ServerBypass,
            match server_ip {
                IpAddr::V4(_) => vec![
                    "route".into(),
                    "add".into(),
                    format!("{server_ip}"),
                    "mask".into(),
                    "255.255.255.255".into(),
                    format!("{original_gateway}"),
                ],
                IpAddr::V6(_) => vec![
                    "netsh".into(),
                    "interface".into(),
                    "ipv6".into(),
                    "add".into(),
                    "route".into(),
                    format!("{server_ip}/128"),
                    interface_name.into(),
                ],
            },
        ));
    }

    cmds
}

#[cfg(target_os = "windows")]
fn platform_split_teardown_commands(tun_name: &str) -> Vec<RouteCommand> {
    vec![
        RouteCommand::new(
            RouteId::SplitV4Low,
            vec![
                "netsh".into(),
                "interface".into(),
                "ip".into(),
                "delete".into(),
                "route".into(),
                "0.0.0.0/1".into(),
                tun_name.into(),
            ],
        ),
        RouteCommand::new(
            RouteId::SplitV4High,
            vec![
                "netsh".into(),
                "interface".into(),
                "ip".into(),
                "delete".into(),
                "route".into(),
                "128.0.0.0/1".into(),
                tun_name.into(),
            ],
        ),
        RouteCommand::new(
            RouteId::SplitV6Low,
            vec![
                "netsh".into(),
                "interface".into(),
                "ipv6".into(),
                "delete".into(),
                "route".into(),
                "::/1".into(),
                tun_name.into(),
            ],
        ),
        RouteCommand::new(
            RouteId::SplitV6High,
            vec![
                "netsh".into(),
                "interface".into(),
                "ipv6".into(),
                "delete".into(),
                "route".into(),
                "8000::/1".into(),
                tun_name.into(),
            ],
        ),
    ]
}

#[cfg(target_os = "windows")]
fn platform_bypass_teardown_command(server_ip: IpAddr, interface_name: &str) -> Option<RouteCommand> {
    // No bypass was installed for a loopback server, so none to delete.
    if server_ip.to_canonical().is_loopback() {
        return None;
    }
    Some(RouteCommand::new(
        RouteId::ServerBypass,
        match server_ip {
            IpAddr::V4(_) => vec![
                "route".into(),
                "delete".into(),
                format!("{server_ip}"),
                "mask".into(),
                "255.255.255.255".into(),
            ],
            IpAddr::V6(_) => vec![
                "netsh".into(),
                "interface".into(),
                "ipv6".into(),
                "delete".into(),
                "route".into(),
                format!("{server_ip}/128"),
                interface_name.into(),
            ],
        },
    ))
}

#[cfg(target_os = "macos")]
fn platform_setup_commands(
    tun_name: &str,
    server_ip: IpAddr,
    original_gateway: IpAddr,
    interface_name: &str,
) -> Vec<RouteCommand> {
    let mut cmds = vec![
        RouteCommand::new(
            RouteId::SplitV4Low,
            vec![
                "route".into(),
                "-n".into(),
                "add".into(),
                "-net".into(),
                "0.0.0.0/1".into(),
                "-interface".into(),
                tun_name.into(),
            ],
        ),
        RouteCommand::new(
            RouteId::SplitV4High,
            vec![
                "route".into(),
                "-n".into(),
                "add".into(),
                "-net".into(),
                "128.0.0.0/1".into(),
                "-interface".into(),
                tun_name.into(),
            ],
        ),
        RouteCommand::new(
            RouteId::SplitV6Low,
            vec![
                "route".into(),
                "-n".into(),
                "add".into(),
                "-inet6".into(),
                "::/1".into(),
                "-interface".into(),
                tun_name.into(),
            ],
        ),
        RouteCommand::new(
            RouteId::SplitV6High,
            vec![
                "route".into(),
                "-n".into(),
                "add".into(),
                "-inet6".into(),
                "8000::/1".into(),
                "-interface".into(),
                tun_name.into(),
            ],
        ),
    ];

    // Bypass: server IP via original gateway/interface. Skipped for loopback —
    // see `build_setup_commands` (loopback is on-link, a gateway bypass would
    // hijack it).
    if !server_ip.to_canonical().is_loopback() {
        cmds.push(RouteCommand::new(
            RouteId::ServerBypass,
            match server_ip {
                IpAddr::V4(_) => vec![
                    "route".into(),
                    "-n".into(),
                    "add".into(),
                    "-host".into(),
                    format!("{server_ip}"),
                    format!("{original_gateway}"),
                ],
                IpAddr::V6(_) => vec![
                    "route".into(),
                    "-n".into(),
                    "add".into(),
                    "-inet6".into(),
                    "-host".into(),
                    format!("{server_ip}"),
                    "-interface".into(),
                    interface_name.into(),
                ],
            },
        ));
    }

    cmds
}

/// The macOS deletes name no interface, unlike their `add` counterparts:
/// `-interface`/`-ifscope` are settled-and-rejected qualifiers (see
/// [`RouteId`]'s doc and CONTRIBUTING's
/// [Route ownership](../../../CONTRIBUTING.md#route-ownership) section for
/// why). Selectivity comes from [`RouteId`] provenance instead.
#[cfg(target_os = "macos")]
fn platform_split_teardown_commands(_tun_name: &str) -> Vec<RouteCommand> {
    vec![
        RouteCommand::new(
            RouteId::SplitV4Low,
            vec![
                "route".into(),
                "-n".into(),
                "delete".into(),
                "-net".into(),
                "0.0.0.0/1".into(),
            ],
        ),
        RouteCommand::new(
            RouteId::SplitV4High,
            vec![
                "route".into(),
                "-n".into(),
                "delete".into(),
                "-net".into(),
                "128.0.0.0/1".into(),
            ],
        ),
        RouteCommand::new(
            RouteId::SplitV6Low,
            vec![
                "route".into(),
                "-n".into(),
                "delete".into(),
                "-inet6".into(),
                "::/1".into(),
            ],
        ),
        RouteCommand::new(
            RouteId::SplitV6High,
            vec![
                "route".into(),
                "-n".into(),
                "delete".into(),
                "-inet6".into(),
                "8000::/1".into(),
            ],
        ),
    ]
}

/// Names no interface, for the reasons in [`platform_split_teardown_commands`].
/// The uplink outlives the tunnel, but it can still be renamed away — a
/// Wi-Fi-to-Ethernet switch between connect and stop — and `route(8)` would
/// abort on the stale name rather than delete the bypass.
#[cfg(target_os = "macos")]
fn platform_bypass_teardown_command(server_ip: IpAddr, _interface_name: &str) -> Option<RouteCommand> {
    // No bypass was installed for a loopback server, so none to delete.
    if server_ip.to_canonical().is_loopback() {
        return None;
    }
    Some(RouteCommand::new(
        RouteId::ServerBypass,
        match server_ip {
            IpAddr::V4(_) => vec![
                "route".into(),
                "-n".into(),
                "delete".into(),
                "-host".into(),
                format!("{server_ip}"),
            ],
            IpAddr::V6(_) => vec![
                "route".into(),
                "-n".into(),
                "delete".into(),
                "-inet6".into(),
                "-host".into(),
                format!("{server_ip}"),
            ],
        },
    ))
}

#[cfg(test)]
#[path = "routing_tests.rs"]
mod routing_tests;
