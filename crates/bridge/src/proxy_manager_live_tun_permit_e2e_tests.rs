//! Session-level composition guard for the standing lockdown cover.
//!
//! `tun_engine`'s `live_tun_permit_privileged_tests` (crates/tun-engine)
//! falsifies the cover's tunnel-permit rule directly: it opens two real TUN
//! devices and proves the permit is sensitive to which one it names. This
//! test does NOT repeat that falsification — it proves something narrower
//! and complementary: a REAL Full-mode session, started through the
//! PRODUCTION path (`Dispatcher::new` -> `routing.install` ->
//! `install_lockdown`), with the kill switch armed, still carries its own
//! tunnel traffic, while a probe deliberately routed OFF the tunnel is
//! blocked at the same instant. Runs on both platforms Hole ships Full mode
//! on (bindreams/hole#850, #874) — the elevated `tun` lane below gates it,
//! and the bypass-route section further down is the one place the test body
//! itself branches by platform (see that section's own doc for why).
//!
//! **What this honestly establishes, and no more:**
//!
//! 1. The composition `routing.install` -> `install_lockdown` -> a live
//!    session does not block the session it is protecting.
//! 2. The cover is demonstrably LIVE at that same instant (the off-tunnel
//!    probe is blocked) — so (1) is not the trivial pass of an inert cover.
//! 3. Whether it can CATCH a stale/duplicate-adapter identity mismatch or a
//!    future refactor that decouples the dispatcher's TUN identity from the
//!    one passed to `install_lockdown` splits by platform:
//!    - **On Windows**, it cannot DEMONSTRATE that it would: `Dispatcher::new`
//!      requests `TunName::Requested(WINDOWS_TUN_ALIAS)`, which `TunIdentity`
//!      never reads back (bindreams/hole#850's read-back only happens under
//!      `KernelAssigned`, macOS-only), so the same `TunIdentity`
//!      `proxy_manager.rs` threads to `install_lockdown` carries that same
//!      requested alias by construction — the two cannot disagree without a
//!      bug in the threading itself, which this test does not induce. There
//!      it is a pure composition guard, not a falsification test.
//!    - **On macOS**, it CAN: `TunName::KernelAssigned` means
//!      `identity().alias()` is read back from the specific device this
//!      `Dispatcher::new` call opened (a fresh `utunN` most runs), not a
//!      value every install shares. A future refactor that threads a
//!      different `TunIdentity` — or the wrong one — to `install_lockdown`
//!      would name a DIFFERENT live interface than the session's own, so the
//!      tunnel-traffic probe (point 1) would fail against a cover that still
//!      reports armed: a real, catchable divergence, not merely a
//!      hypothetical one. This is the one respect in which the macOS run of
//!      this test is strictly stronger than the Windows run.
//!
//!    Either way, the interface-liveness falsification itself (that the
//!    permit rule is sensitive to which adapter it names at all) lives in
//!    `tun-engine`'s test, not here.
//!
//! COUPLED NAME: the test name below contains the literal substring
//! `live_tun_permit_`, which `.config/nextest.toml`'s `global_net_state`
//! filter matches by substring.
//!
//! `serial = TUN` reuses `crate::test_support::skuld_fixtures::TUN` — the
//! same label `e2e_none_full_tunnel_local_networking_intact` carries — never redeclared.

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::test_support::dist_fixture::*;
use crate::test_support::dist_harness::DistHarness;
use crate::test_support::port_alloc::allocate_ephemeral_port;
use crate::test_support::rt;
use crate::test_support::skuld_fixtures::*;
use hole_common::config::{DnsConfig, FilterAction, FilterRule, MatchType, ServerEntry};
use hole_common::protocol::{BridgeRequest, BridgeResponse, ProxyConfig, TunnelMode};
use tun_engine::test_utils::{classify, describe_output, EscapeGuard, OwnedRoute, ProbeFate, RecordSpec};
use tun_engine::GatewayInfo;
use util::port_alloc::Protocols;

/// TEST-NET-3 (RFC 5737) — never routable on the real internet. A different
/// block from `tun-engine`'s own probe net (TEST-NET-2), so a route or filter
/// stranded on the box is attributable to whichever test left it, and neither
/// test's residue can out-compete the other's split by longest-prefix match.
const TUNNEL_PROBE: &str = "203.0.113.0/24";
/// Host `.7` inside [`TUNNEL_PROBE`]. Both addresses below are DERIVED from
/// the constant they must sit inside: a second literal would silently drift
/// out of its net (or off its bypass route) and the probe would then measure
/// a different path than the one the test set up, with nothing failing.
const TUNNEL_PROBE_HOST: u8 = 7;
const NO_LEAK_TARGET_IP: &str = "8.8.8.8";
const NO_LEAK_TARGET_PORT: u16 = 443;
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

fn tunnel_probe_addr() -> SocketAddr {
    let net: IpAddr = TUNNEL_PROBE
        .split('/')
        .next()
        .expect("literal")
        .parse()
        .expect("literal");
    let IpAddr::V4(net) = net else {
        panic!("HARNESS: {TUNNEL_PROBE} must be IPv4")
    };
    let [a, b, c, _] = net.octets();
    SocketAddr::from(([a, b, c, TUNNEL_PROBE_HOST], 80))
}

fn no_leak_target_ip() -> IpAddr {
    NO_LEAK_TARGET_IP.parse().expect("literal")
}

fn no_leak_target_addr() -> SocketAddr {
    SocketAddr::new(no_leak_target_ip(), NO_LEAK_TARGET_PORT)
}

/// The escape record this test writes before it arms anything.
const RECORD: RecordSpec = RecordSpec {
    file_name: "hole-live-tun-permit-e2e-RECOVERY.txt",
    what: "hole live-tun-permit session e2e",
};

fn entry_from(ss: &SsServerHandle) -> ServerEntry {
    ServerEntry {
        id: "live-tun-permit-e2e".into(),
        name: "live-tun-permit-e2e".into(),
        server: ss.addr.ip().to_string().into(),
        server_port: ss.addr.port(),
        method: ss.method.into(),
        password: ss.password.clone(),
        plugin: ss.plugin.clone(),
        plugin_opts: ss.plugin_opts.clone(),
        validation: None,
    }
}

fn connect(addr: SocketAddr) -> ProbeFate {
    classify(&TcpStream::connect_timeout(&addr, PROBE_TIMEOUT))
}

/// A TCP connect to a TEST-NET host under a session with no listener there.
/// `Delivered` — a completed three-way handshake — is the one outcome a
/// firewall drop provably cannot manufacture: something (smoltcp's
/// `ensure_listener`, per `driver.rs`) answered locally.
fn probe_tunnel() -> ProbeFate {
    connect(tunnel_probe_addr())
}

// Bypass route ========================================================================================================
//
// Windows and non-Windows (macOS in practice — this crate ships Full mode
// nowhere else) need genuinely different route shapes here, so this section
// is the one place in this file that IS platform-conditional (branching via
// `cfg!()`, same convention `tun_engine::test_utils::route` itself uses, so
// both branches are typechecked on every target even though only one runs).
//
// Windows routes this through `OwnedRoute`'s `nexthop=` support — a genuine
// gateway route there. `OwnedRoute::add`'s non-Windows path cannot express
// the same thing: it is `-interface`-only (own module doc), which means
// "this destination is directly reachable via this interface" — correct for
// this crate's on-link TUN split routes, wrong for `8.8.8.8`, a real host
// reached through a real gateway. Passing `Some(gw.gateway_ip)` there used
// to trip that path's own `assert!(nexthop.is_none(), ...)` (a harness
// assertion doing its job, left untouched); silently dropping to `None`
// instead would have cleared the panic but still installed an on-link
// route that cannot actually deliver a packet to `8.8.8.8` — a route the
// kernel accepts (so a table read-back alone would not catch it) but this
// test's own later real TCP connect to that same host would have (that
// connect is exactly why this is a delivery bug, not merely a table-lookup
// one). [`MacosGatewayRoute`] is the correct shape instead, matching
// production's own mechanism verbatim: `tun_engine::routing`'s macOS
// `platform_setup_commands` installs its `RouteId::ServerBypass` route the
// same way — `route add -host <dest> <gateway-ip>`, gateway as a plain
// positional argument, no `-interface`.

/// Either owned bypass-route shape, so the caller need not match on
/// platform again after installing one.
enum Bypass {
    Windows(OwnedRoute),
    Gateway(MacosGatewayRoute),
}

impl Bypass {
    fn winner_for(&self, dest: IpAddr) -> Result<String, String> {
        match self {
            Bypass::Windows(route) => route.winner_for(dest),
            Bypass::Gateway(route) => route.winner_for(dest),
        }
    }

    fn interface(&self) -> &str {
        match self {
            Bypass::Windows(route) => route.interface(),
            Bypass::Gateway(route) => route.interface(),
        }
    }
}

/// Own only what we installed. Without this route, `8.8.8.8` is a TUNNEL
/// destination under a Full-mode session (the `0.0.0.0/1` split), so the
/// interface permit would correctly permit it. Longest-prefix match puts this
/// `/32` (Windows) / host route (non-Windows) ahead of the `/1` split once
/// installed.
fn install_bypass_route(gw: &GatewayInfo) -> Bypass {
    if cfg!(target_os = "windows") {
        let route = OwnedRoute::add(
            &format!("{NO_LEAK_TARGET_IP}/32"),
            &gw.interface_name,
            Some(gw.gateway_ip),
        );
        // Read the table back via the kernel's own lookup for the real
        // destination — distinguishes "add failed" from "add succeeded but
        // another route still wins a metric tiebreak". The route is already
        // owned, so a panic here still removes it on the way out.
        route.assert_wins_for(no_leak_target_ip());
        return Bypass::Windows(route);
    }
    let route = MacosGatewayRoute::add(no_leak_target_ip(), gw);
    route.assert_wins_for(no_leak_target_ip());
    Bypass::Gateway(route)
}

/// A gateway-routed host route for a real (non on-link) destination, added
/// on `route add -host <dest> <gateway-ip>` — the macOS-shaped counterpart
/// to `OwnedRoute`'s Windows `nexthop=` path; see the section doc above for
/// why `OwnedRoute` itself cannot express this on non-Windows.
///
/// Duplicates macOS `route(8)`'s exit-0-on-failure oracle
/// (`tun_engine::routing::macos_route_command_succeeded` /
/// `macos_route_confirmed_absent`) rather than importing it — both are
/// `pub(crate)` to `tun-engine`, unreachable from this crate — the same
/// reason this file already duplicates its `DnsConfigNotify` harness from
/// `tun_engine::dns_steer::privileged_tests` (see the module doc).
struct MacosGatewayRoute {
    dest: IpAddr,
    gateway: IpAddr,
    interface: String,
}

/// True if macOS `route(8)`'s own text confirms the mutation went through.
/// `route(8)` exits 0 unconditionally even on a routing-socket failure; the
/// only reliable signal is the stderr text `rtmsg()` prints — verified
/// mechanism, see CONTRIBUTING's Route ownership section.
fn macos_route_command_succeeded(out: &std::process::Output) -> bool {
    out.status.success() && !String::from_utf8_lossy(&out.stderr).contains("writing to routing socket")
}

/// True if macOS `route(8)`'s own text confirms the route is now gone.
/// Mirrors `macos_route_command_succeeded`'s doc: a delete failing because
/// there was nothing to delete (`"not in table"`) still means the route is
/// gone.
fn macos_route_confirmed_absent(out: &std::process::Output) -> bool {
    if !out.status.success() {
        return false;
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !stderr.contains("writing to routing socket") {
        return true;
    }
    stderr.contains("writing to routing socket: not in table")
}

impl MacosGatewayRoute {
    fn add(dest: IpAddr, gw: &GatewayInfo) -> Self {
        let out = Command::new("route")
            .args(["-n", "add", "-host", &dest.to_string(), &gw.gateway_ip.to_string()])
            .output()
            .unwrap_or_else(|e| panic!("HARNESS: failed to spawn route add -host {dest} {}: {e}", gw.gateway_ip));
        if !macos_route_command_succeeded(&out) {
            panic!(
                "HARNESS: adding gateway route for {dest} via {} failed: {}",
                gw.gateway_ip,
                describe_output(&out)
            );
        }
        Self {
            dest,
            gateway: gw.gateway_ip,
            interface: gw.interface_name.clone(),
        }
    }

    /// Assert the kernel's OWN lookup for `dest` now leaves via this
    /// route's interface — same rationale as `OwnedRoute::assert_wins_for`.
    fn assert_wins_for(&self, dest: IpAddr) {
        let winner = self.winner_for(dest).unwrap_or_else(|e| panic!("HARNESS: {e}"));
        assert_eq!(
            winner, self.interface,
            "HARNESS: after adding a gateway route for {} via {}, traffic to {dest} would actually leave via \
             '{winner}', not '{}' — a pre-existing route may be winning a metric tiebreak",
            self.dest, self.gateway, self.interface
        );
    }

    /// The interface the kernel would send `dest` out of, right now, or a
    /// rendered diagnostic. Never panics — see `OwnedRoute::winner_for`.
    fn winner_for(&self, dest: IpAddr) -> Result<String, String> {
        let out = Command::new("route")
            .args(["-n", "get", &dest.to_string()])
            .output()
            .map_err(|e| format!("failed to spawn route get: {e}"))?;
        if !out.status.success() {
            return Err(format!("route -n get {dest} failed: {}", describe_output(&out)));
        }
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.lines()
            .find_map(|l| l.trim().strip_prefix("interface:").map(|s| s.trim().to_string()))
            .ok_or_else(|| format!("could not parse `route -n get {dest}` output:\n{text}"))
    }

    fn interface(&self) -> &str {
        &self.interface
    }
}

impl Drop for MacosGatewayRoute {
    fn drop(&mut self) {
        let out = Command::new("route")
            .args([
                "-n",
                "delete",
                "-host",
                &self.dest.to_string(),
                &self.gateway.to_string(),
            ])
            .output();
        match out {
            Ok(o) if macos_route_confirmed_absent(&o) => {}
            Ok(o) => eprintln!(
                "HARNESS: removing gateway route for {} via {} failed: {} — the host is left modified",
                self.dest,
                self.gateway,
                describe_output(&o)
            ),
            Err(e) => eprintln!(
                "HARNESS: failed to spawn the gateway route-delete command for {} via {}: {e} — the host is left \
                 modified",
                self.dest, self.gateway
            ),
        }
    }
}

// The session-level test ==============================================================================================

async fn run_live_tun_permit_session(dist: &Path, ss: &SsServerHandle) {
    let gw = tun_engine::get_default_gateway_info().expect("HARNESS: get_default_gateway_info");
    let bypass = install_bypass_route(&gw);

    let local_port = allocate_ephemeral_port(Protocols::TCP | Protocols::UDP).await;
    let config = ProxyConfig {
        server: entry_from(ss),
        local_port,
        tunnel_mode: TunnelMode::Full,
        filters: vec![FilterRule {
            address: TUNNEL_PROBE.into(),
            matching: MatchType::Subnet,
            action: FilterAction::Block,
        }],
        dns: DnsConfig {
            enabled: false,
            ..DnsConfig::default()
        },
        proxy_socks5: true,
        proxy_http: false,
        local_port_http: 4074,
        diagnostic_plugin_tap: false,
    };

    let mut harness = DistHarness::spawn(dist).await.expect("HARNESS: spawn DistHarness");

    // Recovery record + escape guard BEFORE anything is armed — written once
    // the harness's state directory exists, well before the SetLockdown{true}
    // call below. From here on the function is unwind-safe even though Phase
    // B additionally defers its own asserts.
    //
    // The guard must be dropped (or still be alive) only while `harness` —
    // and its `TempDir` — has not yet been removed; a directory already
    // deleted would make `release_all` read a clean host over a possibly-live
    // cover, a manufactured lockout. Declaring it after `harness` and
    // dropping it explicitly before `harness` goes out of scope satisfies
    // that. It is a second, redundant layer under the "no assertion while
    // covered" discipline below, not a substitute for it: deferring every
    // assert until after release means the guard's unwind path is normally
    // never exercised at all.
    let guard = EscapeGuard::over(&RECORD, harness.state_dir.path());

    // Phase A — harness control, cover OFF. A completed three-way handshake
    // to a nonexistent TEST-NET host is the only outcome a firewall drop
    // provably cannot manufacture, so this is the baseline phase B is judged
    // against, not merely a smoke test.
    let resp = harness
        .send(BridgeRequest::Start {
            config: config.clone(),
            attempt_id: "live-tun-permit-e2e-a".into(),
            covered: false,
        })
        .await
        .expect("HARNESS: send Start (phase A)");
    assert!(
        matches!(resp, BridgeResponse::Ack),
        "HARNESS/CONTROL FAILED: phase A Start did not Ack: {resp:?}"
    );

    let control_outcome = probe_tunnel();
    assert_eq!(
        control_outcome,
        ProbeFate::Delivered,
        "HARNESS/CONTROL FAILED (says nothing about the cover — no cover is engaged in phase A): expected a \
         completed handshake to {}, got {control_outcome:?}",
        tunnel_probe_addr()
    );

    // Reachability baseline for phase B's no-leak assertion. Note: this does
    // NOT verify the bypass route — with a Full-mode session up this would
    // return Ok either way, since smoltcp answers the SYN locally for a
    // TUNNEL destination too. The route-table read-back in
    // `install_bypass_route` is the only thing that verifies the route.
    let baseline_no_leak = connect(no_leak_target_addr());
    assert_eq!(
        baseline_no_leak,
        ProbeFate::Delivered,
        "HARNESS/CONTROL FAILED: baseline reachability to {} (over the bypass route) failed: {baseline_no_leak:?}",
        no_leak_target_addr()
    );

    let resp = harness
        .send(BridgeRequest::Stop)
        .await
        .expect("HARNESS: send Stop (phase A)");
    assert!(
        matches!(resp, BridgeResponse::Ack),
        "HARNESS: phase A Stop did not Ack: {resp:?}"
    );

    // Phase B — cover ON. From here until the explicit `drop(guard)` below,
    // NO assertion/expect/unwrap that could plausibly fail runs: every
    // outcome — including a failed arm, a failed Start, or a failed IPC call
    // — is folded into a local `Option`/`bool` and judged only after release.
    let arm = harness.send(BridgeRequest::SetLockdown { enabled: true }).await;
    let armed = matches!(arm, Ok(BridgeResponse::Ack));

    let start_b = harness
        .send(BridgeRequest::Start {
            config,
            attempt_id: "live-tun-permit-e2e-b".into(),
            covered: false,
        })
        .await;
    let start_b_acked = matches!(start_b, Ok(BridgeResponse::Ack));

    let intent_active = if start_b_acked {
        match harness.send(BridgeRequest::Status).await {
            Ok(BridgeResponse::Status { lockdown_active, .. }) => Some(lockdown_active),
            _ => None,
        }
    } else {
        None
    };
    let tun_outcome = start_b_acked.then(probe_tunnel);
    // The no-leak probe and its two same-instant cross-checks. Taken here,
    // together, because a `cover_blocking` read on its own is vacuous: a
    // transient blip on the way to the no-leak target also reads as
    // "blocked", and the test would then PASS over a leaking kill switch.
    // `tun_outcome` cannot serve as the cross-check — it targets a TEST-NET
    // host smoltcp answers locally, so it says nothing about the real path.
    //
    // - `no_leak` classifies rather than collapsing to `is_err()`, so a
    //   vanished route (`NeverLeft`) is a harness failure, not a block.
    // - `permitted_reachable` connects to the one destination the cover must
    //   NOT block, the session's own server IP: a cover that blocks
    //   everything, or a dead stack, fails here too.
    // - `path_to_no_leak` asks the kernel whether the bypass route still
    //   wins for the no-leak target, so an interface that went down during
    //   the window is named rather than mistaken for the cover working.
    let no_leak = start_b_acked.then(|| connect(no_leak_target_addr()));
    let permitted_reachable = start_b_acked.then(|| connect(ss.addr));
    let path_to_no_leak = start_b_acked.then(|| bypass.winner_for(no_leak_target_ip()));

    // Release (best-effort — the guard below is the real backstop), THEN assert.
    let _ = harness.send(BridgeRequest::Stop).await;
    let _ = harness.send(BridgeRequest::SetLockdown { enabled: false }).await;
    // Explicit drop (not scope-end): must run while `harness` — and its
    // TempDir — is still alive. `harness`'s own Drop (later, at function
    // end) kills the child if it hasn't already exited; a killed bridge
    // leaves the cover engaged by design, which is exactly what this guard
    // is the escape from.
    drop(guard);

    assert!(
        armed,
        "HARNESS: SetLockdown(true) did not Ack, so the kill switch was never armed and nothing below is a \
         verdict about a cover: {arm:?}"
    );
    assert!(
        start_b_acked,
        "HARNESS: phase B Start did not Ack (with the kill switch armed): {start_b:?}"
    );
    assert_eq!(
        permitted_reachable,
        Some(ProbeFate::Delivered),
        "HARNESS: the cover's own permitted server IP ({}) was unreachable while covered — the block is not \
         selective, or this host's stack is down; either way the no-leak result below says nothing about a \
         leak; got {permitted_reachable:?}",
        ss.addr
    );
    assert!(
        matches!(&path_to_no_leak, Some(Ok(iface)) if iface == bypass.interface()),
        "HARNESS: the bypass route to {NO_LEAK_TARGET_IP} no longer won the kernel's lookup while covered \
         (expected '{}'), so a failed probe there is a routing change, not a block; got {path_to_no_leak:?}",
        bypass.interface()
    );
    assert!(
        matches!(no_leak, Some(ProbeFate::Rejected(_))),
        "the armed kill switch must block a probe routed off the tunnel ({}) — the stack must have rejected it \
         (a `NeverLeft` outcome is a harness fault, `Delivered` is a LEAK); if the block did not hold, nothing \
         downstream (including tun_outcome) means anything; got {no_leak:?}",
        no_leak_target_addr()
    );
    assert_eq!(
        intent_active,
        Some(true),
        "the lockdown intent must be reported active after SetLockdown(true) + Start — in-process bookkeeping, \
         necessary but not sufficient on its own; got {intent_active:?}"
    );
    assert_eq!(
        tun_outcome,
        Some(ProbeFate::Delivered),
        "PRODUCT BUG, not a test bug: the armed kill switch blocked the session's own tunnel traffic (expected \
         Some(Delivered) matching phase A's control, got {tun_outcome:?}); a firewall block yields a `Rejected` \
         outcome, never a completed handshake. Recover with `hole bridge unlock`; recovery record was at the \
         path this test wrote before arming."
    );
}

/// See the module doc for what this test does and does not establish.
#[skuld::test(labels = [DIST_BIN, TUN, GLOBAL_NET_STATE], serial = TUN)]
fn live_tun_permit_holds_for_a_real_session_with_the_kill_switch_armed(
    #[fixture(dist_dir)] dist: &Path,
    #[fixture(ssserver_none)] ss: &SsServerHandle,
) {
    rt().block_on(run_live_tun_permit_session(dist, ss));
}
