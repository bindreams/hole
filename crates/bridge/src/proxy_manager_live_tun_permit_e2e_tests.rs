//! Session-level composition guard for the standing lockdown cover, Windows
//! half.
//!
//! `tun_engine`'s `live_tun_permit_privileged_tests` (crates/tun-engine)
//! falsifies the cover's tunnel-permit rule directly: it opens two real TUN
//! devices and proves the permit is sensitive to which one it names. This
//! test does NOT repeat that falsification — it proves something narrower
//! and complementary: a REAL Full-mode session, started through the
//! PRODUCTION path (`Dispatcher::new` -> `routing.install` ->
//! `install_lockdown`), with the kill switch armed, still carries its own
//! tunnel traffic, while a probe deliberately routed OFF the tunnel is
//! blocked at the same instant.
//!
//! **What this honestly establishes, on Windows, and no more:**
//!
//! 1. The composition `routing.install` -> `install_lockdown` -> a live
//!    session does not block the session it is protecting.
//! 2. The cover is demonstrably LIVE at that same instant (the off-tunnel
//!    probe is blocked) — so (1) is not the trivial pass of an inert cover.
//! 3. It will CATCH a stale/duplicate-adapter LUID mismatch or a future
//!    refactor that decouples the dispatcher's TUN name from the one passed
//!    to `install_lockdown`, if either occurs. It cannot DEMONSTRATE that it
//!    would: `dispatcher.rs` sets `c.tun_name = TUN_DEVICE_NAME` and
//!    `proxy_manager.rs` passes that SAME constant to `install_lockdown`, so
//!    the two names cannot disagree by construction, and this test induces
//!    no mutation. It is a composition guard, not a falsification test — the
//!    interface-liveness falsification lives in `tun-engine`'s test. The
//!    macOS half of THIS test, where the TUN name is discovered at runtime
//!    rather than shared as a compile-time constant (so production CAN name
//!    the wrong interface), does not exist yet: `Dispatcher::new` is not
//!    reachable on macOS at all until macOS TUN naming becomes
//!    runtime-discovered.
//!
//! Gate: `cfg(target_os = "windows")` — `Dispatcher::new` sets
//! `c.tun_name = TUN_DEVICE_NAME` unconditionally and the pinned `tun` crate
//! rejects any macOS name not starting with `utun`, so a macOS Full-mode
//! start dies before routes, before DNS, and before `install_lockdown` today.
//!
//! COUPLED NAME: the test name below contains the literal substring
//! `live_tun_permit_`, which `.config/nextest.toml`'s `global_net_state`
//! filter matches by substring.
//!
//! `serial = TUN` reuses `crate::test_support::skuld_fixtures::TUN` — the
//! same label `e2e_none_full_tunnel_local_networking_intact` carries — never redeclared.

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

use crate::test_support::dist_fixture::*;
use crate::test_support::dist_harness::DistHarness;
use crate::test_support::port_alloc::allocate_ephemeral_port;
use crate::test_support::rt;
use crate::test_support::skuld_fixtures::*;
use hole_common::config::{DnsConfig, FilterAction, FilterRule, MatchType, ServerEntry};
use hole_common::protocol::{BridgeRequest, BridgeResponse, ProxyConfig, TunnelMode};
use tun_engine::test_utils::{classify, EscapeGuard, OwnedRoute, ProbeFate, RecordSpec};
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

/// Own only what we installed. Without this route, `8.8.8.8` is a TUNNEL
/// destination under a Full-mode session (the `0.0.0.0/1` split), so the
/// interface permit would correctly permit it. Longest-prefix match puts this
/// `/32` ahead of the `/1` split once installed.
fn install_bypass_route(gw: &GatewayInfo) -> OwnedRoute {
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
    route
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
