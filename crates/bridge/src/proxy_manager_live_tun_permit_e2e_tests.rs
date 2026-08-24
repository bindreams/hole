//! Session-level composition guard for the standing lockdown cover (#874),
//! Windows half.
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
//!    interface-liveness falsification lives in `tun-engine`'s test, and the
//!    macOS half of THIS test (where the TUN name is discovered at runtime
//!    rather than shared as a compile-time constant, so production CAN name
//!    the wrong interface) is a required deliverable of #850, which also
//!    makes `Dispatcher::new` reachable on macOS in the first place.
//!
//! Gate: `cfg(target_os = "windows")` — `Dispatcher::new` sets
//! `c.tun_name = TUN_DEVICE_NAME` unconditionally and the pinned `tun` crate
//! rejects any macOS name not starting with `utun`, so a macOS Full-mode
//! start dies before routes, before DNS, and before `install_lockdown` today.
//! Widens to `any(windows, macos)` once #850 lands.
//!
//! COUPLED NAME: the test name below contains the literal substring
//! `live_tun_permit_`, which `.config/nextest.toml`'s `global-net-state`
//! filter matches by substring.
//!
//! `serial = TUN` reuses `crate::test_support::skuld_fixtures::TUN` — the
//! same label `e2e_none_full_tunnel_roundtrip` carries — never redeclared.

use std::io;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::test_support::dist_fixture::*;
use crate::test_support::dist_harness::DistHarness;
use crate::test_support::port_alloc::allocate_ephemeral_port;
use crate::test_support::rt;
use crate::test_support::skuld_fixtures::*;
use hole_common::config::{DnsConfig, FilterAction, FilterRule, MatchType, ServerEntry};
use hole_common::protocol::{BridgeRequest, BridgeResponse, ProxyConfig, TunnelMode};
use tun_engine::GatewayInfo;
use util::port_alloc::Protocols;

/// TEST-NET-2 (RFC 5737) — never routable on the real internet. Distinct
/// prefix from `tun-engine`'s own probe net so a stranded route or filter is
/// attributable to whichever test left it.
const TUNNEL_PROBE: &str = "198.51.100.0/24";
const TUNNEL_PROBE_ADDR: &str = "198.51.100.7:80";
const NO_LEAK_TARGET_IP: &str = "8.8.8.8";
const NO_LEAK_TARGET_ADDR: &str = "8.8.8.8:443";

fn entry_from(ss: &SsServerHandle) -> ServerEntry {
    ServerEntry {
        id: "live-tun-permit-e2e".into(),
        name: "live-tun-permit-e2e".into(),
        server: ss.addr.ip().to_string(),
        server_port: ss.addr.port(),
        method: ss.method.into(),
        password: ss.password.clone(),
        plugin: ss.plugin.clone(),
        plugin_opts: ss.plugin_opts.clone(),
        validation: None,
    }
}

/// The only outcomes a TCP connect to a TEST-NET-2 host under a session with
/// no listener there can produce. `Connected` is the one outcome a firewall
/// drop provably cannot manufacture — a completed three-way handshake means
/// something (smoltcp's `ensure_listener`, per `driver.rs`) answered locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeOutcome {
    Connected,
    ResetOrRefused,
    TimedOut,
    PermissionDenied,
    Other,
}

fn classify(r: io::Result<TcpStream>) -> ProbeOutcome {
    match r {
        Ok(_) => ProbeOutcome::Connected,
        Err(e) => match e.kind() {
            io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset => ProbeOutcome::ResetOrRefused,
            io::ErrorKind::TimedOut => ProbeOutcome::TimedOut,
            io::ErrorKind::PermissionDenied => ProbeOutcome::PermissionDenied,
            _ => ProbeOutcome::Other,
        },
    }
}

fn probe_tunnel() -> ProbeOutcome {
    classify(TcpStream::connect_timeout(
        &TUNNEL_PROBE_ADDR.parse().expect("literal"),
        Duration::from_secs(5),
    ))
}

// Bypass route (F6/F9) ================================================================================================

fn ps_output(script: &str) -> String {
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output()
        .unwrap_or_else(|e| panic!("HARNESS: failed to spawn powershell: {e}"));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Own only what we installed (F9). Without this route, `8.8.8.8` is a
/// TUNNEL destination under a Full-mode session (the `0.0.0.0/1` split), so
/// the interface permit would correctly permit it — see F6. Longest-prefix
/// match puts this `/32` ahead of the `/1` split once installed.
struct BypassRoute {
    interface_name: String,
}

impl BypassRoute {
    fn install(gw: &GatewayInfo) -> Self {
        let prefix = format!("{NO_LEAK_TARGET_IP}/32");
        let existing = ps_output(&format!(
            "(Get-NetRoute -DestinationPrefix '{prefix}' -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String).Trim()"
        ));
        if !existing.is_empty() {
            panic!("HARNESS: a pre-existing route to {prefix} already exists — refusing to add a second:\n{existing}");
        }

        let out = Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "add",
                "route",
                &format!("prefix={prefix}"),
                &format!("interface=\"{}\"", gw.interface_name),
                &format!("nexthop={}", gw.gateway_ip),
                "store=active",
            ])
            .output()
            .unwrap_or_else(|e| panic!("HARNESS: failed to spawn netsh add route: {e}"));
        if !out.status.success() {
            panic!(
                "HARNESS: netsh add route prefix={prefix} interface=\"{}\" nexthop={} failed: {}",
                gw.interface_name,
                gw.gateway_ip,
                String::from_utf8_lossy(&out.stderr)
            );
        }

        // Read the table back via the kernel's own lookup for the real
        // destination — distinguishes "add failed" from "add succeeded but
        // another route still wins a metric tiebreak" (F9).
        let winner = ps_output(&format!(
            "(Find-NetRoute -RemoteIPAddress '{NO_LEAK_TARGET_IP}' -ErrorAction Stop | Select-Object -First 1 -ExpandProperty InterfaceAlias)"
        ));
        if winner != gw.interface_name {
            panic!(
                "HARNESS: after adding the bypass route, traffic to {NO_LEAK_TARGET_IP} would actually leave \
                 via '{winner}', not the default gateway interface ('{}')",
                gw.interface_name
            );
        }

        Self {
            interface_name: gw.interface_name.clone(),
        }
    }
}

impl Drop for BypassRoute {
    fn drop(&mut self) {
        let prefix = format!("{NO_LEAK_TARGET_IP}/32");
        let out = Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "delete",
                "route",
                &format!("prefix={prefix}"),
                &format!("interface=\"{}\"", self.interface_name),
                "store=active",
            ])
            .output();
        match out {
            Ok(o) if o.status.success() => {}
            Ok(o) => eprintln!(
                "HARNESS: netsh delete route prefix={prefix} interface=\"{}\" failed: {}",
                self.interface_name,
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => eprintln!("HARNESS: failed to spawn netsh delete route: {e}"),
        }
    }
}

// Recovery record (F8) — same recipe as tun-engine's Task 1 Step 2, a local
// copy because it is test-private code on the other side of a crate
// boundary. ===========================================================================================================

fn open_controlling_terminal() -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new().write(true).open("CONOUT$")
}

fn write_recovery_record(state_dir: &Path) -> io::Result<PathBuf> {
    use std::io::Write as _;

    let path = std::env::temp_dir().join("hole-live-tun-permit-e2e-RECOVERY.txt");
    let text = format!(
        "hole live-tun-permit session e2e: a real system-wide fail-closed cover may be engaged.\n\
         State directory: {}\n\
         If this file still exists and the test process is gone, the host may be stranded\n\
         fail-closed. Recover with:\n\
         \n    hole bridge unlock\n\n",
        state_dir.display(),
    );
    std::fs::write(&path, &text)?;
    if let Ok(mut tty) = open_controlling_terminal() {
        let _ = tty.write_all(text.as_bytes());
    }
    Ok(path)
}

/// Unconditional escape (F7/F8-equivalent): calls `release_all` over the
/// harness's OWN state directory. Created right after the harness spawns —
/// BEFORE anything can be armed — and lives until the explicit `drop(guard)`
/// at the release step, so a panic ANYWHERE in between (including one this
/// module does not anticipate) still releases the cover during unwind. This
/// is a second, redundant layer under the "no assertion while covered"
/// discipline below, not a substitute for it: deferring every assert until
/// after release means the guard's unwind path is normally never exercised
/// at all.
///
/// Must be dropped (or must still be alive) only while `harness` — and its
/// `TempDir` — has not yet been removed; a directory already deleted would
/// make `release_all` read a clean host over a possibly-live cover, the
/// manufactured lockout F7 warns against. Declaring it after `harness` and
/// dropping it explicitly before `harness` goes out of scope satisfies that.
struct SessionEscapeGuard {
    dir: PathBuf,
    record_path: PathBuf,
}

impl Drop for SessionEscapeGuard {
    fn drop(&mut self) {
        if let Err(e) = tun_engine::routing::failclosed::release_all(&self.dir) {
            eprintln!(
                "HARNESS: release_all failed during SessionEscapeGuard::drop over {:?}: {e} — host may still be \
                 fail-closed; see {:?}",
                self.dir, self.record_path
            );
        }
        if let Err(e) = std::fs::remove_file(&self.record_path) {
            eprintln!("HARNESS: failed to remove recovery record {:?}: {e}", self.record_path);
        }
    }
}

// The session-level test ==============================================================================================

async fn run_live_tun_permit_session(dist: &Path, ss: &SsServerHandle) {
    let gw = tun_engine::get_default_gateway_info().expect("HARNESS: get_default_gateway_info");
    let _bypass = BypassRoute::install(&gw);

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

    // Recovery record + escape guard BEFORE anything is armed (F7/F8) —
    // written/created once the harness's state directory exists, well
    // before the SetLockdown{true} call below. From here on the function is
    // unwind-safe even though Phase B additionally defers its own asserts.
    let record_path = write_recovery_record(harness.state_dir.path()).expect("HARNESS: write recovery record");
    let guard = SessionEscapeGuard {
        dir: harness.state_dir.path().to_path_buf(),
        record_path,
    };

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
        ProbeOutcome::Connected,
        "HARNESS/CONTROL FAILED (says nothing about the cover — no cover is engaged in phase A): expected a \
         completed handshake to {TUNNEL_PROBE_ADDR}, got {control_outcome:?}"
    );

    // Reachability baseline for phase B's no-leak assertion. Note: this does
    // NOT verify the bypass route — with a Full-mode session up this would
    // return Ok either way, since smoltcp answers the SYN locally for a
    // TUNNEL destination too. The route-table read-back inside
    // `BypassRoute::install` is the only thing that verifies the route.
    let baseline_no_leak =
        TcpStream::connect_timeout(&NO_LEAK_TARGET_ADDR.parse().expect("literal"), Duration::from_secs(5));
    assert!(
        baseline_no_leak.is_ok(),
        "HARNESS/CONTROL FAILED: baseline reachability to {NO_LEAK_TARGET_ADDR} (over the bypass route) failed: \
         {:?}",
        baseline_no_leak.err().map(|e| e.kind())
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
    // outcome — including a failed Start or a failed IPC call — is folded
    // into a local `Option`/`bool` and judged only after release. A failure
    // to even Ack the Start is itself asserted after release, not before.
    let _ = harness.send(BridgeRequest::SetLockdown { enabled: true }).await;

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
    let tun_outcome = if start_b_acked { Some(probe_tunnel()) } else { None };
    let cover_blocking = if start_b_acked {
        Some(
            TcpStream::connect_timeout(&NO_LEAK_TARGET_ADDR.parse().expect("literal"), Duration::from_secs(5)).is_err(),
        )
    } else {
        None
    };

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
        start_b_acked,
        "HARNESS: phase B Start did not Ack (with the kill switch armed): {start_b:?}"
    );
    assert_eq!(
        intent_active,
        Some(true),
        "the lockdown intent must be reported active after SetLockdown(true) + Start — in-process bookkeeping, \
         necessary but not sufficient on its own; got {intent_active:?}"
    );
    assert_eq!(
        cover_blocking,
        Some(true),
        "the armed kill switch must block a probe routed off the tunnel ({NO_LEAK_TARGET_ADDR}) — if the block \
         did not hold, nothing downstream (including tun_outcome) means anything; got {cover_blocking:?}"
    );
    assert_eq!(
        tun_outcome,
        Some(ProbeOutcome::Connected),
        "PRODUCT BUG, not a test bug: the armed kill switch blocked the session's own tunnel traffic (expected \
         Some(Connected) matching phase A's control, got {tun_outcome:?}); a firewall block yields TimedOut or \
         PermissionDenied, never a completed handshake. Recover with `hole bridge unlock`; recovery record was \
         at the path this test wrote before arming."
    );
}

/// See the module doc for what this test does and does not establish.
#[skuld::test(labels = [DIST_BIN, TUN], serial = TUN)]
fn live_tun_permit_holds_for_a_real_session_with_the_kill_switch_armed(
    #[fixture(dist_dir)] dist: &Path,
    #[fixture(ssserver_none)] ss: &SsServerHandle,
) {
    rt().block_on(run_live_tun_permit_session(dist, ss));
}
