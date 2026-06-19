use std::cell::RefCell;
use std::net::IpAddr;

use super::state::{self, RouteState, STATE_FILE_NAME};
use super::*;

// Helpers =============================================================================================================

fn ipv4_server() -> IpAddr {
    "1.2.3.4".parse().unwrap()
}

fn ipv6_server() -> IpAddr {
    "2001:db8::1".parse().unwrap()
}

fn ipv4_gateway() -> IpAddr {
    "192.168.1.1".parse().unwrap()
}

fn setup_cmds_joined(server_ip: IpAddr, gateway: IpAddr) -> String {
    let cmds = build_setup_commands("utun7", server_ip, gateway, "en0");
    cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n")
}

/// True if any command has an argument that *is* the address (or its `/128`
/// netsh form) — a structural check for the server-bypass command, robust
/// against substring coincidences like `::1` inside `::/1`.
fn mentions_addr(cmds: &[Vec<String>], ip: &str) -> bool {
    let slash128 = format!("{ip}/128");
    cmds.iter().flatten().any(|arg| arg == ip || arg == &slash128)
}

fn teardown_cmds_joined(server_ip: IpAddr) -> String {
    let cmds = build_teardown_commands("utun7", server_ip, "en0");
    cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n")
}

// Setup tests — IPv4 server ===========================================================================================

#[skuld::test]
fn setup_generates_five_commands() {
    let cmds = build_setup_commands("utun7", ipv4_server(), ipv4_gateway(), "en0");
    assert_eq!(cmds.len(), 5);
}

#[skuld::test]
fn setup_includes_low_half_route() {
    let joined = setup_cmds_joined(ipv4_server(), ipv4_gateway());
    assert!(joined.contains("0.0.0.0/1"), "missing low-half route in:\n{joined}");
}

#[skuld::test]
fn setup_includes_high_half_route() {
    let joined = setup_cmds_joined(ipv4_server(), ipv4_gateway());
    assert!(joined.contains("128.0.0.0/1"), "missing high-half route in:\n{joined}");
}

#[skuld::test]
fn setup_includes_ipv6_low_half_route() {
    let joined = setup_cmds_joined(ipv4_server(), ipv4_gateway());
    assert!(joined.contains("::/1"), "missing IPv6 low-half route in:\n{joined}");
}

#[skuld::test]
fn setup_includes_ipv6_high_half_route() {
    let joined = setup_cmds_joined(ipv4_server(), ipv4_gateway());
    assert!(
        joined.contains("8000::/1"),
        "missing IPv6 high-half route in:\n{joined}"
    );
}

#[skuld::test]
fn setup_includes_server_bypass_route() {
    let server_ip: IpAddr = "5.6.7.8".parse().unwrap();
    let joined = setup_cmds_joined(server_ip, ipv4_gateway());
    assert!(joined.contains("5.6.7.8"), "missing server bypass route in:\n{joined}");
}

#[skuld::test]
fn setup_bypass_uses_original_gateway() {
    let server_ip: IpAddr = "5.6.7.8".parse().unwrap();
    let gateway: IpAddr = "10.0.0.1".parse().unwrap();
    let joined = setup_cmds_joined(server_ip, gateway);
    assert!(
        joined.contains("10.0.0.1"),
        "missing gateway in bypass route:\n{joined}"
    );
}

/// A loopback server needs no bypass: it is reached via the kernel's on-link
/// `127.0.0.0/8` route, more specific than the `/1` splits. Installing a `/32`
/// gateway bypass for it would hijack all loopback traffic (bindreams/hole#541).
/// So setup yields only the 4 split routes — no 5th bypass command.
#[skuld::test]
fn setup_with_loopback_server_has_no_bypass() {
    for ip in ["127.0.0.1", "::1"] {
        let server_ip: IpAddr = ip.parse().unwrap();
        let cmds = build_setup_commands("utun7", server_ip, ipv4_gateway(), "en0");
        assert_eq!(
            cmds.len(),
            4,
            "loopback {ip}: expected only 4 split routes, got {cmds:?}"
        );
        assert!(
            !mentions_addr(&cmds, ip),
            "loopback {ip}: no command should reference the server address, got {cmds:?}"
        );
    }
}

// Setup tests — IPv6 server ===========================================================================================

#[skuld::test]
fn setup_with_ipv6_server_generates_five_commands() {
    let cmds = build_setup_commands("utun7", ipv6_server(), ipv4_gateway(), "en0");
    assert_eq!(cmds.len(), 5);
}

#[skuld::test]
fn setup_with_ipv6_server_includes_ipv6_bypass() {
    let cmds = build_setup_commands("utun7", ipv6_server(), ipv4_gateway(), "en0");
    // The bypass is the last command (index 4)
    let bypass = cmds[4].join(" ");
    assert!(
        bypass.contains("2001:db8::1"),
        "missing IPv6 server address in bypass command:\n{bypass}"
    );
    assert!(
        bypass.contains("en0"),
        "missing interface name in bypass command:\n{bypass}"
    );
}

#[skuld::test]
fn setup_with_ipv6_server_has_no_ipv4_bypass() {
    let joined = setup_cmds_joined(ipv6_server(), ipv4_gateway());
    assert!(
        !joined.contains("mask 255.255.255.255"),
        "IPv6 server should not have IPv4 bypass:\n{joined}"
    );
}

// Teardown tests — IPv4 server ========================================================================================

#[skuld::test]
fn teardown_generates_five_commands() {
    let cmds = build_teardown_commands("utun7", ipv4_server(), "en0");
    assert_eq!(cmds.len(), 5);
}

#[skuld::test]
fn teardown_includes_low_half_route() {
    let joined = teardown_cmds_joined(ipv4_server());
    assert!(joined.contains("0.0.0.0/1"), "missing low-half route in:\n{joined}");
}

#[skuld::test]
fn teardown_includes_high_half_route() {
    let joined = teardown_cmds_joined(ipv4_server());
    assert!(joined.contains("128.0.0.0/1"), "missing high-half route in:\n{joined}");
}

#[skuld::test]
fn teardown_includes_ipv6_low_half_route() {
    let joined = teardown_cmds_joined(ipv4_server());
    assert!(joined.contains("::/1"), "missing IPv6 low-half route in:\n{joined}");
}

#[skuld::test]
fn teardown_includes_ipv6_high_half_route() {
    let joined = teardown_cmds_joined(ipv4_server());
    assert!(
        joined.contains("8000::/1"),
        "missing IPv6 high-half route in:\n{joined}"
    );
}

#[skuld::test]
fn teardown_includes_server_bypass() {
    let server_ip: IpAddr = "9.8.7.6".parse().unwrap();
    let cmds = build_teardown_commands("utun7", server_ip, "en0");
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(joined.contains("9.8.7.6"), "missing server bypass in:\n{joined}");
}

/// Mirror of [`setup_with_loopback_server_has_no_bypass`]: no bypass was
/// installed for a loopback server, so teardown deletes only the 4 splits.
#[skuld::test]
fn teardown_with_loopback_server_has_no_bypass() {
    for ip in ["127.0.0.1", "::1"] {
        let server_ip: IpAddr = ip.parse().unwrap();
        let cmds = build_teardown_commands("utun7", server_ip, "en0");
        assert_eq!(
            cmds.len(),
            4,
            "loopback {ip}: expected only 4 split deletes, got {cmds:?}"
        );
        assert!(
            !mentions_addr(&cmds, ip),
            "loopback {ip}: no teardown command should reference the server address, got {cmds:?}"
        );
    }
}

// Teardown tests — IPv6 server ========================================================================================

#[skuld::test]
fn teardown_with_ipv6_server_includes_ipv6_bypass() {
    let cmds = build_teardown_commands("utun7", ipv6_server(), "en0");
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(
        joined.contains("2001:db8::1"),
        "missing IPv6 server bypass in:\n{joined}"
    );
}

#[skuld::test]
fn teardown_with_ipv6_server_has_no_ipv4_bypass() {
    let cmds = build_teardown_commands("utun7", ipv6_server(), "en0");
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(
        !joined.contains("mask 255.255.255.255"),
        "IPv6 server should not have IPv4 bypass:\n{joined}"
    );
}

// Split route teardown (crash recovery) ===============================================================================

#[skuld::test]
fn split_teardown_generates_four_commands() {
    let cmds = build_split_route_teardown_commands("utun7");
    assert_eq!(cmds.len(), 4);
}

#[skuld::test]
fn split_teardown_includes_ipv4_low_half() {
    let cmds = build_split_route_teardown_commands("utun7");
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(
        joined.contains("0.0.0.0/1"),
        "missing IPv4 low-half route in:\n{joined}"
    );
}

#[skuld::test]
fn split_teardown_includes_ipv4_high_half() {
    let cmds = build_split_route_teardown_commands("utun7");
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(
        joined.contains("128.0.0.0/1"),
        "missing IPv4 high-half route in:\n{joined}"
    );
}

#[skuld::test]
fn split_teardown_includes_ipv6_low_half() {
    let cmds = build_split_route_teardown_commands("utun7");
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(joined.contains("::/1"), "missing IPv6 low-half route in:\n{joined}");
}

#[skuld::test]
fn split_teardown_includes_ipv6_high_half() {
    let cmds = build_split_route_teardown_commands("utun7");
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(
        joined.contains("8000::/1"),
        "missing IPv6 high-half route in:\n{joined}"
    );
}

// Interface name with spaces ==========================================================================================

#[skuld::test]
fn setup_with_spaced_interface_name_includes_full_name() {
    let cmds = build_setup_commands("utun7", ipv6_server(), ipv4_gateway(), "Wi-Fi Direct");
    let bypass = cmds[4].join(" ");
    assert!(
        bypass.contains("Wi-Fi Direct"),
        "interface name with spaces should be preserved:\n{bypass}"
    );
}

// `SystemRoutes` has private fields and no pub constructor — it is
// always produced via `SystemRouting::install`, so field-storage
// assertions aren't possible without exercising real netsh (which the
// trait seam disallows). The critical invariant ("Drop tears down via
// the trait, not the free function") is covered in bridge by
// `proxy_manager_tests::stop_runs_mock_teardown_not_real_netsh`.

// Phase classifier ====================================================================================================
//
// `is_recovery_phase` decides whether `run_commands` logs failures at debug
// (idempotent best-effort cleanup) or warn (a real error). These tests are
// regressions against accidental modification of the matcher itself —
// they reference the same `PHASE_*` constants used by `recover_routes_with`,
// so the literal phase strings live in exactly one place.

#[skuld::test]
fn recover_phases_are_classified_as_expected_failures() {
    assert!(is_recovery_phase(PHASE_RECOVER_SPLIT));
    assert!(is_recovery_phase(PHASE_RECOVER_BYPASS));
}

/// `PHASE_TEARDOWN` is best-effort: `netsh interface ip delete route
/// 0.0.0.0/1 <adapter>` and the bare `route delete <ip>` both exit
/// non-zero when the route is absent, and `setup_routes` is NOT
/// transactional — a failed mid-install leaves an arbitrary subset of
/// routes present, so teardown must tolerate missing routes silently.
/// Real teardown failures surface elsewhere (post-teardown
/// `Remove-NetAdapter` reporting, state-file persistence errors).
#[skuld::test]
fn teardown_phase_is_classified_as_expected_failures() {
    assert!(is_recovery_phase(PHASE_TEARDOWN));
}

#[skuld::test]
fn setup_phase_is_not_recovery() {
    // PHASE_SETUP is the only path that should warn on non-zero exit:
    // initial route install IS expected to succeed.
    assert!(!is_recovery_phase(PHASE_SETUP));
}

#[skuld::test]
fn recover_cover_phase_is_classified_as_expected_failures() {
    assert!(is_recovery_phase(PHASE_RECOVER_COVER));
}

// `PHASE_COVER` is macOS-only (the engage subprocess phase), so this
// assertion is too. Engage failures are real anomalies that abort the cutover.
#[cfg(target_os = "macos")]
#[skuld::test]
fn cover_engage_phase_is_not_recovery() {
    assert!(!is_recovery_phase(PHASE_COVER));
}

// recover_routes_with tests ===========================================================================================
//
// These use an injectable command runner so the test doesn't shell out.

type Captured = Vec<(String, Vec<Vec<String>>)>;

fn capturing_runner(log: &RefCell<Captured>) -> impl Fn(&[Vec<String>], &str) -> std::io::Result<()> + '_ {
    |cmds: &[Vec<String>], phase: &str| {
        log.borrow_mut().push((phase.into(), cmds.to_vec()));
        Ok(())
    }
}

#[skuld::test]
fn recover_without_state_file_is_a_noop() {
    // No state file means the previous run installed no routes (the
    // write-ordering contract persists state BEFORE any routing
    // mutation), so recovery issues zero commands. Load-bearing for the
    // parallel e2e harness: a SOCKS5-only bridge with an empty state dir
    // must not `netsh delete route` out from under a concurrent TUN
    // bridge.
    let tmp = tempfile::tempdir().unwrap();
    let log: RefCell<Captured> = RefCell::new(Vec::new());
    recover_routes_with(tmp.path(), capturing_runner(&log), |_| {}, false, || false, |_| {});

    let log = log.into_inner();
    assert!(log.is_empty(), "expected no commands with no state file, got {log:?}");
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());
}

#[skuld::test]
fn recover_with_state_file_runs_split_then_bypass_then_clears() {
    let tmp = tempfile::tempdir().unwrap();
    let persisted_state = RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: ipv4_server(),
        interface_name: "en0".into(),
    };
    state::save(tmp.path(), &persisted_state).unwrap();

    let log: RefCell<Captured> = RefCell::new(Vec::new());
    recover_routes_with(tmp.path(), capturing_runner(&log), |_| {}, false, || false, |_| {});

    let log = log.into_inner();
    assert_eq!(log.len(), 2, "expected split + bypass phases, got {log:?}");
    assert_eq!(log[0].0, PHASE_RECOVER_SPLIT);
    assert_eq!(log[1].0, PHASE_RECOVER_BYPASS);
    assert!(
        !tmp.path().join(STATE_FILE_NAME).exists(),
        "state file should be cleared after recovery"
    );
}

/// Crash recovery must inherit the loopback guard: a persisted loopback
/// `server_ip` yields no bypass command in the recover-bypass phase (only the
/// 4 split deletes). Guards against re-leaking the recovery path if the guard
/// were ever moved out of `platform_teardown_commands` to the call sites.
#[skuld::test]
fn recover_with_loopback_server_skips_bypass() {
    let tmp = tempfile::tempdir().unwrap();
    let persisted_state = RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: "127.0.0.1".parse().unwrap(),
        interface_name: "en0".into(),
    };
    state::save(tmp.path(), &persisted_state).unwrap();

    let log: RefCell<Captured> = RefCell::new(Vec::new());
    recover_routes_with(tmp.path(), capturing_runner(&log), |_| {}, false, || false, |_| {});

    let log = log.into_inner();
    assert_eq!(log[1].0, PHASE_RECOVER_BYPASS);
    assert_eq!(
        log[1].1.len(),
        4,
        "loopback recovery bypass phase must delete only the 4 splits, got {:?}",
        log[1].1
    );
    assert!(
        !mentions_addr(&log[1].1, "127.0.0.1"),
        "loopback recovery must not reference the server address, got {:?}",
        log[1].1
    );
}

#[skuld::test]
fn recover_clears_state_file_even_when_runner_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let persisted_state = RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: ipv4_server(),
        interface_name: "en0".into(),
    };
    state::save(tmp.path(), &persisted_state).unwrap();

    let failing =
        |_: &[Vec<String>], _: &str| -> std::io::Result<()> { Err(std::io::Error::other("simulated runner failure")) };
    recover_routes_with(tmp.path(), failing, |_| {}, false, || false, |_| {});

    assert!(
        !tmp.path().join(STATE_FILE_NAME).exists(),
        "state file should be cleared even when runner returns Err"
    );
}

#[skuld::test]
fn recover_invokes_cover_sweep_even_without_route_state() {
    // A crashed cutover can leave a cover engaged with the routes already torn
    // down (no route-state file). The cover sweep must run regardless.
    let tmp = tempfile::tempdir().unwrap();
    let log: RefCell<Captured> = RefCell::new(Vec::new());
    let swept = std::cell::Cell::new(false);
    recover_routes_with(
        tmp.path(),
        capturing_runner(&log),
        |_| swept.set(true),
        false,
        || false,
        |_| {},
    );

    assert!(log.into_inner().is_empty(), "no route-state file => no route commands");
    assert!(swept.get(), "recover_routes_with must invoke the cover sweep");
}

// recover_routes_with lockdown wiring =================================================================================

#[skuld::test]
fn recover_sweeps_lockdown_when_intent_off_and_present() {
    // NO route-state file — proves the lockdown decision is decoupled from
    // bridge-routes.json (keyed on the injected presence probe instead).
    let tmp = tempfile::tempdir().unwrap();
    let log: RefCell<Captured> = RefCell::new(Vec::new());
    let decided: std::cell::Cell<Option<CoverRecovery>> = std::cell::Cell::new(None);
    recover_routes_with(
        tmp.path(),
        capturing_runner(&log),
        |_| {},
        false,
        || true,
        |decision| decided.set(Some(decision)),
    );
    assert_eq!(decided.get(), Some(CoverRecovery::Sweep));
}

#[skuld::test]
fn recover_adopts_lockdown_when_intent_on_and_present() {
    let tmp = tempfile::tempdir().unwrap();
    let log: RefCell<Captured> = RefCell::new(Vec::new());
    let decided: std::cell::Cell<Option<CoverRecovery>> = std::cell::Cell::new(None);
    recover_routes_with(
        tmp.path(),
        capturing_runner(&log),
        |_| {},
        true,
        || true,
        |d| decided.set(Some(d)),
    );
    assert_eq!(decided.get(), Some(CoverRecovery::Adopt));
}

#[skuld::test]
fn recover_lockdown_noop_when_cover_absent() {
    let tmp = tempfile::tempdir().unwrap();
    let log: RefCell<Captured> = RefCell::new(Vec::new());
    let decided: std::cell::Cell<Option<CoverRecovery>> = std::cell::Cell::new(None);
    // Probe says no cover present => Noop regardless of intent.
    recover_routes_with(
        tmp.path(),
        capturing_runner(&log),
        |_| {},
        true,
        || false,
        |d| decided.set(Some(d)),
    );
    assert_eq!(decided.get(), Some(CoverRecovery::Noop), "absent cover => Noop");
}

// decide_cover_recovery ===============================================================================================

#[skuld::test]
fn cover_recovery_on_and_present_adopts() {
    assert_eq!(decide_cover_recovery(true, true), CoverRecovery::Adopt);
}

#[skuld::test]
fn cover_recovery_off_and_present_sweeps() {
    assert_eq!(decide_cover_recovery(false, true), CoverRecovery::Sweep);
}

#[skuld::test]
fn cover_recovery_absent_is_noop_regardless_of_intent() {
    assert_eq!(decide_cover_recovery(true, false), CoverRecovery::Noop);
    assert_eq!(decide_cover_recovery(false, false), CoverRecovery::Noop);
}
