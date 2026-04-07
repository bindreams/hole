use super::*;
use std::net::IpAddr;

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

// RouteGuard tests ====================================================================================================
//
// `RouteGuard::drop` shells out to `netsh`/`route` via teardown_routes AND
// clears the route-state file. These tests are about construction only, so
// every test uses `std::mem::forget(guard)` at the end to prevent Drop
// from running. The tempdir holding `state_dir` still gets cleaned up via
// its own Drop — std::mem::forget only applies to the RouteGuard itself.

#[skuld::test]
fn route_guard_stores_server_ip() {
    let tmp = tempfile::tempdir().unwrap();
    let guard = RouteGuard::new("utun7".into(), ipv4_server(), "en0".into(), tmp.path().to_path_buf());
    assert_eq!(guard.server_ip, ipv4_server());
    std::mem::forget(guard);
}

#[skuld::test]
fn route_guard_stores_tun_name() {
    let tmp = tempfile::tempdir().unwrap();
    let guard = RouteGuard::new("utun7".into(), ipv4_server(), "en0".into(), tmp.path().to_path_buf());
    assert_eq!(guard.tun_name, "utun7");
    std::mem::forget(guard);
}

#[skuld::test]
fn route_guard_stores_interface_name() {
    let tmp = tempfile::tempdir().unwrap();
    let guard = RouteGuard::new("utun7".into(), ipv4_server(), "en0".into(), tmp.path().to_path_buf());
    assert_eq!(guard.interface_name, "en0");
    std::mem::forget(guard);
}

#[skuld::test]
fn route_guard_stores_state_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().to_path_buf();
    let guard = RouteGuard::new("utun7".into(), ipv4_server(), "en0".into(), path.clone());
    assert_eq!(guard.state_dir, path);
    std::mem::forget(guard);
}

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

#[skuld::test]
fn setup_and_teardown_phases_are_not_recovery() {
    assert!(!is_recovery_phase(PHASE_SETUP));
    assert!(!is_recovery_phase(PHASE_TEARDOWN));
}

// recover_routes_with tests ===========================================================================================
//
// These use an injectable command runner so the test doesn't shell out. The
// runner records (phase, commands) into a RefCell so we can assert on it.

use crate::route_state::{self, RouteState, STATE_FILE_NAME};
use std::cell::RefCell;

type Captured = Vec<(String, Vec<Vec<String>>)>;

fn capturing_runner(log: &RefCell<Captured>) -> impl Fn(&[Vec<String>], &str) -> std::io::Result<()> + '_ {
    |cmds: &[Vec<String>], phase: &str| {
        log.borrow_mut().push((phase.into(), cmds.to_vec()));
        Ok(())
    }
}

#[skuld::test]
fn recover_without_state_file_runs_only_split_teardown() {
    let tmp = tempfile::tempdir().unwrap();
    let log: RefCell<Captured> = RefCell::new(Vec::new());
    recover_routes_with(tmp.path(), capturing_runner(&log));

    let log = log.into_inner();
    assert_eq!(log.len(), 1, "expected only split-teardown phase, got {log:?}");
    assert_eq!(log[0].0, PHASE_RECOVER_SPLIT);
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());
}

#[skuld::test]
fn recover_with_state_file_runs_split_then_bypass_then_clears() {
    let tmp = tempfile::tempdir().unwrap();
    let state = RouteState {
        version: route_state::SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: ipv4_server(),
        interface_name: "en0".into(),
    };
    route_state::save(tmp.path(), &state).unwrap();

    let log: RefCell<Captured> = RefCell::new(Vec::new());
    recover_routes_with(tmp.path(), capturing_runner(&log));

    let log = log.into_inner();
    assert_eq!(log.len(), 2, "expected split + bypass phases, got {log:?}");
    assert_eq!(log[0].0, PHASE_RECOVER_SPLIT);
    assert_eq!(log[1].0, PHASE_RECOVER_BYPASS);
    assert!(
        !tmp.path().join(STATE_FILE_NAME).exists(),
        "state file should be cleared after recovery"
    );
}

#[skuld::test]
fn recover_clears_state_file_even_when_runner_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let state = RouteState {
        version: route_state::SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: ipv4_server(),
        interface_name: "en0".into(),
    };
    route_state::save(tmp.path(), &state).unwrap();

    let failing =
        |_: &[Vec<String>], _: &str| -> std::io::Result<()> { Err(std::io::Error::other("simulated runner failure")) };
    recover_routes_with(tmp.path(), failing);

    assert!(
        !tmp.path().join(STATE_FILE_NAME).exists(),
        "state file should be cleared even when runner returns Err"
    );
}
