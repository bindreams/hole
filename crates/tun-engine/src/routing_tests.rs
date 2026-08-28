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

/// The setup commands' bare argv, for the string-oracle assertions below.
fn setup_argv(tun_name: &str, server_ip: IpAddr, gateway: IpAddr, interface_name: &str) -> Vec<Vec<String>> {
    build_setup_commands(tun_name, server_ip, gateway, interface_name)
        .into_iter()
        .map(|c| c.argv)
        .collect()
}

/// Teardown for a run that installed everything it planned — the shape every
/// assertion that is not itself about provenance wants.
fn teardown_argv(tun_name: &str, server_ip: IpAddr, interface_name: &str) -> Vec<Vec<String>> {
    build_teardown_commands(tun_name, server_ip, interface_name, &planned_routes(server_ip))
}

fn joined(cmds: &[Vec<String>]) -> String {
    cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n")
}

fn setup_cmds_joined(server_ip: IpAddr, gateway: IpAddr) -> String {
    joined(&setup_argv("utun7", server_ip, gateway, "en0"))
}

fn teardown_cmds_joined(server_ip: IpAddr) -> String {
    joined(&teardown_argv("utun7", server_ip, "en0"))
}

/// True if any command has an argument that *is* the address (or its `/128`
/// netsh form) — a structural check for the server-bypass command, robust
/// against substring coincidences like `::1` inside `::/1`.
fn mentions_addr(cmds: &[Vec<String>], ip: &str) -> bool {
    let slash128 = format!("{ip}/128");
    cmds.iter().flatten().any(|arg| arg == ip || arg == &slash128)
}

// Success oracle ======================================================================================================
//
// route(8) exits 0 unconditionally on macOS even on failure — see
// `macos_route_command_succeeded`/`macos_route_confirmed_absent`'s docs for
// the mechanism these tests assert against. Not gated to macOS (see the
// functions' own `#[cfg(any(target_os = "macos", test, feature =
// "test-utils"))]`), so these run on every host.

fn output_with(success: bool, stdout: &str, stderr: &str) -> std::process::Output {
    #[cfg(windows)]
    let status = {
        use std::os::windows::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(u32::from(!success))
    };
    #[cfg(not(windows))]
    let status = {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(if success { 0 } else { 1 << 8 })
    };
    std::process::Output {
        status,
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

#[skuld::test]
fn macos_route_command_succeeded_true_on_clean_success() {
    let out = output_with(true, "add net 0.0.0.0/1: gateway utun7\n", "");
    assert!(macos_route_command_succeeded(&out));
}

/// `route add` on a prefix another VPN already holds exits 0 (route(8)'s
/// unconditional exit), but prints the routing socket write failure on
/// stderr — that stderr text is the only signal that distinguishes this from
/// a real success.
#[skuld::test]
fn macos_route_command_succeeded_false_on_eexist_despite_exit_zero() {
    let out = output_with(
        true, // route(8) exits 0 regardless
        "add net 0.0.0.0/1: gateway utun7: File exists\n",
        "route: writing to routing socket: File exists\n",
    );
    assert!(
        !macos_route_command_succeeded(&out),
        "an exit-0 EEXIST must not read as success"
    );
}

#[skuld::test]
fn macos_route_command_succeeded_false_on_nonzero_exit() {
    // getaddr()'s errx()/exit() aborts (e.g. an unresolvable name) DO surface
    // as a non-zero exit, ahead of rtmsg() ever running.
    let out = output_with(false, "", "route: bad address: nonsense\n");
    assert!(!macos_route_command_succeeded(&out));
}

#[skuld::test]
fn macos_route_confirmed_absent_true_on_success() {
    let out = output_with(true, "delete net 0.0.0.0/1\n", "");
    assert!(macos_route_confirmed_absent(&out));
}

#[skuld::test]
fn macos_route_confirmed_absent_true_on_not_in_table() {
    let out = output_with(
        true,
        "delete net 0.0.0.0/1: not in table\n",
        "route: writing to routing socket: not in table\n",
    );
    assert!(
        macos_route_confirmed_absent(&out),
        "ESRCH (\"not in table\") means the route is already gone"
    );
}

/// A genuine in-kernel delete failure (`EBUSY`, printed as "entry in use")
/// must NOT be treated as "already gone" — doing so would drop the route
/// from the persisted record while it is still installed.
#[skuld::test]
fn macos_route_confirmed_absent_false_on_a_real_delete_failure() {
    let out = output_with(
        true,
        "delete net 0.0.0.0/1: entry in use\n",
        "route: writing to routing socket: entry in use\n",
    );
    assert!(!macos_route_confirmed_absent(&out));
}

/// Windows has no text oracle — `route_confirmed_absent`'s non-macOS arm
/// must key on exit status alone, not unconditionally return `true`. A
/// route delete that genuinely failed (e.g. "requires elevation", measured
/// as exit 1 with no distinguishing text) must NOT be treated as gone.
#[cfg(not(target_os = "macos"))]
#[skuld::test]
fn route_confirmed_absent_keys_on_exit_status_when_not_macos() {
    assert!(route_confirmed_absent(&output_with(true, "", "")));
    assert!(!route_confirmed_absent(&output_with(
        false,
        "",
        "The requested operation requires elevation.\n"
    )));
}

// Setup tests — IPv4 server ===========================================================================================

#[skuld::test]
fn setup_generates_five_commands() {
    let cmds = setup_argv("utun7", ipv4_server(), ipv4_gateway(), "en0");
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
    for ip in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
        let server_ip: IpAddr = ip.parse().unwrap();
        let cmds = setup_argv("utun7", server_ip, ipv4_gateway(), "en0");
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
    let cmds = setup_argv("utun7", ipv6_server(), ipv4_gateway(), "en0");
    assert_eq!(cmds.len(), 5);
}

#[skuld::test]
fn setup_with_ipv6_server_includes_ipv6_bypass() {
    let cmds = setup_argv("utun7", ipv6_server(), ipv4_gateway(), "en0");
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
    let cmds = teardown_argv("utun7", ipv4_server(), "en0");
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
    let cmds = teardown_argv("utun7", server_ip, "en0");
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(joined.contains("9.8.7.6"), "missing server bypass in:\n{joined}");
}

/// Mirror of [`setup_with_loopback_server_has_no_bypass`]: no bypass was
/// installed for a loopback server, so teardown deletes only the 4 splits.
#[skuld::test]
fn teardown_with_loopback_server_has_no_bypass() {
    for ip in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
        let server_ip: IpAddr = ip.parse().unwrap();
        let cmds = teardown_argv("utun7", server_ip, "en0");
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
    let cmds = teardown_argv("utun7", ipv6_server(), "en0");
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(
        joined.contains("2001:db8::1"),
        "missing IPv6 server bypass in:\n{joined}"
    );
}

#[skuld::test]
fn teardown_with_ipv6_server_has_no_ipv4_bypass() {
    let cmds = teardown_argv("utun7", ipv6_server(), "en0");
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(
        !joined.contains("mask 255.255.255.255"),
        "IPv6 server should not have IPv4 bypass:\n{joined}"
    );
}

// Split route teardown (crash recovery) ===============================================================================

#[skuld::test]
fn split_teardown_generates_four_commands() {
    let cmds = build_split_route_teardown_commands("utun7", &SPLIT_ROUTES);
    assert_eq!(cmds.len(), 4);
}

#[skuld::test]
fn split_teardown_includes_ipv4_low_half() {
    let cmds = build_split_route_teardown_commands("utun7", &SPLIT_ROUTES);
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(
        joined.contains("0.0.0.0/1"),
        "missing IPv4 low-half route in:\n{joined}"
    );
}

#[skuld::test]
fn split_teardown_includes_ipv4_high_half() {
    let cmds = build_split_route_teardown_commands("utun7", &SPLIT_ROUTES);
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(
        joined.contains("128.0.0.0/1"),
        "missing IPv4 high-half route in:\n{joined}"
    );
}

#[skuld::test]
fn split_teardown_includes_ipv6_low_half() {
    let cmds = build_split_route_teardown_commands("utun7", &SPLIT_ROUTES);
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(joined.contains("::/1"), "missing IPv6 low-half route in:\n{joined}");
}

#[skuld::test]
fn split_teardown_includes_ipv6_high_half() {
    let cmds = build_split_route_teardown_commands("utun7", &SPLIT_ROUTES);
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(
        joined.contains("8000::/1"),
        "missing IPv6 high-half route in:\n{joined}"
    );
}

// Interface name with spaces ==========================================================================================

#[skuld::test]
fn setup_with_spaced_interface_name_includes_full_name() {
    let cmds = setup_argv("utun7", ipv6_server(), ipv4_gateway(), "Wi-Fi Direct");
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
// `is_recovery_phase` decides whether `run_one_output` logs failures at debug
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
// These use an injectable per-command runner so the test doesn't shell out.

type Captured = Vec<(String, Vec<String>)>;

/// Records every runner call — one entry per command, or a single
/// empty-argv entry when a phase has nothing to do (`run_teardown_commands`'s
/// phase-entered-empty signal). Every command "succeeds" (route confirmed
/// gone) by default.
fn capturing_runner(log: &RefCell<Captured>) -> impl Fn(&[String], &str) -> std::io::Result<bool> + '_ {
    |cmd: &[String], phase: &str| {
        log.borrow_mut().push((phase.into(), cmd.to_vec()));
        Ok(true)
    }
}

/// Real per-command entries for `phase`.
fn commands_in_phase(log: &Captured, phase: &str) -> Vec<Vec<String>> {
    log.iter()
        .filter(|(p, cmd)| p == phase && !cmd.is_empty())
        .map(|(_, cmd)| cmd.clone())
        .collect()
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
    recover_routes_with(
        tmp.path(),
        None,
        capturing_runner(&log),
        |_, _| {},
        false,
        || false,
        |_| {},
    );

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
        installed: planned_routes(ipv4_server()),
    };
    state::save(tmp.path(), &persisted_state, None).unwrap();

    let log: RefCell<Captured> = RefCell::new(Vec::new());
    recover_routes_with(
        tmp.path(),
        None,
        capturing_runner(&log),
        |_, _| {},
        false,
        || false,
        |_| {},
    );

    let log = log.into_inner();
    assert_eq!(
        commands_in_phase(&log, PHASE_RECOVER_SPLIT).len(),
        4,
        "expected the 4 split deletes, got {log:?}"
    );
    assert_eq!(
        commands_in_phase(&log, PHASE_RECOVER_BYPASS).len(),
        1,
        "expected the bypass delete, got {log:?}"
    );
    let first_bypass = log
        .iter()
        .position(|(p, _)| p == PHASE_RECOVER_BYPASS)
        .expect("bypass phase must run");
    assert!(
        log[..first_bypass].iter().all(|(p, _)| p == PHASE_RECOVER_SPLIT),
        "split phase must run before bypass phase, got {log:?}"
    );
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
    let loopback: IpAddr = "127.0.0.1".parse().unwrap();
    let persisted_state = RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: loopback,
        interface_name: "en0".into(),
        installed: planned_routes(loopback),
    };
    state::save(tmp.path(), &persisted_state, None).unwrap();

    let log: RefCell<Captured> = RefCell::new(Vec::new());
    recover_routes_with(
        tmp.path(),
        None,
        capturing_runner(&log),
        |_, _| {},
        false,
        || false,
        |_| {},
    );

    let log = log.into_inner();
    assert!(
        commands_in_phase(&log, PHASE_RECOVER_BYPASS).is_empty(),
        "a loopback server installs no bypass, so its recovery phase has nothing to delete, got {log:?}"
    );
    assert!(
        !mentions_addr(&commands_in_phase(&log, PHASE_RECOVER_SPLIT), "127.0.0.1"),
        "loopback recovery must not reference the server address, got {log:?}"
    );
}

// Deliberate design change from the old "always clear regardless of runner
// outcome" contract: a command that fails to spawn means its route may still
// be installed, so it must stay recorded for the next start to retry — never
// silently discarded. See CONTRIBUTING's Route ownership section.

#[skuld::test]
fn recover_keeps_state_file_when_every_command_fails_to_spawn() {
    let tmp = tempfile::tempdir().unwrap();
    let persisted_state = RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: ipv4_server(),
        interface_name: "en0".into(),
        installed: planned_routes(ipv4_server()),
    };
    state::save(tmp.path(), &persisted_state, None).unwrap();

    let failing = |_cmd: &[String], _phase: &str| -> std::io::Result<bool> {
        Err(std::io::Error::other("simulated runner failure"))
    };
    recover_routes_with(tmp.path(), None, failing, |_, _| {}, false, || false, |_| {});

    let remaining = state::load(tmp.path()).expect("a spawn failure on every command must keep the state file");
    assert_eq!(
        remaining.installed,
        planned_routes(ipv4_server()),
        "nothing could be confirmed gone, so every recorded route stays recorded"
    );
}

#[skuld::test]
fn recover_narrows_the_state_file_to_the_command_that_failed_to_spawn() {
    let tmp = tempfile::tempdir().unwrap();
    let persisted_state = RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: ipv4_server(),
        interface_name: "en0".into(),
        installed: planned_routes(ipv4_server()),
    };
    state::save(tmp.path(), &persisted_state, None).unwrap();

    let failing_one = |cmd: &[String], _phase: &str| -> std::io::Result<bool> {
        if cmd.iter().any(|a| a == "::/1") {
            Err(std::io::Error::other("simulated runner failure"))
        } else {
            Ok(true)
        }
    };
    recover_routes_with(tmp.path(), None, failing_one, |_, _| {}, false, || false, |_| {});

    let remaining = state::load(tmp.path()).expect("the unconfirmed route must stay recorded");
    assert_eq!(
        remaining.installed,
        vec![RouteId::SplitV6Low],
        "only the route whose delete failed to spawn should remain, got {:?}",
        remaining.installed
    );
}

/// Defensive: an `installed` id with no possible teardown command for the
/// recorded `server_ip` (unreachable from any production writer — every
/// writer keeps `installed` a subset of `planned_routes(server_ip)` — but
/// reachable via a hand-edited file) can never be attempted, so it can never
/// drain from `still_installed`. It must be dropped up front instead of
/// pinning the state file open forever.
#[skuld::test]
fn recover_drops_an_unplannable_id_instead_of_looping_forever() {
    let tmp = tempfile::tempdir().unwrap();
    let loopback: IpAddr = "127.0.0.1".parse().unwrap();
    let persisted_state = RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: loopback,
        interface_name: "en0".into(),
        installed: vec![RouteId::ServerBypass], // unplannable: loopback never installs a bypass
    };
    state::save(tmp.path(), &persisted_state, None).unwrap();

    let log: RefCell<Captured> = RefCell::new(Vec::new());
    recover_routes_with(
        tmp.path(),
        None,
        capturing_runner(&log),
        |_, _| {},
        false,
        || false,
        |_| {},
    );

    assert!(
        !tmp.path().join(STATE_FILE_NAME).exists(),
        "an unplannable id must not permanently pin the state file open"
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
        None,
        capturing_runner(&log),
        |_, _| swept.set(true),
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
        None,
        capturing_runner(&log),
        |_, _| {},
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
        None,
        capturing_runner(&log),
        |_, _| {},
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
        None,
        capturing_runner(&log),
        |_, _| {},
        true,
        || false,
        |d| decided.set(Some(d)),
    );
    assert_eq!(decided.get(), Some(CoverRecovery::Noop), "absent cover => Noop");
}

#[skuld::test]
fn recover_orders_lockdown_before_transient_sweep_and_passes_adopting() {
    let dir = tempfile::tempdir().unwrap();

    // Record the call order and the `adopting` flag passed to sweep_cover.
    let order: RefCell<Vec<&'static str>> = RefCell::new(vec![]);
    let adopting_seen: RefCell<Option<bool>> = RefCell::new(None);

    recover_routes_with(
        dir.path(),
        None,
        |_cmd, _phase| Ok(true),
        |_state_dir, adopting| {
            order.borrow_mut().push("sweep_cover");
            *adopting_seen.borrow_mut() = Some(adopting);
        },
        /* lockdown_intent = */ true,
        /* lockdown_present = */ || true, // standing cover present
        |decision| {
            order.borrow_mut().push("lockdown_recover");
            assert_eq!(decision, CoverRecovery::Adopt);
        },
    );

    assert_eq!(
        *order.borrow(),
        vec!["lockdown_recover", "sweep_cover"],
        "lockdown reconcile must run BEFORE the transient sweep"
    );
    assert_eq!(
        *adopting_seen.borrow(),
        Some(true),
        "sweep_cover must be told the standing cover is being adopted so it won't clobber it"
    );
}

#[skuld::test]
fn recover_passes_adopting_only_on_adopt() {
    // The value handed to `sweep_cover` is `adopt` (Adopt decision), NOT mere
    // cover presence. The discriminating case is Sweep (intent off + cover
    // present): a standing cover IS present, yet the transient restore must run
    // (false) because the standing ruleset is being torn down — so passing
    // "present" instead of "adopting" would wrongly skip the restore.
    // (intent, present, expected `adopting` passed to sweep_cover)
    let table = [
        (true, true, true),    // Adopt -> skip restore
        (false, true, false),  // Sweep -> restore MUST run despite cover present
        (true, false, false),  // Noop (absent) -> nothing to adopt
        (false, false, false), // Noop (absent)
    ];
    for (intent, present, expected) in table {
        let dir = tempfile::tempdir().unwrap();
        let adopting_seen: RefCell<Option<bool>> = RefCell::new(None);
        recover_routes_with(
            dir.path(),
            None,
            |_c, _p| Ok(true),
            |_d, adopting| *adopting_seen.borrow_mut() = Some(adopting),
            intent,
            || present,
            |_decision| {},
        );
        assert_eq!(
            *adopting_seen.borrow(),
            Some(expected),
            "intent={intent} present={present} => sweep_cover adopting must be {expected}"
        );
    }
}

// macOS teardown names no interface ===================================================================================
//
// Named for what is checked: the macOS delete argv carries no interface
// operand — no qualifier can be correct here, see [`RouteId`]'s doc and
// CONTRIBUTING's Route ownership section. These assertions cannot show a
// delete is SCOPED — nothing at this layer can, since the argv never reaches
// route(8) here — only that it carries no such operand; selectivity is
// asserted where it actually lives, in the provenance tests below.
#[cfg(target_os = "macos")]
mod macos_teardown_names_no_interface {
    use super::*;

    const SPLIT_DESTS: [&str; 4] = ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"];

    /// route(8) resolves the operand after `-interface` (and after `-ifscope`)
    /// through `getifaddrs`/`if_nametoindex`, and exits on failure.
    fn names_an_interface(cmd: &[String]) -> bool {
        cmd.iter().any(|a| a == "-interface" || a == "-ifscope")
    }

    #[skuld::test]
    fn split_deletes_carry_no_interface_operand() {
        let cmds = build_teardown_commands("utun7", ipv4_server(), "en0", &planned_routes(ipv4_server()));
        for cmd in &cmds {
            assert!(
                !names_an_interface(cmd),
                "a delete naming an interface aborts once that interface is gone, dropping the delete: {cmd:?}"
            );
        }
        for dest in SPLIT_DESTS {
            assert!(
                cmds.iter().any(|c| c.iter().any(|a| a == dest)),
                "no delete for {dest} in {cmds:?}"
            );
        }
    }

    #[skuld::test]
    fn crash_recovery_split_deletes_carry_no_interface_operand() {
        for cmd in build_split_route_teardown_commands("utun7", &SPLIT_ROUTES) {
            assert!(!names_an_interface(&cmd), "recovery delete names an interface: {cmd:?}");
        }
    }

    /// The install DOES name the tun — `-interface` is what makes the route
    /// point at it. Asserted here so a later "make teardown and setup
    /// symmetric" edit cannot strip it.
    #[skuld::test]
    fn split_installs_still_name_the_tun() {
        let cmds = setup_argv("utun7", ipv4_server(), ipv4_gateway(), "en0");
        for dest in SPLIT_DESTS {
            let cmd = cmds
                .iter()
                .find(|c| c.iter().any(|a| a == dest))
                .unwrap_or_else(|| panic!("no install for {dest} in {cmds:?}"));
            assert!(
                cmd.windows(2).any(|w| w[0] == "-interface" && w[1] == "utun7"),
                "install of {dest} must point at the tun: {cmd:?}"
            );
        }
    }
}

// Teardown is independent of the interface arguments ==================================================================

/// Teardown that embeds an interface name yields a command route(8) cannot
/// run once that interface is gone — which is always, since
/// `RunningState` closes the TUN before dropping the routes guard, and a
/// crashed run's utun died with the process. Driving teardown with names that
/// resolve to nothing must still emit every delete.
#[skuld::test]
fn teardown_emits_the_same_deletes_for_an_interface_that_no_longer_exists() {
    let planned = planned_routes(ipv4_server());
    let live = build_teardown_commands("hole-tun", ipv4_server(), "en0", &planned);
    let dead = build_teardown_commands("hole-tun-gone-99", ipv4_server(), "en-gone-99", &planned);
    assert!(!live.is_empty(), "teardown must emit deletes at all");
    assert_eq!(
        dead.len(),
        live.len(),
        "a dead interface must not suppress deletes — the leaked routes are exactly the ones pointing at it"
    );
    for dest in ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"] {
        assert!(
            dead.iter().any(|c| c.iter().any(|a| a == dest)),
            "missing delete for {dest} with a dead interface: {dead:?}"
        );
    }
}

#[skuld::test]
fn crash_recovery_split_teardown_survives_a_dead_tun_name() {
    let dead = build_split_route_teardown_commands("hole-tun-gone-99", &SPLIT_ROUTES);
    assert_eq!(
        dead.len(),
        SPLIT_ROUTES.len(),
        "recovery runs after the utun is gone by definition; every split delete must still be emitted: {dead:?}"
    );
}

// Teardown provenance =================================================================================================
//
// A run that never installed `0.0.0.0/1` — because another VPN already held
// it, so `route add` failed — must not delete it. The
// table holds one entry per key, so if the entry is not ours, ours is already
// gone and the delete can only take out theirs.

#[skuld::test]
fn teardown_deletes_nothing_when_nothing_was_installed() {
    let cmds = build_teardown_commands("hole-tun", ipv4_server(), "en0", &[]);
    assert!(
        cmds.is_empty(),
        "a run that installed no routes must issue no deletes, got {cmds:?}"
    );
}

#[skuld::test]
fn teardown_deletes_only_the_recorded_routes() {
    let cmds = build_teardown_commands("hole-tun", ipv4_server(), "en0", &[RouteId::SplitV4High]);
    assert_eq!(cmds.len(), 1, "expected exactly the recorded delete, got {cmds:?}");
    assert!(
        cmds[0].iter().any(|a| a == "128.0.0.0/1"),
        "wrong route deleted: {cmds:?}"
    );
    assert!(
        !cmds.iter().flatten().any(|a| a == "0.0.0.0/1"),
        "a route this run failed to install belongs to whoever holds it now: {cmds:?}"
    );
}

#[skuld::test]
fn teardown_omits_the_bypass_when_it_was_not_installed() {
    let cmds = build_teardown_commands("hole-tun", ipv4_server(), "en0", &SPLIT_ROUTES);
    assert!(
        !mentions_addr(&cmds, "1.2.3.4"),
        "a bypass absent from the record must not be deleted, got {cmds:?}"
    );
}

#[skuld::test]
fn recovery_deletes_only_the_recorded_routes() {
    let tmp = tempfile::tempdir().unwrap();
    state::save(
        tmp.path(),
        &RouteState {
            version: state::SCHEMA_VERSION,
            tun_name: "hole-tun".into(),
            server_ip: ipv4_server(),
            interface_name: "en0".into(),
            installed: vec![RouteId::SplitV6Low],
        },
        None,
    )
    .unwrap();

    let log: RefCell<Captured> = RefCell::new(Vec::new());
    recover_routes_with(
        tmp.path(),
        None,
        capturing_runner(&log),
        |_, _| {},
        false,
        || false,
        |_| {},
    );

    let log = log.into_inner();
    let split = commands_in_phase(&log, PHASE_RECOVER_SPLIT);
    assert_eq!(split.len(), 1, "expected one recorded split delete, got {log:?}");
    assert!(split[0].iter().any(|a| a == "::/1"), "wrong route: {split:?}");
    assert!(
        commands_in_phase(&log, PHASE_RECOVER_BYPASS).is_empty(),
        "the bypass was never installed, so there is nothing to delete, got {log:?}"
    );
}

/// Recovery ran the splits in its first phase; re-issuing them in the bypass
/// phase would delete whatever claimed the now-free prefix in between.
#[skuld::test]
fn recovery_bypass_phase_does_not_repeat_the_split_deletes() {
    let tmp = tempfile::tempdir().unwrap();
    state::save(
        tmp.path(),
        &RouteState {
            version: state::SCHEMA_VERSION,
            tun_name: "hole-tun".into(),
            server_ip: ipv4_server(),
            interface_name: "en0".into(),
            installed: planned_routes(ipv4_server()),
        },
        None,
    )
    .unwrap();

    let log: RefCell<Captured> = RefCell::new(Vec::new());
    recover_routes_with(
        tmp.path(),
        None,
        capturing_runner(&log),
        |_, _| {},
        false,
        || false,
        |_| {},
    );

    let log = log.into_inner();
    let split = commands_in_phase(&log, PHASE_RECOVER_SPLIT);
    let bypass = commands_in_phase(&log, PHASE_RECOVER_BYPASS);
    assert_eq!(split.len(), 4, "split phase deletes the 4 splits, got {log:?}");
    assert_eq!(
        bypass.len(),
        1,
        "bypass phase deletes the bypass and nothing else, got {log:?}"
    );
    assert!(mentions_addr(&bypass, "1.2.3.4"), "got {bypass:?}");
}

// Per-command checkpoint producer =====================================================================================
//
// The tests above validate the CONSUMER half: handed a finished `installed`
// list, teardown deletes only what it names. These validate the PRODUCER
// half — the code that builds that list one command at a time — by driving
// `setup_routes`/`run_teardown_commands` directly with a scripted runner
// (never the real `netsh`/`route`, matching the #165 test-isolation
// contract every other test in this file already relies on).

#[skuld::test]
fn setup_routes_pops_a_route_the_runner_reports_not_installed() {
    let mut installed = Vec::new();
    #[allow(clippy::disallowed_methods)]
    // exercising the checkpoint loop directly, with a scripted runner — no real netsh/route
    let result = setup_routes(
        "utun7",
        ipv4_server(),
        ipv4_gateway(),
        "en0",
        &mut installed,
        |argv| Ok(!argv.iter().any(|a| a == "128.0.0.0/1")),
        |_ids| Ok(()),
    );
    assert!(result.is_ok());
    assert!(
        !installed.contains(&RouteId::SplitV4High),
        "a route the runner reported not-installed must not be recorded: {installed:?}"
    );
    assert_eq!(installed.len(), 4, "the other 4 routes still install: {installed:?}");
}

/// A command whose spawn failed must not be rolled back — it never ran —
/// while the on-disk checkpoint from just before the failed spawn is left
/// naming it anyway (the accepted superset-of-one).
#[skuld::test]
fn setup_routes_excludes_a_spawn_failure_from_installed_but_not_from_the_last_checkpoint() {
    let mut installed = Vec::new();
    let checkpoints: RefCell<Vec<Vec<RouteId>>> = RefCell::new(Vec::new());
    #[allow(clippy::disallowed_methods)]
    // exercising the checkpoint loop directly, with a scripted runner — no real netsh/route
    let result = setup_routes(
        "utun7",
        ipv4_server(),
        ipv4_gateway(),
        "en0",
        &mut installed,
        |argv| {
            if argv.iter().any(|a| a == "::/1") {
                Err(std::io::Error::other("simulated spawn failure"))
            } else {
                Ok(true)
            }
        },
        |ids| {
            checkpoints.borrow_mut().push(ids.to_vec());
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(
        installed,
        vec![RouteId::SplitV4Low, RouteId::SplitV4High],
        "a command that never spawned must not be rolled back: {installed:?}"
    );
    let last_checkpoint = checkpoints.into_inner().pop().unwrap();
    assert_eq!(
        last_checkpoint,
        vec![RouteId::SplitV4Low, RouteId::SplitV4High, RouteId::SplitV6Low],
        "the on-disk checkpoint from just before the failed spawn must still name the \
         speculative id — that's the accepted superset-of-one, got {last_checkpoint:?}"
    );
}

/// A pre-command checkpoint failure must abort setup — this codebase must
/// not run a mutation it failed to record first — and the never-durably-
/// recorded id must not be rolled back either, same as a runner spawn
/// failure.
#[skuld::test]
fn setup_routes_aborts_when_a_pre_command_checkpoint_fails() {
    let mut installed = Vec::new();
    let mut checkpoint_calls = 0u32;
    #[allow(clippy::disallowed_methods)]
    // exercising the checkpoint loop directly, with a scripted runner — no real netsh/route
    let result = setup_routes(
        "utun7",
        ipv4_server(),
        ipv4_gateway(),
        "en0",
        &mut installed,
        |_argv| Ok(true),
        |_ids| {
            checkpoint_calls += 1;
            // Fail the pre-command checkpoint of the 2nd command (call
            // sequence: cmd1 pre, cmd1 post, cmd2 pre, ...).
            if checkpoint_calls == 3 {
                Err(std::io::Error::other("simulated checkpoint failure"))
            } else {
                Ok(())
            }
        },
    );
    assert!(
        result.is_err(),
        "a pre-command checkpoint failure must abort setup, not be swallowed"
    );
    assert_eq!(
        installed,
        vec![RouteId::SplitV4Low],
        "only the first route's runner ran before the abort: {installed:?}"
    );
}

/// The asymmetric counterpart: a POST-command checkpoint failure (the write
/// that narrows the record after a route already confirmed installed) must
/// NOT abort — setup continues, and later commands still accumulate into
/// `installed`. Only the pre-command checkpoint is load-bearing enough to stop
/// the loop.
#[skuld::test]
fn setup_routes_continues_when_a_post_command_checkpoint_fails() {
    let mut installed = Vec::new();
    let mut checkpoint_calls = 0u32;
    #[allow(clippy::disallowed_methods)]
    // exercising the checkpoint loop directly, with a scripted runner — no real netsh/route
    let result = setup_routes(
        "utun7",
        ipv4_server(),
        ipv4_gateway(),
        "en0",
        &mut installed,
        |_argv| Ok(true),
        |_ids| {
            checkpoint_calls += 1;
            // Fail the post-command checkpoint of the 1st command (call
            // sequence: cmd1 pre = 1, cmd1 post = 2, cmd2 pre = 3, ...).
            if checkpoint_calls == 2 {
                Err(std::io::Error::other("simulated checkpoint failure"))
            } else {
                Ok(())
            }
        },
    );
    assert!(
        result.is_ok(),
        "a post-command checkpoint failure must not abort setup: {result:?}"
    );
    assert_eq!(
        installed,
        planned_routes(ipv4_server()),
        "every command still ran despite the one failed post-command checkpoint write: {installed:?}"
    );
}

#[skuld::test]
fn run_teardown_commands_keeps_an_id_whose_delete_fails_to_spawn() {
    let cmds = platform_split_teardown_commands("utun7");
    let mut still_installed = SPLIT_ROUTES.to_vec();
    run_teardown_commands(
        &cmds,
        PHASE_TEARDOWN,
        &mut still_installed,
        |argv, _phase| {
            if argv.iter().any(|a| a == "::/1") {
                Err(std::io::Error::other("simulated spawn failure"))
            } else {
                Ok(true)
            }
        },
        |_ids| {},
    );
    assert_eq!(
        still_installed,
        vec![RouteId::SplitV6Low],
        "only the id whose delete failed to spawn should remain, got {still_installed:?}"
    );
}

/// A command that spawns but reports the route is NOT confirmed gone (a
/// genuine macOS in-kernel delete failure, not "already absent") must also
/// stay recorded.
#[skuld::test]
fn run_teardown_commands_keeps_an_id_the_runner_says_is_not_confirmed_gone() {
    let cmds = platform_split_teardown_commands("utun7");
    let mut still_installed = SPLIT_ROUTES.to_vec();
    run_teardown_commands(
        &cmds,
        PHASE_TEARDOWN,
        &mut still_installed,
        |argv, _phase| Ok(!argv.iter().any(|a| a == "0.0.0.0/1")),
        |_ids| {},
    );
    assert_eq!(
        still_installed,
        vec![RouteId::SplitV4Low],
        "a delete the runner did not confirm gone must stay recorded, got {still_installed:?}"
    );
}

#[skuld::test]
fn run_teardown_commands_checkpoints_after_every_command() {
    let cmds = platform_split_teardown_commands("utun7");
    let mut still_installed = SPLIT_ROUTES.to_vec();
    let checkpoints: RefCell<Vec<Vec<RouteId>>> = RefCell::new(Vec::new());
    run_teardown_commands(
        &cmds,
        PHASE_TEARDOWN,
        &mut still_installed,
        |_argv, _phase| Ok(true),
        |ids| checkpoints.borrow_mut().push(ids.to_vec()),
    );
    let checkpoints = checkpoints.into_inner();
    assert_eq!(checkpoints.len(), 4, "one checkpoint per command, got {checkpoints:?}");
    assert_eq!(
        checkpoints.last(),
        Some(&Vec::new()),
        "the last checkpoint must reflect every command having drained, got {checkpoints:?}"
    );
}

// teardown_routes — the composed function SystemRoutes::drop/install's rollback actually call =========================
//
// `run_teardown_commands` tests above cover the per-command loop in
// isolation; these cover the SPECIFIC composition `teardown_routes` performs
// on top of it — building the combined split+bypass command list from
// `installed`, threading one `still_installed` accumulator through both
// halves, and returning the final remainder.

/// An empty `installed` (e.g. an install where every planned route failed to
/// go in, or a fully-drained recovery) must be a safe no-op — not a panic.
/// The production runner (`run_one_teardown`) unconditionally indexes
/// `cmd[0]`; a prior version of this code synthesized an empty-argv "phase
/// entered, nothing to do" signal through that same runner and crashed on
/// every loopback-server crash recovery.
#[skuld::test]
fn teardown_routes_with_nothing_installed_does_not_panic() {
    #[allow(clippy::disallowed_methods)]
    // exercising teardown_routes directly, with a scripted runner — no real netsh/route
    let remaining = teardown_routes(
        "utun7",
        ipv4_server(),
        "en0",
        &[],
        |argv, _phase| panic!("no command should run for an empty installed set: {argv:?}"),
        |_ids| {},
    );
    assert!(remaining.is_empty());
}

/// Same as above but through the REAL production runner (`run_one_teardown`,
/// which spawns real subprocesses for a non-empty argv) — proves the empty
/// case never reaches it at all, closing the gap a scripted-runner-only test
/// can't: the panic this guards was in `run_one_output`'s own indexing, not
/// in anything a mock could stand in for.
#[skuld::test]
fn teardown_routes_with_nothing_installed_never_calls_the_real_runner() {
    #[allow(clippy::disallowed_methods)] // exercising teardown_routes directly with the real per-command runner
    let remaining = teardown_routes("utun7", ipv4_server(), "en0", &[], run_one_teardown, |_ids| {});
    assert!(remaining.is_empty());
}

#[skuld::test]
fn teardown_routes_deletes_everything_on_full_success() {
    #[allow(clippy::disallowed_methods)]
    // exercising teardown_routes directly, with a scripted runner — no real netsh/route
    let remaining = teardown_routes(
        "utun7",
        ipv4_server(),
        "en0",
        &planned_routes(ipv4_server()),
        |_argv, _phase| Ok(true),
        |_ids| {},
    );
    assert!(
        remaining.is_empty(),
        "a fully successful teardown leaves nothing recorded: {remaining:?}"
    );
}

#[skuld::test]
fn teardown_routes_only_attempts_the_recorded_subset() {
    let attempted: RefCell<Vec<RouteId>> = RefCell::new(Vec::new());
    #[allow(clippy::disallowed_methods)]
    // exercising teardown_routes directly, with a scripted runner — no real netsh/route
    let remaining = teardown_routes(
        "utun7",
        ipv4_server(),
        "en0",
        &[RouteId::SplitV4High, RouteId::ServerBypass],
        |argv, _phase| {
            if argv.iter().any(|a| a == "128.0.0.0/1") {
                attempted.borrow_mut().push(RouteId::SplitV4High);
            } else if argv.iter().any(|a| a == "1.2.3.4") {
                attempted.borrow_mut().push(RouteId::ServerBypass);
            } else {
                panic!("teardown_routes attempted a route outside the recorded subset: {argv:?}");
            }
            Ok(true)
        },
        |_ids| {},
    );
    assert_eq!(
        attempted.into_inner(),
        vec![RouteId::SplitV4High, RouteId::ServerBypass],
        "only the two recorded ids should have been attempted"
    );
    assert!(remaining.is_empty());
}

#[skuld::test]
fn teardown_routes_keeps_the_id_whose_delete_fails_to_spawn() {
    #[allow(clippy::disallowed_methods)]
    // exercising teardown_routes directly, with a scripted runner — no real netsh/route
    let remaining = teardown_routes(
        "utun7",
        ipv4_server(),
        "en0",
        &planned_routes(ipv4_server()),
        |argv, _phase| {
            if argv.iter().any(|a| a == "1.2.3.4") {
                Err(std::io::Error::other("simulated spawn failure"))
            } else {
                Ok(true)
            }
        },
        |_ids| {},
    );
    assert_eq!(
        remaining,
        vec![RouteId::ServerBypass],
        "only the bypass, whose delete failed to spawn, should remain: {remaining:?}"
    );
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
