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
    for ip in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
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
    for ip in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
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

// Command execution failure policy ====================================================================================
//
// The first group drives the real subprocess path, so the exit code is the
// OS's, not a mock's. They spawn a shell that only sets an exit code — never a
// `route` / `netsh` command — so the #165 isolation contract holds: no host
// routing state is touched. The second group injects a recording executor to
// assert each loop's failure policy (fatal aborts, best-effort does not).

/// A command that always exits with `code`. `cfg!` is a runtime branch, so
/// both arms compile on every target.
fn always_exits(code: i32) -> Vec<String> {
    if cfg!(windows) {
        vec!["cmd".into(), "/c".into(), format!("exit {code}")]
    } else {
        vec!["sh".into(), "-c".into(), format!("exit {code}")]
    }
}

#[skuld::test]
fn a_failed_setup_command_is_an_error() {
    assert!(
        run_setup_commands(&[always_exits(3)], PHASE_SETUP).is_err(),
        "a non-zero exit during route setup must surface as an error — returning Ok \
         reports split routes that were never installed, and traffic egresses outside \
         the tunnel while the UI says it is protected (#901)"
    );
}

#[skuld::test]
fn a_successful_setup_command_is_ok() {
    assert!(run_setup_commands(&[always_exits(0)], PHASE_SETUP).is_ok());
}

#[skuld::test]
fn setup_error_carries_the_exit_code_and_position() {
    let err = run_setup_commands(&[always_exits(0), always_exits(3)], PHASE_SETUP).unwrap_err();
    let rendered = err.to_string();
    assert!(rendered.contains("exited with code 3"), "got {rendered}");
    assert!(rendered.contains("command 2 of 2"), "got {rendered}");
}

/// The message reaches a GUI toast verbatim (`StartError::Failed`), so it must
/// not carry the argv — the server IP and the upstream interface name live
/// there. They stay in the `warn` log instead.
#[skuld::test]
fn setup_error_does_not_leak_the_command_arguments() {
    let cmds = build_setup_commands("hole-tun", ipv4_server(), ipv4_gateway(), "en0");
    let err = RouteCommandError {
        program: cmds[4][0].clone(),
        index: 4,
        total: cmds.len(),
        failure: CommandFailure::Exit(1),
    };
    let rendered = err.to_string();
    assert!(!rendered.contains("1.2.3.4"), "server IP leaked into: {rendered}");
    assert!(!rendered.contains("192.168.1.1"), "gateway leaked into: {rendered}");
    assert!(!rendered.contains("en0"), "interface name leaked into: {rendered}");
}

#[skuld::test]
fn a_failed_cleanup_command_is_reported_but_not_returned() {
    // The return type has no error channel at all; the count is the only signal.
    let report = run_cleanup_commands(&[always_exits(3), always_exits(0)], PHASE_TEARDOWN);
    assert_eq!(
        report,
        CleanupReport {
            attempted: 2,
            failed: 1
        }
    );
}

/// Records every command the loop hands it and fails the ones whose index is
/// in `fail_at`.
fn recording_exec<'a>(
    seen: &'a RefCell<Vec<String>>,
    fail_at: &'a [usize],
) -> impl FnMut(&[String], &str) -> Result<(), CommandFailure> + 'a {
    move |cmd: &[String], _phase: &str| {
        let index = seen.borrow().len();
        seen.borrow_mut().push(cmd.join(" "));
        if fail_at.contains(&index) {
            return Err(CommandFailure::Exit(1));
        }
        Ok(())
    }
}

fn numbered_commands(count: usize) -> Vec<Vec<String>> {
    (0..count).map(|i| vec!["route".into(), format!("cmd{i}")]).collect()
}

#[skuld::test]
fn setup_stops_at_the_first_failing_command() {
    // Fatal phase: keeping on mutating the route table after a failure would
    // build a route set nobody can reason about.
    let seen: RefCell<Vec<String>> = RefCell::new(Vec::new());
    let err = run_setup_with(&numbered_commands(5), PHASE_SETUP, recording_exec(&seen, &[1])).unwrap_err();

    assert_eq!(err.index, 1);
    assert_eq!(
        *seen.borrow(),
        vec!["route cmd0", "route cmd1"],
        "no command after the failure may be issued"
    );
}

#[skuld::test]
fn cleanup_issues_every_command_even_when_all_of_them_fail() {
    // Best-effort phase: stopping early would strand the routes the remaining
    // deletes name, leaving the user worse off than if Hole had never run.
    let seen: RefCell<Vec<String>> = RefCell::new(Vec::new());
    let report = run_cleanup_with(
        &numbered_commands(5),
        PHASE_TEARDOWN,
        recording_exec(&seen, &[0, 1, 2, 3, 4]),
    );

    assert_eq!(
        report,
        CleanupReport {
            attempted: 5,
            failed: 5
        }
    );
    assert_eq!(seen.borrow().len(), 5, "every cleanup command must be issued");
}

#[skuld::test]
fn cleanup_survives_a_spawn_failure_and_keeps_going() {
    // A spawn failure used to `?` out of the loop, skipping every remaining
    // delete. It is now just another failed command.
    let seen: RefCell<Vec<String>> = RefCell::new(Vec::new());
    let report = run_cleanup_with(&numbered_commands(3), PHASE_RECOVER_SPLIT, |cmd, _| {
        seen.borrow_mut().push(cmd.join(" "));
        Err(CommandFailure::Spawn(std::io::Error::other("no such program")))
    });

    assert_eq!(
        report,
        CleanupReport {
            attempted: 3,
            failed: 3
        }
    );
    assert_eq!(seen.borrow().len(), 3);
}

// SystemRouting::install failure path =================================================================================
//
// `install_with` injects the two phases, so these drive the real
// state-file/rollback logic without issuing a route command (#165).

fn failed_setup(_: &str, _: IpAddr, _: IpAddr, _: &str) -> Result<(), RouteCommandError> {
    Err(RouteCommandError {
        program: "route".into(),
        index: 0,
        total: 5,
        failure: CommandFailure::Exit(1),
    })
}

#[skuld::test]
fn install_hands_back_no_guard_when_a_setup_command_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let routing = SystemRouting::new(tmp.path().to_path_buf(), None);

    let result = routing.install_with(
        "hole-tun",
        ipv4_server(),
        ipv4_gateway(),
        "en0",
        failed_setup,
        |_, _, _| CleanupReport::default(),
    );

    assert!(
        result.is_err(),
        "a failed route install must not return a guard — the guard IS the bridge's \
         evidence that the tunnel carries traffic (#901)"
    );
}

#[skuld::test]
fn install_rolls_back_and_clears_state_when_a_setup_command_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let routing = SystemRouting::new(tmp.path().to_path_buf(), None);
    let torn_down: RefCell<Vec<(String, IpAddr, String)>> = RefCell::new(Vec::new());

    let result = routing.install_with(
        "hole-tun",
        ipv4_server(),
        ipv4_gateway(),
        "en0",
        failed_setup,
        |tun, ip, iface| {
            torn_down.borrow_mut().push((tun.into(), ip, iface.into()));
            CleanupReport {
                attempted: 5,
                failed: 4,
            }
        },
    );

    assert!(result.is_err());
    assert_eq!(
        *torn_down.borrow(),
        vec![("hole-tun".to_string(), ipv4_server(), "en0".to_string())],
        "the half-installed route set must be torn down with the same identity it was installed under"
    );
    assert!(
        !tmp.path().join(STATE_FILE_NAME).exists(),
        "a rolled-back install must leave no route-state file for the next start to replay"
    );
}

#[skuld::test]
fn install_persists_state_before_the_setup_phase_runs() {
    // A SIGKILL between the two would otherwise leak routes with no on-disk
    // record, defeating crash recovery.
    let tmp = tempfile::tempdir().unwrap();
    let routing = SystemRouting::new(tmp.path().to_path_buf(), None);
    let state_seen = std::cell::Cell::new(false);

    let _ = routing.install_with(
        "hole-tun",
        ipv4_server(),
        ipv4_gateway(),
        "en0",
        |_, _, _, _| {
            state_seen.set(tmp.path().join(STATE_FILE_NAME).exists());
            failed_setup("", ipv4_server(), ipv4_gateway(), "")
        },
        |_, _, _| CleanupReport::default(),
    );

    assert!(
        state_seen.get(),
        "route-state must be on disk before any route mutation"
    );
}

#[skuld::test]
fn install_returns_a_guard_when_every_setup_command_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let routing = SystemRouting::new(tmp.path().to_path_buf(), None);

    let routes = routing
        .install_with(
            "hole-tun",
            ipv4_server(),
            ipv4_gateway(),
            "en0",
            |_, _, _, _| Ok(()),
            |_, _, _| unreachable!("a successful install must not roll back"),
        )
        .expect("install must succeed when the setup phase does");

    assert!(tmp.path().join(STATE_FILE_NAME).exists());
    // `SystemRoutes::drop` issues REAL netsh/route commands and a
    // `Remove-NetAdapter`; the #165 contract forbids that from a unit test.
    std::mem::forget(routes);
}

// Phase classifier ====================================================================================================
//
// `is_recovery_phase` decides whether a failed command logs at debug
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

fn capturing_runner(log: &RefCell<Captured>) -> impl Fn(&[Vec<String>], &str) -> CleanupReport + '_ {
    |cmds: &[Vec<String>], phase: &str| {
        log.borrow_mut().push((phase.into(), cmds.to_vec()));
        CleanupReport {
            attempted: cmds.len(),
            failed: 0,
        }
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
    recover_routes_with(tmp.path(), capturing_runner(&log), |_, _| {}, false, || false, |_| {});

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
    state::save(tmp.path(), &persisted_state, None).unwrap();

    let log: RefCell<Captured> = RefCell::new(Vec::new());
    recover_routes_with(tmp.path(), capturing_runner(&log), |_, _| {}, false, || false, |_| {});

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
    state::save(tmp.path(), &persisted_state, None).unwrap();

    let log: RefCell<Captured> = RefCell::new(Vec::new());
    recover_routes_with(tmp.path(), capturing_runner(&log), |_, _| {}, false, || false, |_| {});

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
fn recover_clears_state_file_even_when_every_command_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let persisted_state = RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: ipv4_server(),
        interface_name: "en0".into(),
    };
    state::save(tmp.path(), &persisted_state, None).unwrap();

    let failing = |cmds: &[Vec<String>], _: &str| CleanupReport {
        attempted: cmds.len(),
        failed: cmds.len(),
    };
    recover_routes_with(tmp.path(), failing, |_, _| {}, false, || false, |_| {});

    assert!(
        !tmp.path().join(STATE_FILE_NAME).exists(),
        "state file should be cleared even when every recovery command failed"
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
        |_cmds, _phase| CleanupReport::default(),
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
            |_c, _p| CleanupReport::default(),
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
