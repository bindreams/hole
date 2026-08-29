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

fn gateway_info(gateway_ip: IpAddr, interface_name: &str, ipv6_available: bool) -> GatewayInfo {
    GatewayInfo {
        gateway_ip,
        interface_name: interface_name.into(),
        interface_index: 1,
        ipv6_available,
    }
}

/// The ordinary upstream: IPv4 gateway, `en0`, IPv6 reachable — so every setup
/// command is fatal.
fn ipv4_gw() -> GatewayInfo {
    gateway_info(ipv4_gateway(), "en0", true)
}

fn argvs(cmds: &[SetupCommand]) -> Vec<Vec<String>> {
    cmds.iter().map(|c| c.argv.clone()).collect()
}

fn is_ipv6_split(cmd: &SetupCommand) -> bool {
    cmd.argv.iter().any(|arg| arg == "::/1" || arg == "8000::/1")
}

fn setup_cmds_joined(server_ip: IpAddr, gateway: &GatewayInfo) -> String {
    // These callers aren't testing IPv6 fatality — hold the TUN's own IPv6
    // binding fixed at "available" (see the dedicated fatality tests below
    // for `false`).
    let cmds = build_setup_commands("utun7", server_ip, gateway, true);
    cmds.iter().map(|c| c.argv.join(" ")).collect::<Vec<_>>().join("\n")
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
    let cmds = build_setup_commands("utun7", ipv4_server(), &ipv4_gw(), true);
    assert_eq!(cmds.len(), 5);
}

#[skuld::test]
fn setup_includes_low_half_route() {
    let joined = setup_cmds_joined(ipv4_server(), &ipv4_gw());
    assert!(joined.contains("0.0.0.0/1"), "missing low-half route in:\n{joined}");
}

#[skuld::test]
fn setup_includes_high_half_route() {
    let joined = setup_cmds_joined(ipv4_server(), &ipv4_gw());
    assert!(joined.contains("128.0.0.0/1"), "missing high-half route in:\n{joined}");
}

#[skuld::test]
fn setup_includes_ipv6_low_half_route() {
    let joined = setup_cmds_joined(ipv4_server(), &ipv4_gw());
    assert!(joined.contains("::/1"), "missing IPv6 low-half route in:\n{joined}");
}

#[skuld::test]
fn setup_includes_ipv6_high_half_route() {
    let joined = setup_cmds_joined(ipv4_server(), &ipv4_gw());
    assert!(
        joined.contains("8000::/1"),
        "missing IPv6 high-half route in:\n{joined}"
    );
}

#[skuld::test]
fn setup_includes_server_bypass_route() {
    let server_ip: IpAddr = "5.6.7.8".parse().unwrap();
    let joined = setup_cmds_joined(server_ip, &ipv4_gw());
    assert!(joined.contains("5.6.7.8"), "missing server bypass route in:\n{joined}");
}

#[skuld::test]
fn setup_bypass_uses_original_gateway() {
    let server_ip: IpAddr = "5.6.7.8".parse().unwrap();
    let gateway = gateway_info("10.0.0.1".parse().unwrap(), "en0", true);
    let joined = setup_cmds_joined(server_ip, &gateway);
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
        let cmds = build_setup_commands("utun7", server_ip, &ipv4_gw(), true);
        assert_eq!(
            cmds.len(),
            4,
            "loopback {ip}: expected only 4 split routes, got {cmds:?}"
        );
        assert!(
            !mentions_addr(&argvs(&cmds), ip),
            "loopback {ip}: no command should reference the server address, got {cmds:?}"
        );
    }
}

// Setup tests — IPv6 server ===========================================================================================

#[skuld::test]
fn setup_with_ipv6_server_generates_five_commands() {
    let cmds = build_setup_commands("utun7", ipv6_server(), &ipv4_gw(), true);
    assert_eq!(cmds.len(), 5);
}

#[skuld::test]
fn setup_with_ipv6_server_includes_ipv6_bypass() {
    let cmds = build_setup_commands("utun7", ipv6_server(), &ipv4_gw(), true);
    // The bypass is the last command (index 4)
    let bypass = cmds[4].argv.join(" ");
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
    let joined = setup_cmds_joined(ipv6_server(), &ipv4_gw());
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
    let gateway = gateway_info(ipv4_gateway(), "Wi-Fi Direct", true);
    let cmds = build_setup_commands("utun7", ipv6_server(), &gateway, true);
    let bypass = cmds[4].argv.join(" ");
    assert!(
        bypass.contains("Wi-Fi Direct"),
        "interface name with spaces should be preserved:\n{bypass}"
    );
}

// Per-command fatality — see `SetupCommand`'s doc for the contract these pin. =========================================

#[skuld::test]
fn ipv6_splits_are_not_fatal_when_the_tun_has_no_ipv6() {
    // Gateway (upstream) says IPv6 IS reachable — proves fatality is decided
    // from `tun_ipv6_available`, not `GatewayInfo::ipv6_available`.
    let cmds = build_setup_commands("hole-tun", ipv4_server(), &ipv4_gw(), false);
    let v6: Vec<_> = cmds.iter().filter(|c| is_ipv6_split(c)).collect();
    assert_eq!(v6.len(), 2, "expected the ::/1 and 8000::/1 adds, got {v6:?}");
    for cmd in v6 {
        assert!(
            !cmd.fatal,
            "IPv6 split must not abort a TUN with no IPv6 binding: {cmd:?}"
        );
    }
}

#[skuld::test]
fn every_setup_command_is_fatal_when_the_tun_has_ipv6() {
    // Gateway (upstream) says IPv6 is UNREACHABLE — proves the TUN's own
    // binding is what matters, not upstream reachability.
    let cmds = build_setup_commands(
        "hole-tun",
        ipv4_server(),
        &gateway_info(ipv4_gateway(), "en0", false),
        true,
    );
    for cmd in &cmds {
        assert!(cmd.fatal, "every command is fatal when the TUN has IPv6 bound: {cmd:?}");
    }
}

/// The IPv4 splits and the server bypass carry the whole tunnel; nothing about
/// the TUN's IPv6 binding may downgrade them.
#[skuld::test]
fn ipv4_splits_and_bypass_stay_fatal_without_tun_ipv6() {
    let cmds = build_setup_commands("hole-tun", ipv4_server(), &ipv4_gw(), false);
    let non_v6: Vec<_> = cmds.iter().filter(|c| !is_ipv6_split(c)).collect();
    assert_eq!(non_v6.len(), 3, "expected 2 IPv4 splits + bypass, got {non_v6:?}");
    for cmd in non_v6 {
        assert!(cmd.fatal, "{cmd:?} must stay fatal");
    }
}

/// Fails exactly the two IPv6 adds, as an IPv6-unbound adapter does.
fn fail_ipv6_splits(
    seen: &RefCell<Vec<String>>,
) -> impl FnMut(&[String], FatalPhase) -> Result<(), CommandFailure> + '_ {
    |argv: &[String], _| {
        seen.borrow_mut().push(argv.join(" "));
        if argv.iter().any(|arg| arg == "::/1" || arg == "8000::/1") {
            return Err(CommandFailure::Exit(1));
        }
        Ok(())
    }
}

#[skuld::test]
fn a_host_without_ipv6_installs_even_when_both_ipv6_adds_fail() {
    let cmds = build_setup_commands("hole-tun", ipv4_server(), &ipv4_gw(), false);
    let seen: RefCell<Vec<String>> = RefCell::new(Vec::new());
    let result = run_setup_with(&cmds, FatalPhase::Setup, fail_ipv6_splits(&seen));

    assert!(
        result.is_ok(),
        "a host with no IPv6 stack has no IPv6 traffic to leak — aborting the start \
         here loses the whole tunnel and avoids nothing, got {result:?}"
    );
    assert_eq!(
        seen.borrow().len(),
        cmds.len(),
        "a non-fatal failure must not short-circuit the rest of the phase"
    );
}

#[skuld::test]
fn a_host_with_ipv6_aborts_when_an_ipv6_add_fails() {
    let cmds = build_setup_commands("hole-tun", ipv4_server(), &ipv4_gw(), true);
    let seen: RefCell<Vec<String>> = RefCell::new(Vec::new());
    let err = run_setup_with(&cmds, FatalPhase::Setup, fail_ipv6_splits(&seen)).unwrap_err();

    assert_eq!(err.index, 2, "the ::/1 add is command 3 of the phase");
    assert_eq!(seen.borrow().len(), 3, "no command after a fatal failure may be issued");
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

fn fatal_exits(code: i32) -> SetupCommand {
    SetupCommand {
        argv: always_exits(code),
        fatal: true,
    }
}

#[skuld::test]
fn a_failed_setup_command_is_an_error() {
    assert!(
        run_setup_commands(&[fatal_exits(3)], FatalPhase::Setup).is_err(),
        "a non-zero exit during route setup must surface as an error — returning Ok \
         reports split routes that were never installed, and traffic egresses outside \
         the tunnel while the UI says it is protected (#901)"
    );
}

#[skuld::test]
fn a_successful_setup_command_is_ok() {
    assert!(run_setup_commands(&[fatal_exits(0)], FatalPhase::Setup).is_ok());
}

#[skuld::test]
fn setup_error_carries_the_exit_code_and_position() {
    let err = run_setup_commands(&[fatal_exits(0), fatal_exits(3)], FatalPhase::Setup).unwrap_err();
    let rendered = err.to_string();
    assert!(rendered.contains("exited with code 3"), "got {rendered}");
    assert!(rendered.contains("command 2 of 2"), "got {rendered}");
}

/// Tolerating a non-fatal command must not soften the phase around it: a later
/// fatal failure still aborts, and is the one reported.
#[skuld::test]
fn a_non_fatal_failure_does_not_mask_a_later_fatal_one() {
    let cmds = vec![
        SetupCommand {
            argv: always_exits(1),
            fatal: false,
        },
        fatal_exits(7),
    ];
    let err = run_setup_commands(&cmds, FatalPhase::Setup).unwrap_err();
    assert_eq!(err.index, 1);
    assert!(err.to_string().contains("exited with code 7"), "got {err}");
}

/// The message reaches a GUI toast verbatim (`StartError::Failed`), so it must
/// not carry the argv — the server IP and the upstream interface name live
/// there. They stay in the `warn` log instead.
#[skuld::test]
fn setup_error_does_not_leak_the_command_arguments() {
    let cmds = build_setup_commands("hole-tun", ipv4_server(), &ipv4_gw(), true);
    let err = RouteCommandError {
        program: cmds[4].argv[0].clone(),
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
    let report = run_cleanup_commands(&[always_exits(3), always_exits(0)], BestEffortPhase::Teardown);
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
fn recording_exec<'a, P>(
    seen: &'a RefCell<Vec<String>>,
    fail_at: &'a [usize],
) -> impl FnMut(&[String], P) -> Result<(), CommandFailure> + 'a {
    move |cmd: &[String], _phase: P| {
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

fn numbered_setup_commands(count: usize) -> Vec<SetupCommand> {
    numbered_commands(count).into_iter().map(SetupCommand::fatal).collect()
}

#[skuld::test]
fn setup_stops_at_the_first_failing_command() {
    // Fatal phase: keeping on mutating the route table after a failure would
    // build a route set nobody can reason about.
    let seen: RefCell<Vec<String>> = RefCell::new(Vec::new());
    let err = run_setup_with(
        &numbered_setup_commands(5),
        FatalPhase::Setup,
        recording_exec(&seen, &[1]),
    )
    .unwrap_err();

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
        BestEffortPhase::Teardown,
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
    let report = run_cleanup_with(&numbered_commands(3), BestEffortPhase::RecoverSplit, |cmd, _| {
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

fn failed_setup(_: &str, _: IpAddr, _: &GatewayInfo) -> Result<(), RouteCommandError> {
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

    let result = routing.install_with("hole-tun", ipv4_server(), &ipv4_gw(), failed_setup, |_, _, _| {
        CleanupReport::default()
    });

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

    let result = routing.install_with("hole-tun", ipv4_server(), &ipv4_gw(), failed_setup, |tun, ip, iface| {
        torn_down.borrow_mut().push((tun.into(), ip, iface.into()));
        CleanupReport {
            attempted: 5,
            failed: 4,
        }
    });

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
        &ipv4_gw(),
        |_, _, gw| {
            state_seen.set(tmp.path().join(STATE_FILE_NAME).exists());
            failed_setup("", ipv4_server(), gw)
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
            &ipv4_gw(),
            |_, _, _| Ok(()),
            |_, _, _| unreachable!("a successful install must not roll back"),
        )
        .expect("install must succeed when the setup phase does");

    assert!(tmp.path().join(STATE_FILE_NAME).exists());
    // `SystemRoutes::drop` issues REAL netsh/route commands and a
    // `Remove-NetAdapter`; the #165 contract forbids that from a unit test.
    std::mem::forget(routes);
}

// Phase classification ================================================================================================
//
// Nothing to test at runtime. Each runner accepts only its own phase type, and
// the command types differ too (`SetupCommand` vs `Vec<String>`), so
// `run_cleanup_commands(cmds, FatalPhase::Setup)` — the misuse the old
// `debug_assert` back-stopped — no longer compiles. Which family is which is a
// `const` pinned by the `const _: () = assert!(..)` pair in routing.rs; a
// `#[skuld::test]` over it would be vacuous (clippy::assertions_on_constants).

// recover_routes_with tests ===========================================================================================
//
// These use an injectable command runner so the test doesn't shell out.

type Captured = Vec<(BestEffortPhase, Vec<Vec<String>>)>;

fn capturing_runner(log: &RefCell<Captured>) -> impl Fn(&[Vec<String>], BestEffortPhase) -> CleanupReport + '_ {
    |cmds: &[Vec<String>], phase: BestEffortPhase| {
        log.borrow_mut().push((phase, cmds.to_vec()));
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
    recover_routes_with(
        tmp.path(),
        None,
        "hole-tun",
        capturing_runner(&log),
        |_, _| {},
        Intent::Off,
        || Absent,
        |_, _| {},
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
    };
    state::save(tmp.path(), &persisted_state, None).unwrap();

    let log: RefCell<Captured> = RefCell::new(Vec::new());
    recover_routes_with(
        tmp.path(),
        None,
        "hole-tun",
        capturing_runner(&log),
        |_, _| {},
        Intent::Off,
        || Absent,
        |_, _| {},
    );

    let log = log.into_inner();
    assert_eq!(log.len(), 2, "expected split + bypass phases, got {log:?}");
    assert_eq!(log[0].0, BestEffortPhase::RecoverSplit);
    assert_eq!(log[1].0, BestEffortPhase::RecoverBypass);
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
    recover_routes_with(
        tmp.path(),
        None,
        "hole-tun",
        capturing_runner(&log),
        |_, _| {},
        Intent::Off,
        || Absent,
        |_, _| {},
    );

    let log = log.into_inner();
    assert_eq!(log[1].0, BestEffortPhase::RecoverBypass);
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

    let failing = |cmds: &[Vec<String>], _: BestEffortPhase| CleanupReport {
        attempted: cmds.len(),
        failed: cmds.len(),
    };
    recover_routes_with(
        tmp.path(),
        None,
        "hole-tun",
        failing,
        |_, _| {},
        Intent::Off,
        || Absent,
        |_, _| {},
    );

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
        None,
        "hole-tun",
        capturing_runner(&log),
        |_, _| swept.set(true),
        Intent::Off,
        || Absent,
        |_, _| {},
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
        "hole-tun",
        capturing_runner(&log),
        |_, _| {},
        Intent::Off,
        || Live,
        |decision, _| decided.set(Some(decision)),
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
        "hole-tun",
        capturing_runner(&log),
        |_, _| {},
        Intent::On,
        || Live,
        |d, _| decided.set(Some(d)),
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
        "hole-tun",
        capturing_runner(&log),
        |_, _| {},
        Intent::On,
        || Absent,
        |d, _| decided.set(Some(d)),
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
        "hole-tun",
        |_cmds, _phase| CleanupReport::default(),
        |_state_dir, adopting| {
            order.borrow_mut().push("sweep_cover");
            *adopting_seen.borrow_mut() = Some(adopting);
        },
        /* lockdown_intent = */ Intent::On,
        /* lockdown_present = */ || Live, // standing cover present
        |decision, _tun_name| {
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
    // The value handed to `sweep_cover` is `adopt` (the Adopt decision), NOT
    // mere cover presence. The discriminating case is Sweep (recorded off +
    // cover present): a standing cover IS present, yet the transient restore
    // must run (false) because the standing ruleset is being torn down — so
    // passing "present" instead of "adopting" would wrongly skip the restore.
    // Walked over the whole decision table so a new cell cannot be added
    // without deciding what the transient sweep is told.
    for (intent, presence, action, _) in RECOVERY_TABLE {
        let expected = action == Adopt;
        let dir = tempfile::tempdir().unwrap();
        let adopting_seen: RefCell<Option<bool>> = RefCell::new(None);
        recover_routes_with(
            dir.path(),
            None,
            "hole-tun",
            |_c, _p| CleanupReport::default(),
            |_d, adopting| *adopting_seen.borrow_mut() = Some(adopting),
            intent,
            || presence,
            |_decision, _tun_name| {},
        );
        assert_eq!(
            *adopting_seen.borrow(),
            Some(expected),
            "intent={intent:?} presence={presence:?} => sweep_cover adopting must be {expected}"
        );
    }
}

// decide_cover_recovery ===============================================================================================

use failclosed::lockdown_state::Intent;
use CoverPresence::{Absent, Indeterminate, Live, Recorded, Unreachable};
use CoverRecovery::{Adopt, Noop, Sweep};

#[skuld::test]
fn cover_recovery_on_and_present_adopts() {
    assert_eq!(decide_cover_recovery(Intent::On, Live).action, Adopt);
}

#[skuld::test]
fn cover_recovery_off_and_present_sweeps() {
    assert_eq!(decide_cover_recovery(Intent::Off, Live).action, Sweep);
}

#[skuld::test]
fn cover_recovery_absent_is_noop_regardless_of_intent() {
    assert_eq!(decide_cover_recovery(Intent::On, Absent).action, Noop);
    assert_eq!(decide_cover_recovery(Intent::Off, Absent).action, Noop);
}

/// Every cell of the intent x presence table, spelled out. A wildcard here
/// would let a new variant of either axis silently inherit a neighbour's
/// answer; the point of the table is that each cell was decided.
const RECOVERY_TABLE: [(Intent, CoverPresence, CoverRecovery, bool); 20] = [
    (Intent::On, Live, Adopt, false),
    (Intent::On, Recorded, Adopt, false),
    (Intent::On, Indeterminate, Adopt, false),
    (Intent::On, Absent, Noop, false),
    (Intent::On, Unreachable, Noop, false),
    (Intent::Off, Live, Sweep, false),
    (Intent::Off, Recorded, Sweep, false),
    (Intent::Off, Indeterminate, Sweep, false),
    (Intent::Off, Absent, Noop, false),
    (Intent::Off, Unreachable, Noop, false),
    (Intent::Unset, Live, Adopt, true),
    (Intent::Unset, Recorded, Adopt, false),
    (Intent::Unset, Indeterminate, Noop, false),
    (Intent::Unset, Absent, Noop, false),
    (Intent::Unset, Unreachable, Noop, false),
    (Intent::Unreadable, Live, Adopt, true),
    (Intent::Unreadable, Recorded, Adopt, false),
    (Intent::Unreadable, Indeterminate, Adopt, false),
    (Intent::Unreadable, Absent, Noop, false),
    (Intent::Unreadable, Unreachable, Noop, false),
];

#[skuld::test]
fn cover_recovery_is_closed_over_intent_and_presence() {
    for (intent, presence, action, record_intent_on) in RECOVERY_TABLE {
        assert_eq!(
            decide_cover_recovery(intent, presence),
            Recovery {
                action,
                record_intent_on,
                presence,
            },
            "cell ({intent:?}, {presence:?}) must be {action:?} with record_intent_on={record_intent_on}"
        );
    }
}

#[skuld::test]
fn cover_recovery_sweeps_only_on_an_explicit_off_intent() {
    // Sweep is the only action that removes protection, and a missing or
    // unreadable intent file is not an "off".
    for (intent, presence, action, _) in RECOVERY_TABLE {
        if action == Sweep {
            assert_eq!(
                intent,
                Intent::Off,
                "only an explicit recorded off may sweep, not {intent:?} ({presence:?})"
            );
        }
    }
    for presence in [Live, Recorded, Indeterminate, Absent, Unreachable] {
        for intent in [Intent::On, Intent::Unset, Intent::Unreadable] {
            assert_ne!(
                decide_cover_recovery(intent, presence).action,
                Sweep,
                "({intent:?}, {presence:?}) must not sweep"
            );
        }
    }
}

#[skuld::test]
fn cover_recovery_records_intent_only_on_a_live_cover() {
    // The repair write is grounded in a positive OS measurement, never
    // inferred from a state file or from an unusable answer.
    for intent in [Intent::On, Intent::Off, Intent::Unset, Intent::Unreadable] {
        for presence in [Live, Recorded, Indeterminate, Absent, Unreachable] {
            let expected = presence == Live && matches!(intent, Intent::Unset | Intent::Unreadable);
            assert_eq!(
                decide_cover_recovery(intent, presence).record_intent_on,
                expected,
                "({intent:?}, {presence:?}) record_intent_on must be {expected}"
            );
        }
    }
}

#[skuld::test]
fn cover_recovery_is_inert_when_the_os_is_unreachable_or_clean() {
    for presence in [Absent, Unreachable] {
        for intent in [Intent::On, Intent::Off, Intent::Unset, Intent::Unreadable] {
            assert_eq!(
                decide_cover_recovery(intent, presence),
                Recovery {
                    action: Noop,
                    record_intent_on: false,
                    presence,
                },
                "({intent:?}, {presence:?}) must be wholly inert"
            );
        }
    }
}

// Recovery dispatch ===================================================================================================

#[skuld::test]
fn adopt_deletes_nothing() {
    // With a wiped state dir, `Unset` x `Live` decides Adopt — and Adopt must
    // not disengage a cover that may belong to a RUNNING first bridge. After
    // the volatile-permit refresh moved into `engage_lockdown`, `Sweep` is the
    // only decision that can disengage the standing cover on either platform.
    // (`Adopt` separately runs a narrow, provably-safe TUN-permit reclaim —
    // see `recover_lockdown` — which is not part of this classification.)
    use failclosed::RecoveryDispatch;
    assert_eq!(
        failclosed::recovery_dispatch(Adopt),
        RecoveryDispatch::Inert,
        "Adopt must not disengage the standing cover"
    );
    assert_eq!(
        failclosed::recovery_dispatch(Noop),
        RecoveryDispatch::Inert,
        "Noop must not disengage the standing cover"
    );
    assert_eq!(
        failclosed::recovery_dispatch(Sweep),
        RecoveryDispatch::Disengage,
        "Sweep is the sole cover-disengaging decision"
    );
}

#[skuld::test]
fn only_an_explicit_off_intent_reaches_the_os() {
    // Walk the whole decision table and confirm the only cells that dispatch an
    // OS mutation are the recorded-off ones. A regression that made a wiped
    // state dir sweep again shows up here as an extra dispatching cell.
    use failclosed::RecoveryDispatch;
    for (intent, presence, _, _) in RECOVERY_TABLE {
        let action = decide_cover_recovery(intent, presence).action;
        if failclosed::recovery_dispatch(action) == RecoveryDispatch::Disengage {
            assert_eq!(
                intent,
                Intent::Off,
                "({intent:?}, {presence:?}) reached the OS without an explicit recorded off"
            );
        }
    }
}

// Intent repair =======================================================================================================
//
// The repair's `owner` is not asserted here. `chown_path` is a no-op off macOS,
// and a self-chown is vacuous (the temp dir is already self-owned), so only a
// macOS root lane chowning to a FIXED foreign uid could discriminate it — the
// same reason `hole_common::update_marker`'s owner proof rides
// `crates/hole/tests/elevated_ownership_privileged.rs`.

/// Drive `recover_routes_with` over `dir` with an injected presence, deriving
/// the intent from `dir` exactly as production does.
fn recover_over(dir: &Path, presence: CoverPresence) -> (Recovery, Option<CoverRecovery>) {
    let acted: std::cell::Cell<Option<CoverRecovery>> = std::cell::Cell::new(None);
    let decision = recover_routes_with(
        dir,
        None,
        "hole-tun",
        |_c, _p| CleanupReport::default(),
        |_d, _a| {},
        failclosed::lockdown_state::load_intent(dir),
        || presence,
        |action, _tun_name| acted.set(Some(action)),
    );
    (decision, acted.get())
}

#[skuld::test]
fn recover_records_the_intent_when_a_live_cover_has_none() {
    // A wiped or recreated state dir over a LIVE cover: the measured truth is
    // written back and the cover is adopted, not swept.
    let dir = tempfile::tempdir().unwrap();
    let (decision, acted) = recover_over(dir.path(), Live);

    assert_eq!(
        acted,
        Some(Adopt),
        "a live cover with no recorded intent must be adopted"
    );
    assert_eq!(decision.action, Adopt);
    assert!(decision.record_intent_on);
    assert_eq!(
        failclosed::lockdown_state::load_intent(dir.path()),
        Intent::On,
        "the repaired intent must be on disk so the tray keeps offering the escape"
    );
}

#[skuld::test]
fn recover_records_the_intent_before_acting_on_it() {
    // Ordering, not just outcome: the write lands before the recover action, so
    // a crash between them leaves an intent that reads armed rather than one
    // that would sweep on the next start.
    let dir = tempfile::tempdir().unwrap();
    let observed: std::cell::Cell<Option<Intent>> = std::cell::Cell::new(None);
    recover_routes_with(
        dir.path(),
        None,
        "hole-tun",
        |_c, _p| CleanupReport::default(),
        |_d, _a| {},
        failclosed::lockdown_state::load_intent(dir.path()),
        || Live,
        |_action, _tun_name| observed.set(Some(failclosed::lockdown_state::load_intent(dir.path()))),
    );
    assert_eq!(
        observed.get(),
        Some(Intent::On),
        "the intent file must already read On when the recover action runs"
    );
}

#[skuld::test]
fn recover_repairs_an_unreadable_intent_over_a_live_cover() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(failclosed::lockdown_state::STATE_FILE_NAME),
        b"{corrupt",
    )
    .unwrap();
    let (decision, acted) = recover_over(dir.path(), Live);

    assert_eq!(acted, Some(Adopt));
    assert!(decision.record_intent_on);
    assert_eq!(failclosed::lockdown_state::load_intent(dir.path()), Intent::On);
}

#[skuld::test]
fn recover_writes_no_intent_file_when_the_host_is_clean() {
    // Every fresh install takes this path. Manufacturing an `enabled: true`
    // here would arm the kill switch on a host that never had a cover.
    let dir = tempfile::tempdir().unwrap();
    let (decision, acted) = recover_over(dir.path(), Absent);

    assert_eq!(acted, Some(Noop));
    assert!(!decision.record_intent_on);
    assert!(
        !dir.path().join(failclosed::lockdown_state::STATE_FILE_NAME).exists(),
        "a clean host must leave no intent file behind"
    );
}

#[skuld::test]
fn recover_adopts_but_writes_nothing_from_a_recorded_only_cover() {
    // macOS: a reboot flushes pf while the state file survives, so pf answers
    // "no label" and the file says a cover was engaged. Both halves matter — no
    // manufactured preference on disk, and an Adopt the bridge carries into
    // `standing_cover_expected` so the stale ruleset gets refreshed.
    let dir = tempfile::tempdir().unwrap();
    let (decision, acted) = recover_over(dir.path(), Recorded);

    assert_eq!(acted, Some(Adopt));
    assert!(!decision.record_intent_on);
    assert!(
        !dir.path().join(failclosed::lockdown_state::STATE_FILE_NAME).exists(),
        "an unconfirmed record is not grounds to write a preference"
    );
}

#[skuld::test]
fn recover_prefers_its_own_route_state_tun_name_over_the_fallback() {
    // The TUN-permit reclaim (#881 finding 2) prefers THIS bridge's own prior
    // run's device — sourced from its own bridge-routes.json — over the
    // caller-supplied fallback, using a DIFFERENT name for each so the
    // precedence is actually exercised, not merely consistent with either.
    let dir = tempfile::tempdir().unwrap();
    let persisted_state = RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "hole-tun-from-state".into(),
        server_ip: ipv4_server(),
        interface_name: "en0".into(),
    };
    state::save(dir.path(), &persisted_state, None).unwrap();

    let seen: RefCell<Option<Option<String>>> = RefCell::new(None);
    recover_routes_with(
        dir.path(),
        None,
        "hole-tun-fallback",
        |_c, _p| CleanupReport::default(),
        |_d, _a| {},
        Intent::On,
        || Live,
        |_decision, tun_name| *seen.borrow_mut() = Some(tun_name.map(str::to_owned)),
    );
    assert_eq!(
        seen.into_inner(),
        Some(Some("hole-tun-from-state".to_owned())),
        "lockdown_recover must see this run's own persisted TUN name, not the fallback"
    );
}

#[skuld::test]
fn recover_falls_back_to_the_given_tun_name_when_no_route_state_exists() {
    // Finding 3 (#898 rework): `bridge-routes.json`'s lifetime is
    // anti-correlated with the condition the reclaim needs — a clean
    // `Cutover` teardown (the canonical Adopt path, kill switch armed) drops
    // the file via `SystemRoutes::drop` before recovery ever runs, and a
    // crashed run's file is deleted by THIS SAME startup's recovery before
    // reaching this call. Passing `None` here skipped the reclaim outright on
    // both; the caller-supplied name must be used instead.
    let dir = tempfile::tempdir().unwrap();
    let seen: RefCell<Option<Option<String>>> = RefCell::new(None);
    recover_routes_with(
        dir.path(),
        None,
        "hole-tun-fallback",
        |_c, _p| CleanupReport::default(),
        |_d, _a| {},
        Intent::On,
        || Live,
        |_decision, tun_name| *seen.borrow_mut() = Some(tun_name.map(str::to_owned)),
    );
    assert_eq!(
        seen.into_inner(),
        Some(Some("hole-tun-fallback".to_owned())),
        "with no route-state file, lockdown_recover must still see the caller's own device name"
    );
}

#[skuld::test]
fn recover_returns_its_decision() {
    // The bridge records the returned action as "a standing cover is live this
    // run", which is what keeps the escape visible independently of the file.
    for (intent, presence, action, record_intent_on) in RECOVERY_TABLE {
        let dir = tempfile::tempdir().unwrap();
        let returned = recover_routes_with(
            dir.path(),
            None,
            "hole-tun",
            |_c, _p| CleanupReport::default(),
            |_d, _a| {},
            intent,
            || presence,
            |_action, _tun_name| {},
        );
        assert_eq!(
            returned,
            Recovery {
                action,
                record_intent_on,
                presence,
            },
            "recover_routes_with must return the decision for ({intent:?}, {presence:?})"
        );
    }
}

// Recovery-path redaction =============================================================================================
//
// `203.0.113.7` is RFC 5737 documentation space and appears in no other
// fixture. The registry is process-global and grow-only; these run under
// `cargo nextest`, one process per test.

const RECOVERED_ADDR: &str = "203.0.113.7";

/// A subscriber whose file-shaped sink is wrapped exactly as production
/// wraps the log-file writer, so the assertions are about the bytes that
/// would land on disk.
fn redacting_capture() -> (
    impl tracing::Subscriber + Send + Sync,
    garter::test_utils::WaitableWriter,
) {
    let writer = garter::test_utils::WaitableWriter::new();
    let sink = writer.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || util::redact::RedactingWriter::new(sink.clone()))
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    (subscriber, writer)
}

/// Drives the production argv log site for every command, without spawning.
fn logging_runner(log: &RefCell<Captured>) -> impl Fn(&[Vec<String>], BestEffortPhase) -> CleanupReport + '_ {
    |cmds: &[Vec<String>], phase: BestEffortPhase| {
        for cmd in cmds {
            log_route_command(phase.name(), cmd);
        }
        log.borrow_mut().push((phase, cmds.to_vec()));
        CleanupReport {
            attempted: cmds.len(),
            failed: 0,
        }
    }
}

fn recovery_state(server_ip: &str) -> RouteState {
    RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: server_ip.parse().unwrap(),
        interface_name: "en0".into(),
    }
}

#[skuld::test]
fn recovery_reports_scope_and_redacts_its_argv() {
    let tmp = tempfile::tempdir().unwrap();
    state::save(tmp.path(), &recovery_state(RECOVERED_ADDR), None).unwrap();

    let (subscriber, writer) = redacting_capture();
    let log: RefCell<Captured> = RefCell::new(Vec::new());
    {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        recover_routes_with(
            tmp.path(),
            None,
            "hole-tun",
            logging_runner(&log),
            |_, _| {},
            Intent::Off,
            || Absent,
            |_, _| {},
        );
    }

    // The commands themselves still carry the address — recovery needs it.
    let captured = log.into_inner();
    assert!(
        captured
            .iter()
            .any(|(phase, cmds)| *phase == BestEffortPhase::RecoverBypass && mentions_addr(cmds, RECOVERED_ADDR)),
        "recovery must still tear down the real bypass route: {captured:?}"
    );

    let text = writer.snapshot();
    assert!(
        !text.contains(RECOVERED_ADDR),
        "a prior run's server IP reached the log on every restart after a crash:\n{text}"
    );
    assert!(
        text.contains("server_scope"),
        "the recovery line must still say what kind of endpoint it was:\n{text}"
    );
}

#[skuld::test]
fn route_command_log_is_redacted_by_the_sink() {
    // The guard against someone later hand-redacting `cmd`: the argv line is
    // deliberately left alone, because the sink covers it.
    util::redact::arm("<server:aaaaaaaa>", [RECOVERED_ADDR.to_string()]);
    let (subscriber, writer) = redacting_capture();
    {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        log_route_command(
            BestEffortPhase::Teardown.name(),
            &["route".to_string(), "delete".to_string(), RECOVERED_ADDR.to_string()],
        );
    }
    let text = writer.snapshot();
    assert!(!text.contains(RECOVERED_ADDR), "argv line leaked the address:\n{text}");
    assert!(text.contains("<server:aaaaaaaa>"), "argv line lost its token:\n{text}");
}

#[skuld::test]
fn recovery_then_start_links_the_two_tokens() {
    // Crash, then reconnect to the same server: without last-wins arming and
    // the join announcement, one endpoint reads as two unlinked tokens in the
    // collected bundle — in the most common circumstance a bundle is taken.
    const ENTRY_TOKEN: &str = "<server:8f2a1c04>";
    let ip: std::net::IpAddr = RECOVERED_ADDR.parse().unwrap();

    let (subscriber, writer) = redacting_capture();
    {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        util::redact::arm_ip(util::redact::RECOVERED_TOKEN, ip);
        util::redact::arm_ip(ENTRY_TOKEN, ip);
    }

    assert_eq!(
        util::redact::redact_str("remote 203.0.113.7:8388"),
        format!("remote {ENTRY_TOKEN}:8388"),
        "the reconnect's token must supersede the recovery token"
    );
    let text = writer.snapshot();
    assert!(
        text.contains(util::redact::RECOVERED_TOKEN) && text.contains(ENTRY_TOKEN),
        "the join announcement must name both tokens:\n{text}"
    );
    assert!(
        !text.contains(RECOVERED_ADDR),
        "the announcement named the address:\n{text}"
    );
}
