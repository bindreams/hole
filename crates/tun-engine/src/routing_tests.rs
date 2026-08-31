use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr};

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
        next_hop: gateway::NextHop::Via(gateway_ip),
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

/// An on-link upstream: no gateway, `en0`, IPv6 reachable. `gateway_ip` stays
/// the unspecified address — same representation `classify_hop` produces —
/// so a test asserting the on-link path is not silently keyed on a real
/// address instead of `next_hop`.
fn on_link_gw() -> GatewayInfo {
    GatewayInfo {
        gateway_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        next_hop: gateway::NextHop::OnLink,
        interface_name: "en0".into(),
        interface_index: 1,
        ipv6_available: true,
    }
}

fn argvs(cmds: &[SetupCommand]) -> Vec<Vec<String>> {
    cmds.iter().map(|c| c.argv.clone()).collect()
}

fn is_ipv6_split(cmd: &SetupCommand) -> bool {
    cmd.argv.iter().any(|arg| arg == "::/1" || arg == "8000::/1")
}

/// The setup commands' bare argv, for the string-oracle assertions below.
/// Holds the TUN's own IPv6 binding fixed at "available" — the dedicated
/// fatality tests below cover `false`.
fn setup_argv(tun_name: &str, server_ip: IpAddr, gateway: &GatewayInfo) -> Vec<Vec<String>> {
    argvs(&build_setup_commands(tun_name, server_ip, gateway, true))
}

/// Teardown for a run that installed everything it planned, scoped by
/// `ipv4_gateway()` — the shape every assertion that is not itself about
/// provenance or gateway-scoping wants.
fn teardown_argv(tun_name: &str, server_ip: IpAddr, interface_name: &str) -> Vec<Vec<String>> {
    build_teardown_commands(
        tun_name,
        server_ip,
        interface_name,
        Some(ipv4_gateway()),
        state::RouteForm::Via,
    )
    .into_iter()
    .map(|c| c.argv)
    .collect()
}

fn joined(cmds: &[Vec<String>]) -> String {
    cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n")
}

fn setup_cmds_joined(server_ip: IpAddr, gateway: &GatewayInfo) -> String {
    joined(&setup_argv("utun7", server_ip, gateway))
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
    let cmds = setup_argv("utun7", ipv4_server(), &ipv4_gw());
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

/// The symmetric IPv4 form to the IPv6 bypass just above: on-link names the
/// interface and no gateway, exactly as `setup_with_ipv6_server_includes_ipv6_bypass`
/// does for IPv6. Windows-only: macOS has no interface-scoped IPv4 bypass
/// form (`reject_macos_on_link` refuses on-link before `install` is ever
/// reached there), so this `GatewayInfo` shape cannot occur on that platform.
#[cfg(target_os = "windows")]
#[skuld::test]
fn an_on_link_upstream_installs_an_interface_scoped_bypass() {
    let server_ip: IpAddr = "5.6.7.8".parse().unwrap();
    let cmds = setup_argv("utun7", server_ip, &on_link_gw());
    // The bypass is the last command (index 4), same position the IPv6 form
    // (`setup_with_ipv6_server_includes_ipv6_bypass`) uses.
    let bypass = cmds[4].join(" ");
    assert!(bypass.contains("5.6.7.8"), "missing server bypass route in:\n{bypass}");
    assert!(bypass.contains("en0"), "missing interface name in:\n{bypass}");
    assert!(
        !bypass.split_whitespace().any(|tok| tok == "0.0.0.0"),
        "an on-link bypass must not name the unspecified address as a gateway:\n{bypass}"
    );
}

/// The regression guard that matters most: an ordinary gateway upstream must
/// keep installing today's gateway-scoped bypass, never the interface-scoped
/// form — `an_on_link_upstream_installs_an_interface_scoped_bypass` is the
/// new capability, this is the existing one it must not disturb.
#[skuld::test]
fn a_gateway_upstream_still_installs_the_gateway_form() {
    let server_ip: IpAddr = "5.6.7.8".parse().unwrap();
    let joined = setup_cmds_joined(server_ip, &ipv4_gw());
    assert!(
        joined.contains(&ipv4_gateway().to_string()),
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
        let cmds = setup_argv("utun7", server_ip, &ipv4_gw());
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
    let cmds = setup_argv("utun7", ipv6_server(), &ipv4_gw());
    assert_eq!(cmds.len(), 5);
}

#[skuld::test]
fn setup_with_ipv6_server_includes_ipv6_bypass() {
    let cmds = setup_argv("utun7", ipv6_server(), &ipv4_gw());
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
    let joined = setup_cmds_joined(ipv6_server(), &ipv4_gw());
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
    let joined = joined(&teardown_argv("utun7", server_ip, "en0"));
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
    let joined = joined(&teardown_argv("utun7", ipv6_server(), "en0"));
    assert!(
        joined.contains("2001:db8::1"),
        "missing IPv6 server bypass in:\n{joined}"
    );
}

#[skuld::test]
fn teardown_with_ipv6_server_has_no_ipv4_bypass() {
    let joined = joined(&teardown_argv("utun7", ipv6_server(), "en0"));
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
    let joined = cmds.iter().map(|c| c.argv.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(
        joined.contains("0.0.0.0/1"),
        "missing IPv4 low-half route in:\n{joined}"
    );
}

#[skuld::test]
fn split_teardown_includes_ipv4_high_half() {
    let cmds = build_split_route_teardown_commands("utun7");
    let joined = cmds.iter().map(|c| c.argv.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(
        joined.contains("128.0.0.0/1"),
        "missing IPv4 high-half route in:\n{joined}"
    );
}

#[skuld::test]
fn split_teardown_includes_ipv6_low_half() {
    let cmds = build_split_route_teardown_commands("utun7");
    let joined = cmds.iter().map(|c| c.argv.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(joined.contains("::/1"), "missing IPv6 low-half route in:\n{joined}");
}

#[skuld::test]
fn split_teardown_includes_ipv6_high_half() {
    let cmds = build_split_route_teardown_commands("utun7");
    let joined = cmds.iter().map(|c| c.argv.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(
        joined.contains("8000::/1"),
        "missing IPv6 high-half route in:\n{joined}"
    );
}

// Interface name with spaces ==========================================================================================

#[skuld::test]
fn setup_with_spaced_interface_name_includes_full_name() {
    let gateway = gateway_info(ipv4_gateway(), "Wi-Fi Direct", true);
    let cmds = setup_argv("utun7", ipv6_server(), &gateway);
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
fn fail_ipv6_splits(seen: &RefCell<Vec<String>>) -> impl Fn(&[String], FatalPhase) -> Result<(), CommandFailure> + '_ {
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
    let mut installed = Vec::new();
    let result = run_setup_commands(&cmds, &mut installed, fail_ipv6_splits(&seen), |_| Ok(()));

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
    let mut installed = Vec::new();
    let err = run_setup_commands(&cmds, &mut installed, fail_ipv6_splits(&seen), |_| Ok(())).unwrap_err();

    assert_eq!(err.index, 2, "the ::/1 add is command 3 of the phase");
    assert_eq!(seen.borrow().len(), 3, "no command after a fatal failure may be issued");
}

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
        id: RouteId::SplitV4Low,
        argv: always_exits(code),
        fatal: true,
    }
}

#[skuld::test]
fn a_failed_setup_command_is_an_error() {
    let mut installed = Vec::new();
    assert!(
        run_setup_commands(&[fatal_exits(3)], &mut installed, exec_one::<FatalPhase>, |_| Ok(())).is_err(),
        "a non-zero exit during route setup must surface as an error — returning Ok \
         reports split routes that were never installed, and traffic egresses outside \
         the tunnel while the UI says it is protected (#901)"
    );
}

#[skuld::test]
fn a_successful_setup_command_is_ok() {
    let mut installed = Vec::new();
    assert!(run_setup_commands(&[fatal_exits(0)], &mut installed, exec_one::<FatalPhase>, |_| Ok(())).is_ok());
}

#[skuld::test]
fn setup_error_carries_the_exit_code_and_position() {
    let mut installed = Vec::new();
    let err = run_setup_commands(
        &[fatal_exits(0), fatal_exits(3)],
        &mut installed,
        exec_one::<FatalPhase>,
        |_| Ok(()),
    )
    .unwrap_err();
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
            id: RouteId::SplitV6Low,
            argv: always_exits(1),
            fatal: false,
        },
        fatal_exits(7),
    ];
    let mut installed = Vec::new();
    let err = run_setup_commands(&cmds, &mut installed, exec_one::<FatalPhase>, |_| Ok(())).unwrap_err();
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

/// Records every runner call. Every command "succeeds" (route confirmed
/// gone) by default.
type Captured = Vec<(BestEffortPhase, Vec<String>)>;

fn capturing_runner(log: &RefCell<Captured>) -> impl Fn(&[String], BestEffortPhase) -> Result<(), CommandFailure> + '_ {
    |cmd: &[String], phase: BestEffortPhase| {
        log.borrow_mut().push((phase, cmd.to_vec()));
        Ok(())
    }
}

/// Real per-command argv entries for `phase`.
fn commands_in_phase(log: &Captured, phase: BestEffortPhase) -> Vec<Vec<String>> {
    log.iter()
        .filter(|(p, _)| *p == phase)
        .map(|(_, cmd)| cmd.clone())
        .collect()
}

#[skuld::test]
fn a_failed_cleanup_command_is_reported_but_not_returned() {
    // No error channel at all: `run_teardown_commands` narrows `still_installed`
    // instead, and a failed command simply stays in it.
    let cmds = vec![
        RouteCommand::new(RouteId::SplitV4Low, always_exits(3)),
        RouteCommand::new(RouteId::SplitV4High, always_exits(0)),
    ];
    let mut still_installed = vec![RouteId::SplitV4Low, RouteId::SplitV4High];
    run_teardown_commands(
        &cmds,
        BestEffortPhase::Teardown,
        &mut still_installed,
        exec_one::<BestEffortPhase>,
        |_| {},
    );
    assert_eq!(
        still_installed,
        vec![RouteId::SplitV4Low],
        "the failed command's id must stay recorded, the successful one must drain"
    );
}

/// Records every command the loop hands it and fails the ones whose index is
/// in `fail_at`.
fn recording_exec<'a>(
    seen: &'a RefCell<Vec<String>>,
    fail_at: &'a [usize],
) -> impl Fn(&[String], BestEffortPhase) -> Result<(), CommandFailure> + 'a {
    move |cmd: &[String], _phase: BestEffortPhase| {
        let index = seen.borrow().len();
        seen.borrow_mut().push(cmd.join(" "));
        if fail_at.contains(&index) {
            return Err(CommandFailure::Exit(1));
        }
        Ok(())
    }
}

fn numbered_teardown_commands(count: usize) -> Vec<RouteCommand> {
    // Cycle through RouteId's 5 variants — the id's identity is irrelevant to
    // these best-effort-loop tests, only "every command gets issued" is.
    const IDS: [RouteId; 5] = [
        RouteId::SplitV4Low,
        RouteId::SplitV4High,
        RouteId::SplitV6Low,
        RouteId::SplitV6High,
        RouteId::ServerBypass,
    ];
    (0..count)
        .map(|i| RouteCommand::new(IDS[i % IDS.len()], vec!["route".into(), format!("cmd{i}")]))
        .collect()
}

#[skuld::test]
fn cleanup_issues_every_command_even_when_all_of_them_fail() {
    // Best-effort phase: stopping early would strand the routes the remaining
    // deletes name, leaving the user worse off than if Hole had never run.
    let seen: RefCell<Vec<String>> = RefCell::new(Vec::new());
    let cmds = numbered_teardown_commands(5);
    let mut still_installed: Vec<RouteId> = cmds.iter().map(|c| c.id).collect();
    run_teardown_commands(
        &cmds,
        BestEffortPhase::Teardown,
        &mut still_installed,
        recording_exec(&seen, &[0, 1, 2, 3, 4]),
        |_| {},
    );

    assert_eq!(seen.borrow().len(), 5, "every cleanup command must be issued");
    assert_eq!(still_installed.len(), 5, "nothing confirmed gone, so nothing drains");
}

#[skuld::test]
fn cleanup_survives_a_spawn_failure_and_keeps_going() {
    // A spawn failure used to `?` out of the loop, skipping every remaining
    // delete. It is now just another failed command.
    let seen: RefCell<Vec<String>> = RefCell::new(Vec::new());
    let cmds = numbered_teardown_commands(3);
    let mut still_installed: Vec<RouteId> = cmds.iter().map(|c| c.id).collect();
    run_teardown_commands(
        &cmds,
        BestEffortPhase::RecoverSplit,
        &mut still_installed,
        |cmd, _| {
            seen.borrow_mut().push(cmd.join(" "));
            Err(CommandFailure::Spawn(std::io::Error::other("no such program")))
        },
        |_| {},
    );

    assert_eq!(seen.borrow().len(), 3);
    assert_eq!(still_installed.len(), 3);
}

#[skuld::test]
fn setup_stops_at_the_first_failing_command() {
    // Fatal phase: keeping on mutating the route table after a failure would
    // build a route set nobody can reason about.
    let seen: RefCell<Vec<String>> = RefCell::new(Vec::new());
    let cmds: Vec<SetupCommand> = (0..5)
        .map(|i| SetupCommand {
            id: RouteId::SplitV4Low,
            argv: vec!["route".into(), format!("cmd{i}")],
            fatal: true,
        })
        .collect();
    let mut installed = Vec::new();
    let err = run_setup_commands(
        &cmds,
        &mut installed,
        |cmd, _| {
            let index = seen.borrow().len();
            seen.borrow_mut().push(cmd.join(" "));
            if index == 1 {
                Err(CommandFailure::Exit(1))
            } else {
                Ok(())
            }
        },
        |_| Ok(()),
    )
    .unwrap_err();

    assert_eq!(err.index, 1);
    assert_eq!(
        *seen.borrow(),
        vec!["route cmd0", "route cmd1"],
        "no command after the failure may be issued"
    );
}

// `SystemRouting::install_with` failure path ==========================================================================
//
// `install_with` injects the two per-command runners, so these drive the real
// checkpointing/rollback logic without issuing a route command (#165).

#[skuld::test]
fn install_hands_back_no_guard_when_a_setup_command_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let routing = SystemRouting::new(tmp.path().to_path_buf(), None);

    let result = routing.install_with(
        "hole-tun",
        ipv4_server(),
        &ipv4_gw(),
        |_, _| Err(CommandFailure::Exit(1)),
        |_, _| Ok(()),
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
    let torn_down: RefCell<Vec<Vec<String>>> = RefCell::new(Vec::new());

    // The first (fatal) command confirms installed; the second fails —
    // a genuine partial install, so the guard's own rollback has something
    // real to tear down.
    let calls = std::cell::Cell::new(0u32);
    let result = routing.install_with(
        "hole-tun",
        ipv4_server(),
        &ipv4_gw(),
        |_, _| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                Ok(())
            } else {
                Err(CommandFailure::Exit(1))
            }
        },
        |argv, _| {
            torn_down.borrow_mut().push(argv.to_vec());
            Ok(())
        },
    );

    assert!(result.is_err());
    assert!(
        !torn_down.borrow().is_empty(),
        "the half-installed route set must be torn down"
    );
    assert!(
        !tmp.path().join(STATE_FILE_NAME).exists(),
        "a fully-confirmed rollback must leave no route-state file for the next start to replay"
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
        |_, _| {
            state_seen.set(tmp.path().join(STATE_FILE_NAME).exists());
            Err(CommandFailure::Exit(1))
        },
        |_, _| Ok(()),
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
            |_, _| Ok(()),
            |_, _| unreachable!("a successful install must not roll back"),
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
// the command types differ too (`SetupCommand` vs `RouteCommand`), so a
// mismatched pairing no longer compiles. Which family is which is a `const`
// pinned by the `const _: () = assert!(..)` pair in routing.rs; a
// `#[skuld::test]` over it would be vacuous (clippy::assertions_on_constants).

// recover_routes_with tests ===========================================================================================
//
// These use an injectable per-command runner so the test doesn't shell out.

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
        failclosed::lockdown_state::Intent::Off,
        || CoverPresence::Absent,
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
        original_gateway: Some(ipv4_gateway()),
        route_form: state::RouteForm::Via,
        installed: planned_routes(ipv4_server()),
        stale: Vec::new(),
    };
    state::save(tmp.path(), &persisted_state, None).unwrap();

    let log: RefCell<Captured> = RefCell::new(Vec::new());
    recover_routes_with(
        tmp.path(),
        None,
        "hole-tun",
        capturing_runner(&log),
        |_, _| {},
        failclosed::lockdown_state::Intent::Off,
        || CoverPresence::Absent,
        |_, _| {},
    );

    let log = log.into_inner();
    assert_eq!(
        commands_in_phase(&log, BestEffortPhase::RecoverSplit).len(),
        4,
        "expected the 4 split deletes, got {log:?}"
    );
    assert_eq!(
        commands_in_phase(&log, BestEffortPhase::RecoverBypass).len(),
        1,
        "expected the bypass delete, got {log:?}"
    );
    let first_bypass = log
        .iter()
        .position(|(p, _)| *p == BestEffortPhase::RecoverBypass)
        .expect("bypass phase must run");
    assert!(
        log[..first_bypass]
            .iter()
            .all(|(p, _)| *p == BestEffortPhase::RecoverSplit),
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
        original_gateway: Some(ipv4_gateway()),
        route_form: state::RouteForm::Via,
        installed: planned_routes(loopback),
        stale: Vec::new(),
    };
    state::save(tmp.path(), &persisted_state, None).unwrap();

    let log: RefCell<Captured> = RefCell::new(Vec::new());
    recover_routes_with(
        tmp.path(),
        None,
        "hole-tun",
        capturing_runner(&log),
        |_, _| {},
        failclosed::lockdown_state::Intent::Off,
        || CoverPresence::Absent,
        |_, _| {},
    );

    let log = log.into_inner();
    assert!(
        commands_in_phase(&log, BestEffortPhase::RecoverBypass).is_empty(),
        "a loopback server installs no bypass, so its recovery phase has nothing to delete, got {log:?}"
    );
    assert!(
        !mentions_addr(&commands_in_phase(&log, BestEffortPhase::RecoverSplit), "127.0.0.1"),
        "loopback recovery must not reference the server address, got {log:?}"
    );
}

// Deliberate design choice, preserved across the #907 merge: teardown/recovery
// has no error channel, so a command that fails to SPAWN means its route may
// still be installed — it must stay recorded for the next start to retry,
// never silently discarded. See CONTRIBUTING's Route ownership section.

#[skuld::test]
fn recover_keeps_state_file_when_every_command_fails_to_spawn() {
    let tmp = tempfile::tempdir().unwrap();
    let persisted_state = RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: ipv4_server(),
        interface_name: "en0".into(),
        original_gateway: Some(ipv4_gateway()),
        route_form: state::RouteForm::Via,
        installed: planned_routes(ipv4_server()),
        stale: Vec::new(),
    };
    state::save(tmp.path(), &persisted_state, None).unwrap();

    let failing = |_cmd: &[String], _phase: BestEffortPhase| -> Result<(), CommandFailure> {
        Err(CommandFailure::Spawn(std::io::Error::other("simulated runner failure")))
    };
    recover_routes_with(
        tmp.path(),
        None,
        "hole-tun",
        failing,
        |_, _| {},
        failclosed::lockdown_state::Intent::Off,
        || CoverPresence::Absent,
        |_, _| {},
    );

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
        original_gateway: Some(ipv4_gateway()),
        route_form: state::RouteForm::Via,
        installed: planned_routes(ipv4_server()),
        stale: Vec::new(),
    };
    state::save(tmp.path(), &persisted_state, None).unwrap();

    let failing_one = |cmd: &[String], _phase: BestEffortPhase| -> Result<(), CommandFailure> {
        if cmd.iter().any(|a| a == "::/1") {
            Err(CommandFailure::Spawn(std::io::Error::other("simulated runner failure")))
        } else {
            Ok(())
        }
    };
    recover_routes_with(
        tmp.path(),
        None,
        "hole-tun",
        failing_one,
        |_, _| {},
        failclosed::lockdown_state::Intent::Off,
        || CoverPresence::Absent,
        |_, _| {},
    );

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
        original_gateway: Some(ipv4_gateway()),
        route_form: state::RouteForm::Via,
        installed: vec![RouteId::ServerBypass], // unplannable: loopback never installs a bypass
        stale: Vec::new(),
    };
    state::save(tmp.path(), &persisted_state, None).unwrap();

    let log: RefCell<Captured> = RefCell::new(Vec::new());
    recover_routes_with(
        tmp.path(),
        None,
        "hole-tun",
        capturing_runner(&log),
        |_, _| {},
        failclosed::lockdown_state::Intent::Off,
        || CoverPresence::Absent,
        |_, _| {},
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
        "hole-tun",
        capturing_runner(&log),
        |_, _| swept.set(true),
        failclosed::lockdown_state::Intent::Off,
        || CoverPresence::Absent,
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
        failclosed::lockdown_state::Intent::Off,
        || CoverPresence::Live,
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
        failclosed::lockdown_state::Intent::On,
        || CoverPresence::Live,
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
        failclosed::lockdown_state::Intent::On,
        || CoverPresence::Absent,
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
        |_cmd, _phase| Ok(()),
        |_state_dir, adopting| {
            order.borrow_mut().push("sweep_cover");
            *adopting_seen.borrow_mut() = Some(adopting);
        },
        /* lockdown_intent = */ failclosed::lockdown_state::Intent::On,
        /* lockdown_present = */ || CoverPresence::Live, // standing cover present
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
            |_c, _p| Ok(()),
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

// Recovery dispatch ===================================================================================================

#[skuld::test]
fn adopt_deletes_nothing() {
    // With a wiped state dir, `Unset` x `Live` decides Adopt — and Adopt must
    // not disengage a cover that may belong to a RUNNING first bridge. After
    // the volatile-permit refresh moved into `engage_lockdown`, `Sweep` is the
    // only decision that can disengage the standing cover on either platform.
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
        |_c, _p| Ok(()),
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
        |_c, _p| Ok(()),
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
        original_gateway: Some(ipv4_gateway()),
        route_form: state::RouteForm::Via,
        installed: planned_routes(ipv4_server()),
        stale: Vec::new(),
    };
    state::save(dir.path(), &persisted_state, None).unwrap();

    let seen: RefCell<Option<Option<String>>> = RefCell::new(None);
    recover_routes_with(
        dir.path(),
        None,
        "hole-tun-fallback",
        |_c, _p| Ok(()),
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
        |_c, _p| Ok(()),
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
            |_c, _p| Ok(()),
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
        let cmds = teardown_argv("utun7", ipv4_server(), "en0");
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
        for cmd in build_split_route_teardown_commands("utun7") {
            assert!(
                !names_an_interface(&cmd.argv),
                "recovery delete names an interface: {cmd:?}"
            );
        }
    }

    /// The install DOES name the tun — `-interface` is what makes the route
    /// point at it. Asserted here so a later "make teardown and setup
    /// symmetric" edit cannot strip it.
    #[skuld::test]
    fn split_installs_still_name_the_tun() {
        let cmds = setup_argv("utun7", ipv4_server(), &ipv4_gw());
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
    let live = teardown_argv("hole-tun", ipv4_server(), "en0");
    let dead = teardown_argv("hole-tun-gone-99", ipv4_server(), "en-gone-99");
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
    let dead = build_split_route_teardown_commands("hole-tun-gone-99");
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
    let cmds: Vec<Vec<String>> = build_teardown_commands(
        "hole-tun",
        ipv4_server(),
        "en0",
        Some(ipv4_gateway()),
        state::RouteForm::Via,
    )
    .into_iter()
    .filter(|c| [].contains(&c.id))
    .map(|c| c.argv)
    .collect();
    assert!(
        cmds.is_empty(),
        "a run that installed no routes must issue no deletes, got {cmds:?}"
    );
}

#[skuld::test]
fn teardown_deletes_only_the_recorded_routes() {
    let installed = [RouteId::SplitV4High];
    let cmds: Vec<Vec<String>> = build_teardown_commands(
        "hole-tun",
        ipv4_server(),
        "en0",
        Some(ipv4_gateway()),
        state::RouteForm::Via,
    )
    .into_iter()
    .filter(|c| installed.contains(&c.id))
    .map(|c| c.argv)
    .collect();
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
    let cmds: Vec<Vec<String>> = build_teardown_commands(
        "hole-tun",
        ipv4_server(),
        "en0",
        Some(ipv4_gateway()),
        state::RouteForm::Via,
    )
    .into_iter()
    .filter(|c| SPLIT_ROUTES.contains(&c.id))
    .map(|c| c.argv)
    .collect();
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
            original_gateway: Some(ipv4_gateway()),
            route_form: state::RouteForm::Via,
            installed: vec![RouteId::SplitV6Low],
            stale: Vec::new(),
        },
        None,
    )
    .unwrap();

    let log: RefCell<Captured> = RefCell::new(Vec::new());
    recover_routes_with(
        tmp.path(),
        None,
        "hole-tun",
        capturing_runner(&log),
        |_, _| {},
        failclosed::lockdown_state::Intent::Off,
        || CoverPresence::Absent,
        |_, _| {},
    );

    let log = log.into_inner();
    let split = commands_in_phase(&log, BestEffortPhase::RecoverSplit);
    assert_eq!(split.len(), 1, "expected one recorded split delete, got {log:?}");
    assert!(split[0].iter().any(|a| a == "::/1"), "wrong route: {split:?}");
    assert!(
        commands_in_phase(&log, BestEffortPhase::RecoverBypass).is_empty(),
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
            original_gateway: Some(ipv4_gateway()),
            route_form: state::RouteForm::Via,
            installed: planned_routes(ipv4_server()),
            stale: Vec::new(),
        },
        None,
    )
    .unwrap();

    let log: RefCell<Captured> = RefCell::new(Vec::new());
    recover_routes_with(
        tmp.path(),
        None,
        "hole-tun",
        capturing_runner(&log),
        |_, _| {},
        failclosed::lockdown_state::Intent::Off,
        || CoverPresence::Absent,
        |_, _| {},
    );

    let log = log.into_inner();
    let split = commands_in_phase(&log, BestEffortPhase::RecoverSplit);
    let bypass = commands_in_phase(&log, BestEffortPhase::RecoverBypass);
    assert_eq!(split.len(), 4, "split phase deletes the 4 splits, got {log:?}");
    assert_eq!(
        bypass.len(),
        1,
        "bypass phase deletes the bypass and nothing else, got {log:?}"
    );
    assert!(mentions_addr(&bypass, "1.2.3.4"), "got {bypass:?}");
}

/// A `stale` group carried forward by an earlier `install`'s own sweep
/// (see `sweep_leftover_before_install`) must also be attempted by crash
/// recovery, not just the primary record — the whole point of carrying it
/// forward is that SOMETHING keeps retrying it. Uses a distinct
/// `tun_name`/`server_ip` for the stale group to prove recovery used ITS
/// OWN provenance, not the primary record's.
#[skuld::test]
fn recover_attempts_a_stale_group_and_clears_the_file_once_everything_drains() {
    let tmp = tempfile::tempdir().unwrap();
    state::save(
        tmp.path(),
        &RouteState {
            version: state::SCHEMA_VERSION,
            tun_name: "hole-tun".into(),
            server_ip: ipv4_server(),
            interface_name: "en0".into(),
            original_gateway: Some(ipv4_gateway()),
            route_form: state::RouteForm::Via,
            installed: vec![RouteId::SplitV6Low],
            stale: vec![state::StaleRecord {
                tun_name: "hole-tun-old".into(),
                server_ip: "9.9.9.9".parse().unwrap(),
                interface_name: "en1".into(),
                original_gateway: Some("9.9.9.1".parse().unwrap()),
                route_form: state::RouteForm::Via,
                installed: vec![RouteId::ServerBypass],
            }],
        },
        None,
    )
    .unwrap();

    let log: RefCell<Captured> = RefCell::new(Vec::new());
    recover_routes_with(
        tmp.path(),
        None,
        "hole-tun",
        capturing_runner(&log),
        |_, _| {},
        failclosed::lockdown_state::Intent::Off,
        || CoverPresence::Absent,
        |_, _| {},
    );

    let log = log.into_inner();
    assert!(
        mentions_addr(&commands_in_phase(&log, BestEffortPhase::RecoverBypass), "9.9.9.9"),
        "the stale group's own bypass delete must be attempted, got {log:?}"
    );
    assert!(
        !tmp.path().join(STATE_FILE_NAME).exists(),
        "the state file must be cleared once BOTH the primary record and the stale group drain"
    );
}

/// The narrower case: only the stale group fails to confirm gone — the
/// state file must stay recorded (not cleared), even though the primary
/// record fully drained.
#[skuld::test]
fn recover_keeps_the_file_when_only_the_stale_group_fails_to_confirm_gone() {
    let tmp = tempfile::tempdir().unwrap();
    state::save(
        tmp.path(),
        &RouteState {
            version: state::SCHEMA_VERSION,
            tun_name: "hole-tun".into(),
            server_ip: ipv4_server(),
            interface_name: "en0".into(),
            original_gateway: Some(ipv4_gateway()),
            route_form: state::RouteForm::Via,
            installed: vec![RouteId::SplitV6Low],
            stale: vec![state::StaleRecord {
                tun_name: "hole-tun-old".into(),
                server_ip: "9.9.9.9".parse().unwrap(),
                interface_name: "en1".into(),
                original_gateway: Some("9.9.9.1".parse().unwrap()),
                route_form: state::RouteForm::Via,
                installed: vec![RouteId::ServerBypass],
            }],
        },
        None,
    )
    .unwrap();

    // The primary record's own command confirms gone; the stale group's
    // does not.
    let stale_attempted = std::cell::Cell::new(false);
    let runner = |argv: &[String], _phase: BestEffortPhase| -> Result<(), CommandFailure> {
        if argv.iter().any(|a| a == "9.9.9.9") {
            stale_attempted.set(true);
            return Err(CommandFailure::Exit(1));
        }
        Ok(())
    };
    recover_routes_with(
        tmp.path(),
        None,
        "hole-tun",
        runner,
        |_, _| {},
        failclosed::lockdown_state::Intent::Off,
        || CoverPresence::Absent,
        |_, _| {},
    );

    assert!(
        stale_attempted.get(),
        "the stale group's own bypass delete must actually be attempted, not just left recorded"
    );

    let remaining =
        state::load(tmp.path()).expect("the stale group's unconfirmed route must keep the state file recorded");
    assert!(
        remaining.installed.is_empty(),
        "the primary record fully drained: {:?}",
        remaining.installed
    );
    assert_eq!(
        remaining.stale,
        vec![state::StaleRecord {
            tun_name: "hole-tun-old".into(),
            server_ip: "9.9.9.9".parse().unwrap(),
            interface_name: "en1".into(),
            original_gateway: Some("9.9.9.1".parse().unwrap()),
            route_form: state::RouteForm::Via,
            installed: vec![RouteId::ServerBypass],
        }],
        "the stale group must survive with its own provenance intact: {:?}",
        remaining.stale
    );
}

// Per-command checkpoint producer =====================================================================================
//
// The tests above validate the CONSUMER half: handed a finished `installed`
// list, teardown deletes only what it names. These validate the PRODUCER
// half — the code that builds that list one command at a time — by driving
// `run_setup_commands`/`run_teardown_commands` directly with a scripted
// runner (never the real `netsh`/`route`, matching the test-isolation
// contract every other test in this file already relies on).

#[skuld::test]
fn setup_routes_pops_a_route_the_runner_reports_not_installed() {
    // A FATAL command reported not-installed aborts the phase (see
    // `a_host_with_ipv6_aborts_when_an_ipv6_add_fails`) — only a NON-fatal one
    // (an IPv6 split on a TUN with no IPv6 binding) pops and continues.
    let cmds = build_setup_commands("utun7", ipv4_server(), &ipv4_gw(), false);
    let mut installed = Vec::new();
    let result = run_setup_commands(
        &cmds,
        &mut installed,
        |argv, _phase| {
            if argv.iter().any(|a| a == "8000::/1") {
                Err(CommandFailure::Exit(1))
            } else {
                Ok(())
            }
        },
        |_ids| Ok(()),
    );
    assert!(result.is_ok());
    assert!(
        !installed.contains(&RouteId::SplitV6High),
        "a non-fatal route the runner reported not-installed must not be recorded: {installed:?}"
    );
    assert_eq!(installed.len(), 4, "the other 4 routes still install: {installed:?}");
}

/// A command whose spawn failed must not be rolled back — it never ran —
/// while the on-disk checkpoint from just before the failed spawn is left
/// naming it anyway (the accepted superset-of-one).
#[skuld::test]
fn setup_routes_excludes_a_spawn_failure_from_installed_but_not_from_the_last_checkpoint() {
    let cmds = build_setup_commands("utun7", ipv4_server(), &ipv4_gw(), true);
    let mut installed = Vec::new();
    let checkpoints: RefCell<Vec<Vec<RouteId>>> = RefCell::new(Vec::new());
    let result = run_setup_commands(
        &cmds,
        &mut installed,
        |argv, _phase| {
            if argv.iter().any(|a| a == "::/1") {
                Err(CommandFailure::Spawn(std::io::Error::other("simulated spawn failure")))
            } else {
                Ok(())
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
    let cmds = build_setup_commands("utun7", ipv4_server(), &ipv4_gw(), true);
    let mut installed = Vec::new();
    let mut checkpoint_calls = 0u32;
    let result = run_setup_commands(
        &cmds,
        &mut installed,
        |_argv, _phase| Ok(()),
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
    let cmds = build_setup_commands("utun7", ipv4_server(), &ipv4_gw(), true);
    let mut installed = Vec::new();
    let mut checkpoint_calls = 0u32;
    let result = run_setup_commands(
        &cmds,
        &mut installed,
        |_argv, _phase| Ok(()),
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
    let cmds = build_split_route_teardown_commands("utun7");
    let mut still_installed = SPLIT_ROUTES.to_vec();
    run_teardown_commands(
        &cmds,
        BestEffortPhase::Teardown,
        &mut still_installed,
        |argv, _phase| {
            if argv.iter().any(|a| a == "::/1") {
                Err(CommandFailure::Spawn(std::io::Error::other("simulated spawn failure")))
            } else {
                Ok(())
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
    let cmds = build_split_route_teardown_commands("utun7");
    let mut still_installed = SPLIT_ROUTES.to_vec();
    run_teardown_commands(
        &cmds,
        BestEffortPhase::Teardown,
        &mut still_installed,
        |argv, _phase| {
            if argv.iter().any(|a| a == "0.0.0.0/1") {
                Err(CommandFailure::Exit(1))
            } else {
                Ok(())
            }
        },
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
    let cmds = build_split_route_teardown_commands("utun7");
    let mut still_installed = SPLIT_ROUTES.to_vec();
    let checkpoints: RefCell<Vec<Vec<RouteId>>> = RefCell::new(Vec::new());
    run_teardown_commands(
        &cmds,
        BestEffortPhase::Teardown,
        &mut still_installed,
        |_argv, _phase| Ok(()),
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
/// The production runner unconditionally indexes `cmd[0]`; a prior version of
/// this code synthesized an empty-argv "phase entered, nothing to do" signal
/// through that same runner and crashed on every loopback-server crash
/// recovery.
#[skuld::test]
fn teardown_routes_with_nothing_installed_does_not_panic() {
    #[allow(clippy::disallowed_methods)]
    // exercising teardown_routes directly, with a scripted runner — no real netsh/route
    let remaining = teardown_routes(
        "utun7",
        ipv4_server(),
        "en0",
        Some(ipv4_gateway()),
        state::RouteForm::Via,
        &[],
        |argv, _phase| panic!("no command should run for an empty installed set: {argv:?}"),
        |_ids| {},
    );
    assert!(remaining.is_empty());
}

/// Same as above but through the REAL production runner (`exec_one`, which
/// spawns real subprocesses for a non-empty argv) — proves the empty case
/// never reaches it at all, closing the gap a scripted-runner-only test
/// can't: the panic this guards was in the runner's own indexing, not in
/// anything a mock could stand in for.
#[skuld::test]
fn teardown_routes_with_nothing_installed_never_calls_the_real_runner() {
    #[allow(clippy::disallowed_methods)]
    // exercising teardown_routes directly, with a scripted runner — no real netsh/route
    let remaining = teardown_routes(
        "utun7",
        ipv4_server(),
        "en0",
        Some(ipv4_gateway()),
        state::RouteForm::Via,
        &[],
        exec_one::<BestEffortPhase>,
        |_ids| {},
    );
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
        Some(ipv4_gateway()),
        state::RouteForm::Via,
        &planned_routes(ipv4_server()),
        |_argv, _phase| Ok(()),
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
        Some(ipv4_gateway()),
        state::RouteForm::Via,
        &[RouteId::SplitV4High, RouteId::ServerBypass],
        |argv, _phase| {
            if argv.iter().any(|a| a == "128.0.0.0/1") {
                attempted.borrow_mut().push(RouteId::SplitV4High);
            } else if argv.iter().any(|a| a == "1.2.3.4") {
                attempted.borrow_mut().push(RouteId::ServerBypass);
            } else {
                panic!("teardown_routes attempted a route outside the recorded subset: {argv:?}");
            }
            Ok(())
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
        Some(ipv4_gateway()),
        state::RouteForm::Via,
        &planned_routes(ipv4_server()),
        |argv, _phase| {
            if argv.iter().any(|a| a == "1.2.3.4") {
                Err(CommandFailure::Spawn(std::io::Error::other("simulated spawn failure")))
            } else {
                Ok(())
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

// checkpoint_installed — install's own advance-on-success-only checkpoint =============================================
//
// A pre-command checkpoint write that fails (ENOSPC, a transient AV/
// MoveFileEx denial, ...) must not leave `persisted.installed` naming the
// id it failed to durably record — `install`'s `uncertain` set is derived
// by diffing `persisted.installed` against the runtime accumulator, so a
// write that never landed must not read as "durably recorded, fate
// unknown." See bindreams/hole#904's root cause 2.

/// Forces the NEXT `state::save` against `state_dir` to fail deterministically
/// on every platform by occupying the destination filename with a directory:
/// `NamedTempFile::persist` cannot rename a file onto one. Holding the file
/// open instead would only block the rename on Windows — POSIX renames over an
/// open file succeed.
fn block_next_save(state_dir: &Path) {
    let path = state_dir.join(STATE_FILE_NAME);
    std::fs::remove_file(&path).expect("a prior successful save must have created the file to block");
    std::fs::create_dir(&path).expect("a directory at the destination blocks the persist rename");
}

#[skuld::test]
fn checkpoint_installed_rolls_back_in_memory_on_save_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let mut persisted = RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "utun7".into(),
        server_ip: ipv4_server(),
        interface_name: "en0".into(),
        original_gateway: Some(ipv4_gateway()),
        route_form: state::RouteForm::Via,
        installed: Vec::new(),
        stale: Vec::new(),
    };

    // First checkpoint succeeds and lands on disk.
    checkpoint_installed(&mut persisted, tmp.path(), None, &[RouteId::SplitV4Low]).unwrap();
    assert_eq!(persisted.installed, vec![RouteId::SplitV4Low]);

    // The next save is forced to fail deterministically.
    block_next_save(tmp.path());
    let result = checkpoint_installed(
        &mut persisted,
        tmp.path(),
        None,
        &[RouteId::SplitV4Low, RouteId::SplitV4High],
    );
    assert!(
        result.is_err(),
        "save must fail while a directory occupies its destination"
    );

    assert_eq!(
        persisted.installed,
        vec![RouteId::SplitV4Low],
        "a failed write must not advance the in-memory value install()'s `uncertain` calc reads from"
    );
}

/// The end-to-end form of the test above: drives the real
/// `SystemRouting::rollback_and_record` (the same call `install` makes on a
/// `setup_routes` error) with the `uncertain` set `install` would have
/// derived, and observes the FILE it leaves behind — not just an in-memory
/// struct. `confirmed` is empty throughout, so `teardown_routes` inside
/// `rollback_and_record` issues no commands and never reaches the real
/// subprocess runner (see `teardown_routes_with_nothing_installed_never_calls_the_real_runner`) —
/// safe to call for real here.
#[skuld::test]
fn install_rollback_clears_the_file_when_a_checkpoint_write_failure_leaves_nothing_confirmed_or_uncertain() {
    let tmp = tempfile::tempdir().unwrap();
    let routing = SystemRouting::new(tmp.path().to_path_buf(), None);

    let mut persisted = RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "utun7".into(),
        server_ip: ipv4_server(),
        interface_name: "en0".into(),
        original_gateway: Some(ipv4_gateway()),
        route_form: state::RouteForm::Via,
        installed: Vec::new(),
        stale: Vec::new(),
    };

    // Occupy the exact destination filename with a directory so the very
    // first pre-command checkpoint's write fails deterministically (the
    // finding's ENOSPC scenario) — `NamedTempFile::persist` cannot rename a
    // file onto an existing directory.
    let state_file_path = tmp.path().join(STATE_FILE_NAME);
    std::fs::create_dir(&state_file_path).unwrap();
    let write_result = checkpoint_installed(&mut persisted, tmp.path(), None, &[RouteId::SplitV4Low]);
    assert!(
        write_result.is_err(),
        "the write must fail while a directory occupies its destination"
    );
    std::fs::remove_dir(&state_file_path).unwrap();

    // The command this checkpoint would have gated never spawns, so
    // `setup_routes`'s own accumulator (mirrored here by `confirmed`, since
    // it's what `install` would pass to `rollback_and_record`) stays empty.
    let confirmed: Vec<RouteId> = Vec::new();
    let uncertain: Vec<RouteId> = persisted
        .installed
        .iter()
        .copied()
        .filter(|id| !confirmed.contains(id))
        .collect();
    assert!(
        uncertain.is_empty(),
        "an id whose checkpoint write never durably landed must not be classified uncertain: {uncertain:?}"
    );

    routing.rollback_and_record(
        "utun7",
        ipv4_server(),
        "en0",
        &confirmed,
        persisted,
        uncertain,
        exec_one::<BestEffortPhase>,
    );

    assert!(
        state::load(tmp.path()).is_none(),
        "nothing was confirmed installed and nothing is uncertain, so rollback must clear the \
         state file, not leave a phantom `installed: [SplitV4Low]` record for the next start's \
         recovery to act on"
    );
}

// Windows bypass-delete gateway scoping (root cause 3) ================================================================
//
// `route.exe`'s own help confirms DELETE's gateway operand is optional but
// accepted; when supplied it scopes which entry is deleted — unlike macOS,
// where the gateway is never read (see CONTRIBUTING's Route ownership
// section). An unscoped delete can take out a co-resident VPN's route to
// the same destination.

#[cfg(target_os = "windows")]
mod windows_bypass_teardown_scoping {
    use super::*;

    #[skuld::test]
    fn bypass_delete_is_scoped_by_the_install_time_gateway() {
        let server_ip = ipv4_server();
        let gateway = ipv4_gateway();
        let cmds = build_teardown_commands("utun7", server_ip, "en0", Some(gateway), state::RouteForm::Via);
        let cmd = cmds
            .iter()
            .find(|c| c.argv.iter().any(|a| a == "1.2.3.4"))
            .expect("bypass delete must be present");
        assert!(
            cmd.argv.iter().any(|a| a == "192.168.1.1"),
            "the delete must be scoped by the install-time gateway so it cannot take out \
             a co-resident VPN's route to the same destination, got {cmd:?}"
        );
    }

    /// Asserts on the FULL argv, not a substring: the legacy unscoped delete
    /// (`bypass_delete_falls_back_to_unscoped_when_gateway_is_unknown`) ALSO
    /// names the server address, so a weaker "a delete command mentions
    /// 1.2.3.4" assertion would pass on the wrong command entirely.
    #[skuld::test]
    fn an_on_link_teardown_never_emits_the_unscoped_delete() {
        let server_ip = ipv4_server();
        let cmds = build_teardown_commands("utun7", server_ip, "en0", None, state::RouteForm::OnLink);
        let cmd = cmds
            .iter()
            .find(|c| c.id == RouteId::ServerBypass)
            .expect("bypass delete must be present");
        assert_eq!(
            cmd.argv,
            vec![
                "netsh".to_string(),
                "interface".to_string(),
                "ip".to_string(),
                "delete".to_string(),
                "route".to_string(),
                "1.2.3.4/32".to_string(),
                "en0".to_string(),
            ],
            "an on-link record must delete the interface-scoped form, never the unscoped \
             `route delete 1.2.3.4 mask 255.255.255.255` a legacy no-gateway record would emit"
        );
    }

    /// A record migrated from schema 1/2/3 never persisted a gateway — the
    /// delete must still be attempted (the old unscoped shape, a disclosed
    /// residual), not silently skipped.
    #[skuld::test]
    fn bypass_delete_falls_back_to_unscoped_when_gateway_is_unknown() {
        let server_ip = ipv4_server();
        let cmds = build_teardown_commands("utun7", server_ip, "en0", None, state::RouteForm::Via);
        let cmd = cmds
            .iter()
            .find(|c| c.argv.iter().any(|a| a == "1.2.3.4"))
            .expect("bypass delete must still be attempted without a known gateway");
        assert!(
            !cmd.argv.iter().any(|a| a == "192.168.1.1"),
            "no gateway known => no gateway operand, got {cmd:?}"
        );
    }
}

// SystemRouting::install pre-install sweep (root cause 1) =============================================================
//
// `install`'s pre-install sweep of a record retained by a prior run/attempt
// in this SAME PROCESS must carry forward whatever it still cannot confirm
// gone — never discard it under the fresh record the new session is about
// to write. A record is only ever retained because its own teardown could
// not confirm the route gone, so the usual outcome of re-sweeping it is
// failing the same way again.

#[skuld::test]
fn install_sweep_carries_forward_a_still_unconfirmed_leftover_instead_of_losing_it() {
    let tmp = tempfile::tempdir().unwrap();
    // Prior run's retained record: teardown could not confirm ServerBypass gone.
    state::save(
        tmp.path(),
        &RouteState {
            version: state::SCHEMA_VERSION,
            tun_name: "hole-tun".into(),
            server_ip: "9.9.9.9".parse().unwrap(),
            interface_name: "en0".into(),
            original_gateway: Some(ipv4_gateway()),
            route_form: state::RouteForm::Via,
            installed: vec![RouteId::ServerBypass],
            stale: Vec::new(),
        },
        None,
    )
    .unwrap();

    // The new session's own template, as `install` builds it before sweeping.
    let mut persisted = RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: "1.1.1.1".parse().unwrap(),
        interface_name: "en0".into(),
        original_gateway: Some(ipv4_gateway()),
        route_form: state::RouteForm::Via,
        installed: Vec::new(),
        stale: Vec::new(),
    };

    // The sweep's delete fails the same way it did before — never confirmed
    // gone — the exact scenario the sweep exists for.
    sweep_leftover_before_install(tmp.path(), None, &mut persisted, |_argv, _phase| {
        Err(CommandFailure::Exit(1))
    });

    let expected_stale = vec![state::StaleRecord {
        tun_name: "hole-tun".into(),
        server_ip: "9.9.9.9".parse().unwrap(),
        interface_name: "en0".into(),
        original_gateway: Some(ipv4_gateway()),
        route_form: state::RouteForm::Via,
        installed: vec![RouteId::ServerBypass],
    }];
    assert_eq!(
        persisted.stale, expected_stale,
        "an unconfirmed leftover must be carried into the new session's stale list, not dropped"
    );
    assert!(
        persisted.installed.is_empty(),
        "the sweep must never touch this session's own `installed`"
    );

    // The file on disk must ALSO carry it forward — not just the in-memory
    // value — proving the write landed, not merely the struct in memory.
    let on_disk = state::load(tmp.path()).unwrap();
    assert_eq!(on_disk.stale, expected_stale);
}

/// The mirror case: when the sweep fully confirms the leftover gone, nothing
/// is carried forward — `stale` must not become a permanent residue that
/// accumulates even after a route is actually cleared.
#[skuld::test]
fn install_sweep_drops_a_fully_confirmed_leftover() {
    let tmp = tempfile::tempdir().unwrap();
    state::save(
        tmp.path(),
        &RouteState {
            version: state::SCHEMA_VERSION,
            tun_name: "hole-tun".into(),
            server_ip: "9.9.9.9".parse().unwrap(),
            interface_name: "en0".into(),
            original_gateway: Some(ipv4_gateway()),
            route_form: state::RouteForm::Via,
            installed: vec![RouteId::ServerBypass],
            stale: Vec::new(),
        },
        None,
    )
    .unwrap();

    let mut persisted = RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: "1.1.1.1".parse().unwrap(),
        interface_name: "en0".into(),
        original_gateway: Some(ipv4_gateway()),
        route_form: state::RouteForm::Via,
        installed: Vec::new(),
        stale: Vec::new(),
    };

    sweep_leftover_before_install(tmp.path(), None, &mut persisted, |_argv, _phase| Ok(()));

    assert!(
        persisted.stale.is_empty(),
        "a fully confirmed sweep must not leave a stale residue: {:?}",
        persisted.stale
    );
}

/// Debt already carried forward by an EARLIER sweep (this call's own
/// `leftover.stale`, from a session before the immediately-prior one) must
/// also be re-attempted, not just the immediately-prior session's own
/// primary record — otherwise a route stuck since session N-2 stops being
/// retried the moment session N-1 also fails to confirm it gone.
#[skuld::test]
fn install_sweep_also_retries_debt_carried_by_an_earlier_sweep() {
    let tmp = tempfile::tempdir().unwrap();
    state::save(
        tmp.path(),
        &RouteState {
            version: state::SCHEMA_VERSION,
            tun_name: "hole-tun".into(),
            server_ip: "5.5.5.5".parse().unwrap(),
            interface_name: "en0".into(),
            original_gateway: Some(ipv4_gateway()),
            route_form: state::RouteForm::Via,
            installed: vec![RouteId::ServerBypass],
            stale: vec![state::StaleRecord {
                tun_name: "hole-tun".into(),
                server_ip: "9.9.9.9".parse().unwrap(),
                interface_name: "en0".into(),
                original_gateway: Some(ipv4_gateway()),
                route_form: state::RouteForm::Via,
                installed: vec![RouteId::ServerBypass],
            }],
        },
        None,
    )
    .unwrap();

    let mut persisted = RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: "1.1.1.1".parse().unwrap(),
        interface_name: "en0".into(),
        original_gateway: Some(ipv4_gateway()),
        route_form: state::RouteForm::Via,
        installed: Vec::new(),
        stale: Vec::new(),
    };

    let attempted: RefCell<Vec<String>> = RefCell::new(Vec::new());
    sweep_leftover_before_install(tmp.path(), None, &mut persisted, |argv, _phase| {
        if argv.iter().any(|a| a == "9.9.9.9") {
            attempted.borrow_mut().push("9.9.9.9".into());
        }
        if argv.iter().any(|a| a == "5.5.5.5") {
            attempted.borrow_mut().push("5.5.5.5".into());
        }
        Err(CommandFailure::Exit(1)) // nothing confirms gone — both groups must still be attempted
    });

    // Both the immediately-prior session's own record AND the older debt it
    // was carrying must have driven a real teardown command — not just be
    // copied into `persisted.stale` unattempted.
    assert_eq!(
        attempted.into_inner(),
        vec!["9.9.9.9", "5.5.5.5"],
        "both the older carried-forward debt and the immediately-prior record must be attempted"
    );

    let server_ips: Vec<IpAddr> = persisted.stale.iter().map(|g| g.server_ip).collect();
    assert_eq!(
        server_ips.len(),
        2,
        "both the immediately-prior record and the older carried-forward debt must survive \
         since the runner never confirmed either gone: {:?}",
        persisted.stale
    );
    assert!(server_ips.contains(&"9.9.9.9".parse().unwrap()));
    assert!(server_ips.contains(&"5.5.5.5".parse().unwrap()));
}

// Canonical-form discipline (troyka round 4) ==========================================================================
//
// `sweep_leftover_before_install` and `recover_routes_with` must route every
// group they fold into a persisted set through `state::coalesce` — never
// construct or append a group without it.

/// The everyday case: a prior run's leftover primary record and an
/// already-carried-forward stale group share IDENTITY (same `tun_name` —
/// fixed in production — plus the same `server_ip`/`interface_name`/
/// `original_gateway`, i.e. a reconnect to the same server). Without
/// coalescing, the sweep issues the identical delete command once per group.
#[skuld::test]
fn install_sweep_coalesces_a_stale_group_identical_to_the_leftover_primary() {
    let tmp = tempfile::tempdir().unwrap();
    state::save(
        tmp.path(),
        &RouteState {
            version: state::SCHEMA_VERSION,
            tun_name: "hole-tun".into(),
            server_ip: "9.9.9.9".parse().unwrap(),
            interface_name: "en0".into(),
            original_gateway: Some(ipv4_gateway()),
            route_form: state::RouteForm::Via,
            installed: vec![RouteId::SplitV4Low],
            stale: vec![state::StaleRecord {
                tun_name: "hole-tun".into(),
                server_ip: "9.9.9.9".parse().unwrap(),
                interface_name: "en0".into(),
                original_gateway: Some(ipv4_gateway()),
                route_form: state::RouteForm::Via,
                installed: vec![RouteId::SplitV4Low],
            }],
        },
        None,
    )
    .unwrap();

    let mut persisted = RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: "1.1.1.1".parse().unwrap(),
        interface_name: "en0".into(),
        original_gateway: Some(ipv4_gateway()),
        route_form: state::RouteForm::Via,
        installed: Vec::new(),
        stale: Vec::new(),
    };

    let log: RefCell<Captured> = RefCell::new(Vec::new());
    sweep_leftover_before_install(tmp.path(), None, &mut persisted, capturing_runner(&log));

    let log = log.into_inner();
    let split_v4_low_deletes: Vec<_> = log
        .iter()
        .filter(|(_, cmd)| cmd.iter().any(|a| a == "0.0.0.0/1"))
        .collect();
    assert_eq!(
        split_v4_low_deletes.len(),
        1,
        "identical-identity groups must coalesce into one delete command, got {log:?}"
    );
}

/// N consecutive failed install attempts to the same server each leave their
/// own unconfirmed leftover. Without merge-on-append, sweep #2 folds the
/// immediately-prior attempt's leftover in as a brand-new `StaleRecord`
/// alongside the one sweep #1 already carried forward, so `stale` grows by
/// one entry per failed attempt instead of staying at one retried entry.
#[skuld::test]
fn install_sweep_merges_a_new_leftover_into_an_existing_stale_group_of_the_same_identity() {
    let tmp = tempfile::tempdir().unwrap();
    // The file on disk right before sweep #2 runs: sweep #1's carried-forward
    // debt in `stale`, plus THIS install attempt's own leftover primary
    // record for the same server.
    state::save(
        tmp.path(),
        &RouteState {
            version: state::SCHEMA_VERSION,
            tun_name: "hole-tun".into(),
            server_ip: "9.9.9.9".parse().unwrap(),
            interface_name: "en0".into(),
            original_gateway: Some(ipv4_gateway()),
            route_form: state::RouteForm::Via,
            installed: vec![RouteId::ServerBypass],
            stale: vec![state::StaleRecord {
                tun_name: "hole-tun".into(),
                server_ip: "9.9.9.9".parse().unwrap(),
                interface_name: "en0".into(),
                original_gateway: Some(ipv4_gateway()),
                route_form: state::RouteForm::Via,
                installed: vec![RouteId::ServerBypass],
            }],
        },
        None,
    )
    .unwrap();

    let mut persisted = RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: "1.1.1.1".parse().unwrap(),
        interface_name: "en0".into(),
        original_gateway: Some(ipv4_gateway()),
        route_form: state::RouteForm::Via,
        installed: Vec::new(),
        stale: Vec::new(),
    };

    // Never confirms gone — both records must fold into ONE retried entry.
    sweep_leftover_before_install(tmp.path(), None, &mut persisted, |_argv, _phase| {
        Err(CommandFailure::Exit(1))
    });

    assert_eq!(
        persisted.stale.len(),
        1,
        "a new leftover sharing identity with an existing stale group must merge into it, not \
         grow the list: {:?}",
        persisted.stale
    );

    let on_disk = state::load(tmp.path()).unwrap();
    assert_eq!(
        on_disk.stale.len(),
        1,
        "the merge must land on disk, not just in memory: {:?}",
        on_disk.stale
    );
}

/// A `stale` group naming only an id with no possible teardown command for
/// its own `server_ip` (a `ServerBypass` against a loopback address) must
/// never survive the sweep — it can never drain, so it would pin
/// `persisted.stale` non-empty forever.
#[skuld::test]
fn install_sweep_drops_an_unplannable_stale_group() {
    let tmp = tempfile::tempdir().unwrap();
    let loopback: IpAddr = "127.0.0.1".parse().unwrap();
    state::save(
        tmp.path(),
        &RouteState {
            version: state::SCHEMA_VERSION,
            tun_name: "hole-tun".into(),
            server_ip: "1.1.1.1".parse().unwrap(),
            interface_name: "en0".into(),
            original_gateway: Some(ipv4_gateway()),
            route_form: state::RouteForm::Via,
            installed: Vec::new(),
            stale: vec![state::StaleRecord {
                tun_name: "hole-tun".into(),
                server_ip: loopback,
                interface_name: "en0".into(),
                original_gateway: Some(ipv4_gateway()),
                route_form: state::RouteForm::Via,
                installed: vec![RouteId::ServerBypass],
            }],
        },
        None,
    )
    .unwrap();

    let mut persisted = RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: "2.2.2.2".parse().unwrap(),
        interface_name: "en0".into(),
        original_gateway: Some(ipv4_gateway()),
        route_form: state::RouteForm::Via,
        installed: Vec::new(),
        stale: Vec::new(),
    };

    let log: RefCell<Captured> = RefCell::new(Vec::new());
    sweep_leftover_before_install(tmp.path(), None, &mut persisted, capturing_runner(&log));

    assert!(
        persisted.stale.is_empty(),
        "an unplannable-only stale group must not pin the sweep's carried-forward list open: {:?}",
        persisted.stale
    );
    assert!(
        log.into_inner().is_empty(),
        "an id with no possible teardown command must never reach the runner"
    );
}

/// Two groups sharing `tun_name` (fixed in production) but a DIFFERENT
/// `server_ip` are not coalesced by identity — yet a split-route delete
/// command depends only on `tun_name`, so both groups would otherwise
/// re-issue the identical delete. The second occurrence would remove
/// whatever claimed the freed prefix in between (see CONTRIBUTING's Route
/// ownership section).
#[skuld::test]
fn recovery_never_issues_the_same_split_delete_twice_across_groups() {
    let tmp = tempfile::tempdir().unwrap();
    state::save(
        tmp.path(),
        &RouteState {
            version: state::SCHEMA_VERSION,
            tun_name: "hole-tun".into(),
            server_ip: ipv4_server(),
            interface_name: "en0".into(),
            original_gateway: Some(ipv4_gateway()),
            route_form: state::RouteForm::Via,
            installed: vec![RouteId::SplitV4Low],
            stale: vec![state::StaleRecord {
                tun_name: "hole-tun".into(),
                server_ip: "9.9.9.9".parse().unwrap(),
                interface_name: "en1".into(),
                original_gateway: Some("9.9.9.1".parse().unwrap()),
                route_form: state::RouteForm::Via,
                installed: vec![RouteId::SplitV4Low],
            }],
        },
        None,
    )
    .unwrap();

    let log: RefCell<Captured> = RefCell::new(Vec::new());
    recover_routes_with(
        tmp.path(),
        None,
        "hole-tun",
        capturing_runner(&log),
        |_, _| {},
        failclosed::lockdown_state::Intent::Off,
        || CoverPresence::Absent,
        |_, _| {},
    );

    let log = log.into_inner();
    let split_v4_low_deletes: Vec<_> = commands_in_phase(&log, BestEffortPhase::RecoverSplit)
        .into_iter()
        .filter(|cmd| cmd.iter().any(|a| a == "0.0.0.0/1"))
        .collect();
    assert_eq!(
        split_v4_low_deletes.len(),
        1,
        "the same tun-scoped split delete must run once across the whole recovery, not once per \
         group: {log:?}"
    );
}

/// macOS's split-route delete argv ignores `tun_name` entirely (see
/// `platform_split_teardown_commands`), so two groups with DIFFERENT
/// `tun_name` — which Windows would treat as genuinely distinct routes on
/// different adapters — still target the identical kernel route on macOS.
/// The second delete must not run. Not executable on this box: gated to the
/// platform whose command-building this depends on.
#[cfg(target_os = "macos")]
#[skuld::test]
fn recovery_never_issues_the_same_macos_split_delete_twice_across_different_tun_names() {
    let tmp = tempfile::tempdir().unwrap();
    state::save(
        tmp.path(),
        &RouteState {
            version: state::SCHEMA_VERSION,
            tun_name: "utun7".into(),
            server_ip: ipv4_server(),
            interface_name: "en0".into(),
            original_gateway: Some(ipv4_gateway()),
            route_form: state::RouteForm::Via,
            installed: vec![RouteId::SplitV4Low],
            stale: vec![state::StaleRecord {
                tun_name: "utun9".into(),
                server_ip: "9.9.9.9".parse().unwrap(),
                interface_name: "en1".into(),
                original_gateway: Some("9.9.9.1".parse().unwrap()),
                route_form: state::RouteForm::Via,
                installed: vec![RouteId::SplitV4Low],
            }],
        },
        None,
    )
    .unwrap();

    let log: RefCell<Captured> = RefCell::new(Vec::new());
    recover_routes_with(
        tmp.path(),
        None,
        "hole-tun",
        capturing_runner(&log),
        |_, _| {},
        failclosed::lockdown_state::Intent::Off,
        || CoverPresence::Absent,
        |_, _| {},
    );

    let log = log.into_inner();
    let split_v4_low_deletes: Vec<_> = commands_in_phase(&log, BestEffortPhase::RecoverSplit)
        .into_iter()
        .filter(|cmd| cmd.iter().any(|a| a == "0.0.0.0/1"))
        .collect();
    assert_eq!(
        split_v4_low_deletes.len(),
        1,
        "macOS ignores tun_name in the delete argv, so two differently-named groups must still \
         dedupe to one command: {log:?}"
    );
}

/// `extra_unconfirmed` — ids whose install outcome is genuinely unknown —
/// must never be absent from the on-disk record at any point during
/// rollback, not just at the end. Uses two `confirmed` ids so there is a
/// real mid-loop instant to observe.
#[skuld::test]
fn rollback_never_erases_extra_unconfirmed_mid_loop() {
    let tmp = tempfile::tempdir().unwrap();
    let routing = SystemRouting::new(tmp.path().to_path_buf(), None);

    let persisted = RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "utun7".into(),
        server_ip: ipv4_server(),
        interface_name: "en0".into(),
        original_gateway: Some(ipv4_gateway()),
        route_form: state::RouteForm::Via,
        installed: vec![RouteId::SplitV4Low, RouteId::SplitV4High, RouteId::ServerBypass],
        stale: Vec::new(),
    };

    let confirmed = [RouteId::SplitV4Low, RouteId::SplitV4High];
    let extra_unconfirmed = vec![RouteId::ServerBypass];

    // Model the file `setup_routes`'s own last checkpoint would have left on
    // disk before this rollback runs.
    state::save(tmp.path(), &persisted, None).unwrap();

    let checked_mid_loop = std::cell::Cell::new(false);
    let runner = |_argv: &[String], _phase: BestEffortPhase| -> Result<(), CommandFailure> {
        let on_disk = state::load(tmp.path()).expect("record must exist mid-rollback");
        assert!(
            on_disk.installed.contains(&RouteId::ServerBypass),
            "extra_unconfirmed must never be absent from the on-disk record mid-rollback: {:?}",
            on_disk.installed
        );
        checked_mid_loop.set(true);
        Ok(())
    };

    routing.rollback_and_record(
        "utun7",
        ipv4_server(),
        "en0",
        &confirmed,
        persisted,
        extra_unconfirmed,
        runner,
    );

    assert!(checked_mid_loop.get(), "the runner must have actually run mid-loop");
}

// default_gateway's own-provenance guard (#798 PR1 Task 3) ============================================================
//
// A `/32` host route is the longest prefix that exists, so `best_route(server)`
// matches Hole's OWN bypass ahead of every other route once one is installed.
// Teardown is `BestEffortPhase` (see `run_teardown_command`), so a `route
// delete` that exits non-zero leaves a prior run's bypass in the table; the
// next start's `default_gateway(server_ip)` would then read back its own
// stale route and report the PREVIOUS run's interface and gateway instead of
// querying anything real. `clear_stale_server_bypass` is the guard: run
// before the OS query, it best-effort deletes exactly that leftover.
//
// The OS query itself (`GetBestRoute2` via `gateway::upstream_route`) has no
// injectable seam — proving "the query no longer reports the stale
// interface" end-to-end would need a real routing table, which is what
// `tests/gateway_privileged.rs` and `best_route_agrees_with_find_netroute`
// already cover for the query in isolation. What IS unit-testable, and what
// this guards, is that the persisted leftover is gone by the time the query
// would run.

#[skuld::test]
fn a_stale_server_bypass_is_not_what_the_lookup_returns() {
    let tmp = tempfile::tempdir().unwrap();
    let leftover = RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: ipv4_server(),
        interface_name: "en0".into(),
        original_gateway: Some(ipv4_gateway()),
        route_form: state::RouteForm::Via,
        installed: vec![RouteId::ServerBypass],
        stale: Vec::new(),
    };
    state::save(tmp.path(), &leftover, None).unwrap();

    let calls = std::cell::RefCell::new(Vec::new());
    clear_stale_server_bypass(tmp.path(), None, ipv4_server(), |argv, _phase| {
        calls.borrow_mut().push(argv.to_vec());
        Ok(())
    });

    assert_eq!(
        calls.borrow().len(),
        1,
        "the stale bypass's own delete command must run exactly once"
    );

    let on_disk = state::load(tmp.path()).expect("record must still exist (only ServerBypass was cleared)");
    assert!(
        !on_disk.installed.contains(&RouteId::ServerBypass),
        "a confirmed-deleted stale bypass must not still be reported installed: {:?}",
        on_disk.installed
    );
}

/// A leftover bypass to a DIFFERENT server cannot poison a query for
/// `dest` — the query is destination-scoped, so only a same-`server_ip`
/// leftover is a hazard. Deleting it anyway would be an unscoped extra
/// deletion.
#[skuld::test]
fn a_stale_bypass_to_a_different_server_is_left_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let leftover = RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: "9.9.9.9".parse().unwrap(),
        interface_name: "en0".into(),
        original_gateway: Some(ipv4_gateway()),
        route_form: state::RouteForm::Via,
        installed: vec![RouteId::ServerBypass],
        stale: Vec::new(),
    };
    state::save(tmp.path(), &leftover, None).unwrap();

    let calls = std::cell::RefCell::new(Vec::new());
    // Query for a DIFFERENT destination than the leftover's own server_ip.
    clear_stale_server_bypass(tmp.path(), None, ipv4_server(), |argv, _phase| {
        calls.borrow_mut().push(argv.to_vec());
        Ok(())
    });

    assert!(
        calls.borrow().is_empty(),
        "a leftover for a different server_ip must not be touched"
    );
    let on_disk = state::load(tmp.path()).unwrap();
    assert!(on_disk.installed.contains(&RouteId::ServerBypass));
}

/// Same guard applied to a group already carried into `stale` by an earlier
/// sweep — `install`'s own pre-install sweep is not the only path that can
/// leave one there.
#[skuld::test]
fn a_stale_server_bypass_inside_the_carried_forward_group_is_also_cleared() {
    let tmp = tempfile::tempdir().unwrap();
    let leftover = RouteState {
        version: state::SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: "5.5.5.5".parse().unwrap(),
        interface_name: "en1".into(),
        original_gateway: None,
        route_form: state::RouteForm::Via,
        installed: Vec::new(),
        stale: vec![state::StaleRecord {
            tun_name: "hole-tun".into(),
            server_ip: ipv4_server(),
            interface_name: "en0".into(),
            original_gateway: Some(ipv4_gateway()),
            route_form: state::RouteForm::Via,
            installed: vec![RouteId::ServerBypass],
        }],
    };
    state::save(tmp.path(), &leftover, None).unwrap();

    clear_stale_server_bypass(tmp.path(), None, ipv4_server(), |_argv, _phase| Ok(()));

    let on_disk = state::load(tmp.path()).unwrap();
    assert!(
        on_disk.stale.is_empty(),
        "the stale group's ServerBypass must be cleared and the now-empty group dropped: {:?}",
        on_disk.stale
    );
}
