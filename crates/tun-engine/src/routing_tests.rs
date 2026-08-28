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
    state::save(tmp.path(), &persisted_state, None).unwrap();

    let failing =
        |_: &[Vec<String>], _: &str| -> std::io::Result<()> { Err(std::io::Error::other("simulated runner failure")) };
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
        |_cmds, _phase| Ok(()),
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
