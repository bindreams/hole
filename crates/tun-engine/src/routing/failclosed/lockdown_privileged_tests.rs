//! Privileged-lane real-engage verification for the standing lockdown cover
//! (#527). Unlike the pure builder unit tests (`windows_tests` / `macos_tests`,
//! the #165 isolation contract), these engage the REAL OS cover (Windows: live
//! FWPM; macOS: live pf) and assert it actually blocks egress — proving the kill
//! switch is not inert.
//!
//! They run on the elevated `tun` lane only: the `TUN` label (→ skuld filter
//! name `tun`) gates them so the unprivileged `SKULD_LABELS="!tun"` pass
//! excludes them and the `SKULD_LABELS="tun"` pass runs them — Windows under
//! CI's elevated token, macOS under `sudo` (pf needs root). They are NOT
//! `#[ignore]`d and do not skip on missing privilege: a default `cargo nextest`
//! run on an unelevated box runs them and fails loud; opting out is the explicit
//! `!tun` filter, and CI provisions the elevation.
//!
//! Cross-binary serialization for the global WFP/pf/TUN state these touch lives
//! in `.config/nextest.toml` (`global-net-state` test-group) — skuld's
//! `serial = TUN` only serializes within one binary.

use super::*;

#[skuld::label]
const TUN: skuld::Label;

/// Windows real-engage verification. Engages the REAL WFP lockdown cover (a
/// `LocalInterface` LUID permit + loopback permits + block-all) and proves
/// (a) loopback stays permitted and (b) egress to an arbitrary non-permitted
/// public IP is BLOCKED at `ALE_AUTH_CONNECT` — so the cover is not inert.
///
/// Loopback is carried by the address-range permit (127.0.0.0/8 + ::1/128) on all
/// four ALE layers — CONNECT *and* RECV_ACCEPT, which a loopback connect both
/// authorizes — plus the `IS_LOOPBACK` flag permit on CONNECT as
/// belt-and-suspenders; NOT by the LUID permit. The range is the deterministic
/// matcher because the flag isn't reliably set at either ALE layer on the
/// elevated lane. A closed-port probe disambiguates any loopback failure
/// (refused => CONNECT permitted, so a listener-probe timeout is an accept-side
/// drop). The interface alias is resolved only to drive the real
/// `ConvertInterfaceAliasToLuid` + `LocalInterface` filter path; that permit
/// matches the named interface's traffic, not loopback in general. The block
/// assertion does not depend on a live `hole-tun`. `serial = TUN` serializes
/// against other in-binary TUN tests; the cross-binary race with the bridge's
/// real-egress e2e is handled by the `global-net-state` test-group
/// (`.config/nextest.toml`).
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn windows_lockdown_blocks_egress_and_permits_loopback() {
    use std::net::TcpListener;
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let resolver = SystemLuidResolver;
    let server_ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();

    // A loopback listener proves the loopback permit holds while the cover is up.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let loopback_port = listener.local_addr().unwrap().port();

    // A closed loopback port: bind to grab a free port, then drop the listener so
    // nothing accepts there. Probing it disambiguates a listener-probe failure —
    // ConnectionRefused proves the CONNECT itself is permitted (kernel reached the
    // closed port and RST'd), so a listener-probe timeout is an accept-side drop;
    // TimedOut/PermissionDenied means the CONNECT is blocked outright.
    let closed_probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_port = closed_probe.local_addr().unwrap().port();
    drop(closed_probe);

    let cover = engage_lockdown(server_ip, "Loopback Pseudo-Interface 1", &resolver, &[], dir.path())
        .expect("engage real WFP lockdown cover");

    // Discriminating probe: connect to the closed loopback port. See above for how
    // its error kind separates a CONNECT block from a RECV_ACCEPT drop.
    let closed_probe_err = std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{closed_port}").parse().unwrap(),
        Duration::from_secs(2),
    )
    .err()
    .map(|e| e.kind());

    // (a) Loopback connect still succeeds (loopback permit). External event with
    // graceful failure bound: the timeout is the failure-to-human signal, not a
    // sync sleep; the assertion is success, not "completed within N".
    let lo = std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{loopback_port}").parse().unwrap(),
        Duration::from_secs(2),
    );
    // Include both probes' error kinds so a failure shows where the drop is: the
    // listener probe's kind (timeout = still dropped, refused = nobody listening,
    // perm = ACL) and the closed-port probe (refused => CONNECT permitted, so a
    // listener-probe timeout is an accept-side drop).
    assert!(
        lo.is_ok(),
        "loopback must stay permitted under lockdown: listener_probe={:?} closed_port_probe(refused=>connect-permitted)={:?}",
        lo.err(),
        closed_probe_err
    );

    // (b) Egress to a non-permitted public IP is blocked at ALE_AUTH_CONNECT.
    // 198.51.100.1 (TEST-NET-2) discard port: external event with graceful
    // failure bound — the assertion is that it ERRORS, not that it times out.
    let blocked = std::net::TcpStream::connect_timeout(&"198.51.100.1:9".parse().unwrap(), Duration::from_secs(2));
    assert!(blocked.is_err(), "lockdown must block egress to a non-permitted IP");

    // Drop sweeps the lockdown filters (kind-aware Cover Drop); egress restored.
    drop(cover);
    drop(listener);
}

/// macOS real-engage verification. Engages the REAL pf lockdown cover (an
/// authoritative main-ruleset replace: `block drop out quick all` with earlier
/// `quick` permits for loopback, the TUN, and the server IP — no anchor, so
/// there is no inert-anchor failure mode) and proves (a) the live filter
/// ruleset carries our block rule, (b) egress to a non-server, non-loopback IP
/// is dropped while the cover holds, and (c) Drop restores the pre-lockdown
/// snapshot.
///
/// No live utun is needed for the block assertion: `pass out quick on
/// <tun-absent>` simply never matches, so a probe to an arbitrary IP is blocked
/// by `block drop out quick all`. `serial = TUN` + the `global-net-state`
/// test-group serialize the process-global pf state: `pfctl -E`/`-X` is
/// refcounted and the main ruleset is host-wide, so a concurrent cover test
/// would race the snapshot restore. (On macOS only this binary carries a TUN
/// test — the bridge TUN e2e is `cfg(windows)` — so the group is single-member,
/// but it costs nothing.)
#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn macos_lockdown_actually_blocks_and_restores() {
    use std::process::Command;
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let resolver = SystemLuidResolver;
    let server_ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();

    let cover =
        engage_lockdown(server_ip, "utun-absent", &resolver, &[], dir.path()).expect("engage real pf lockdown cover");

    // (a) The live main ruleset carries our authoritative block rule.
    let sr = Command::new("pfctl").args(["-sr"]).output().unwrap();
    let rules = String::from_utf8_lossy(&sr.stdout);
    assert!(
        rules.contains("block drop out quick all"),
        "main ruleset must carry the lockdown block (else inert):\n{rules}"
    );

    // (b) Egress to a non-permitted IP is blocked while the cover holds.
    // External event with graceful failure bound: the assertion is that it
    // ERRORS, not that it times out.
    let blocked = std::net::TcpStream::connect_timeout(&"198.51.100.1:9".parse().unwrap(), Duration::from_secs(2));
    assert!(blocked.is_err(), "lockdown must block egress to a non-permitted IP");

    // (c) Drop restores the pre-lockdown snapshot; our block rule is gone.
    drop(cover);
    let after = Command::new("pfctl").args(["-sr"]).output().unwrap();
    assert!(
        !String::from_utf8_lossy(&after.stdout).contains("block drop out quick all"),
        "snapshot restore must remove our lockdown block rule"
    );
}
