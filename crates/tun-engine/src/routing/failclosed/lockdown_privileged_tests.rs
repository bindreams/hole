//! Privileged-lane real-engage verification for the standing lockdown cover
//! (#527). Unlike the pure builder unit tests (`windows_tests` / `macos_tests`,
//! the #165 isolation contract), these engage the REAL OS cover (Windows: live
//! FWPM; macOS: live pf) and prove at runtime that it is SELECTIVE: it permits
//! the configured server IP and blocks all other egress, then restores on
//! disengage. That catches the block-everything arbitration class of bug (the
//! permit must beat block-all) AND proves no-leak (a non-permitted host is
//! blocked).
//!
//! The probe is OUTBOUND egress, not inbound loopback: an egress kill switch
//! governs outbound flows, and the GitHub Actions Windows runner's firewall
//! drops inbound loopback to the test exe — a pre-cover baseline connect to a
//! local listener TIMES OUT even with no cover, so loopback can't tell a working
//! cover from a broken one. Outbound to a routable IP works on the runner.
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
//!
//! COUPLED NAMES: that group's filter matches these tests by the name prefixes
//! `windows_lockdown_permits_server_ip_` and `macos_lockdown_permits_server_ip_`.
//! Renaming a prefix WITHOUT updating `.config/nextest.toml` drops the test from
//! the group → a silent cross-binary race with the bridge's live-egress
//! `e2e_none_full_tunnel_roundtrip`. Change both together.

use super::*;

#[skuld::label]
const TUN: skuld::Label;

// Two routable anycast hosts on :443 (the runner has outbound internet). IP
// literals only — the cover blocks DNS, so a hostname connect would fail for the
// wrong reason. PERMITTED is engaged as the server IP; NON_PERMITTED proves the
// block holds.
#[cfg(any(target_os = "windows", target_os = "macos"))]
const PERMITTED: &str = "1.1.1.1:443";
#[cfg(any(target_os = "windows", target_os = "macos"))]
const NON_PERMITTED: &str = "8.8.8.8:443";

/// Windows real-engage verification. Engages the REAL WFP lockdown cover with
/// `server_ip = 1.1.1.1` and proves it is SELECTIVE: egress to the permitted
/// server IP stays Ok (the permit beats block-all — the assertion that catches
/// the block-everything arbitration bug) while egress to a non-permitted host is
/// blocked at `ALE_AUTH_CONNECT` (no leak). Drop restores both.
///
/// The interface alias resolves a real, always-present LUID purely to drive the
/// real `ConvertInterfaceAliasToLuid` + `LocalInterface` filter path; the
/// block/permit assertions don't depend on it (the `LocalInterface` permit
/// matches that interface's traffic, not the egress probed here), nor on a live
/// `hole-tun`. `serial = TUN` serializes against other in-binary TUN tests; the
/// cross-binary race with the bridge's real-egress e2e is handled by the
/// `global-net-state` test-group (`.config/nextest.toml`).
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn windows_lockdown_permits_server_ip_and_blocks_other_egress() {
    use std::net::TcpStream;
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let resolver = SystemLuidResolver;
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    // External-event probe with a graceful failure bound: the timeout is the
    // failure-to-human signal, not a sync sleep; assertions are Ok/Err, not timing.
    let connect = |addr: &str| TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5));

    // Baseline (PRE-cover): both hosts must be reachable. A failure here is a
    // network/reachability problem, not the cover — fail loud and self-validate the
    // probe so a network blip is never a false pass.
    let base_permitted = connect(PERMITTED);
    let base_non = connect(NON_PERMITTED);
    assert!(
        base_permitted.is_ok() && base_non.is_ok(),
        "NETWORK/ENVIRONMENT problem (not the cover): pre-cover baseline egress must reach both hosts; \
         {PERMITTED}={:?} {NON_PERMITTED}={:?}",
        base_permitted.err().map(|e| e.kind()),
        base_non.err().map(|e| e.kind()),
    );

    // "Loopback Pseudo-Interface 1" is an always-present alias used only as a LUID
    // source to exercise the real resolve + `LocalInterface` filter path.
    let cover = engage_lockdown(server_ip, "Loopback Pseudo-Interface 1", &resolver, &[], dir.path())
        .expect("engage real WFP lockdown cover");

    let permitted = connect(PERMITTED);
    let non = connect(NON_PERMITTED);

    // Permit beats block-all: the server IP stays reachable (catches block-everything).
    assert!(
        permitted.is_ok(),
        "server-IP permit must beat block-all (else the cover blocks everything): \
         {PERMITTED}={:?}; baseline {PERMITTED}=Ok {NON_PERMITTED}=Ok",
        permitted.err().map(|e| e.kind()),
    );
    // No leak: egress to a non-permitted host is blocked at ALE_AUTH_CONNECT.
    assert!(
        non.is_err(),
        "lockdown must block egress to a non-permitted host (leak!): \
         {NON_PERMITTED} connected; baseline {PERMITTED}=Ok {NON_PERMITTED}=Ok",
    );

    // Drop sweeps the lockdown filters (kind-aware Cover Drop); egress restored.
    drop(cover);
    assert!(
        connect(NON_PERMITTED).is_ok(),
        "disengage must restore egress to the previously-blocked host: {NON_PERMITTED}={:?}",
        connect(NON_PERMITTED).err().map(|e| e.kind()),
    );
}

/// macOS real-engage verification. Engages the REAL pf lockdown cover (an
/// authoritative main-ruleset replace: `block drop out quick all` with earlier
/// `quick` permits for loopback, the TUN, and the server IP — no anchor, so
/// there is no inert-anchor failure mode) with `server_ip = 1.1.1.1` and proves
/// (a) the live ruleset carries our block rule, (b) it is SELECTIVE — egress to
/// the server IP stays Ok while a non-permitted host is dropped, and (c) Drop
/// restores the pre-lockdown snapshot.
///
/// No live utun is needed: `pass out quick on <tun-absent>` simply never matches,
/// so the block rule governs the probed egress. `serial = TUN` + the
/// `global-net-state` test-group serialize the process-global pf state:
/// `pfctl -E`/`-X` is refcounted and the main ruleset is host-wide, so a
/// concurrent cover test would race the snapshot restore.
#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn macos_lockdown_permits_server_ip_blocks_other_egress_and_restores() {
    use std::net::TcpStream;
    use std::process::Command;
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let resolver = SystemLuidResolver;
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    // External-event probe with a graceful failure bound: the timeout is the
    // failure-to-human signal, not a sync sleep; assertions are Ok/Err, not timing.
    let connect = |addr: &str| TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5));

    // Baseline (PRE-cover): both hosts must be reachable. A failure here is a
    // network/reachability problem, not the cover — fail loud and self-validate the
    // probe so a network blip is never a false pass.
    let base_permitted = connect(PERMITTED);
    let base_non = connect(NON_PERMITTED);
    assert!(
        base_permitted.is_ok() && base_non.is_ok(),
        "NETWORK/ENVIRONMENT problem (not the cover): pre-cover baseline egress must reach both hosts; \
         {PERMITTED}={:?} {NON_PERMITTED}={:?}",
        base_permitted.err().map(|e| e.kind()),
        base_non.err().map(|e| e.kind()),
    );

    let cover =
        engage_lockdown(server_ip, "utun-absent", &resolver, &[], dir.path()).expect("engage real pf lockdown cover");

    // (a) The live main ruleset carries our authoritative block rule.
    let sr = Command::new("pfctl").args(["-sr"]).output().unwrap();
    let rules = String::from_utf8_lossy(&sr.stdout);
    assert!(
        rules.contains("block drop out quick all"),
        "main ruleset must carry the lockdown block (else inert):\n{rules}"
    );

    let permitted = connect(PERMITTED);
    let non = connect(NON_PERMITTED);

    // (b) Selective: permit beats block (server IP reachable), non-permitted blocked.
    assert!(
        permitted.is_ok(),
        "server-IP permit must beat block-all (else the cover blocks everything): \
         {PERMITTED}={:?}; baseline {PERMITTED}=Ok {NON_PERMITTED}=Ok",
        permitted.err().map(|e| e.kind()),
    );
    assert!(
        non.is_err(),
        "lockdown must block egress to a non-permitted host (leak!): \
         {NON_PERMITTED} connected; baseline {PERMITTED}=Ok {NON_PERMITTED}=Ok",
    );

    // (c) Drop restores the pre-lockdown snapshot: block rule gone, egress restored.
    drop(cover);
    let after = Command::new("pfctl").args(["-sr"]).output().unwrap();
    assert!(
        !String::from_utf8_lossy(&after.stdout).contains("block drop out quick all"),
        "snapshot restore must remove our lockdown block rule"
    );
    assert!(
        connect(NON_PERMITTED).is_ok(),
        "disengage must restore egress to the previously-blocked host: {NON_PERMITTED}={:?}",
        connect(NON_PERMITTED).err().map(|e| e.kind()),
    );
}
