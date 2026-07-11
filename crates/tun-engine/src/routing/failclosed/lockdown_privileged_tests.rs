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
// A third routable host engaged as a DoH resolver IP, so the transient
// block-until-connected cover's resolver permit is proven distinct from the
// server permit.
#[cfg(any(target_os = "windows", target_os = "macos"))]
const RESOLVER: &str = "9.9.9.9:443";

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
    let cover = engage_lockdown(
        server_ip,
        "Loopback Pseudo-Interface 1",
        &resolver,
        &[],
        dir.path(),
        None,
    )
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

    let cover = engage_lockdown(server_ip, "utun-absent", &resolver, &[], dir.path(), None)
        .expect("engage real pf lockdown cover");

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

/// Windows real-engage verification for the transient block-until-connected cover
/// (#553). Engages the REAL WFP transient cover with `server_ip = 1.1.1.1` and a
/// resolver permit for `9.9.9.9`, and proves it is SELECTIVE: egress to the
/// permitted server IP AND the resolver IP stay Ok (each permit beats block-all —
/// catches the block-everything arbitration bug AND proves the resolver permit is
/// wired) while a non-permitted host is blocked (no leak). Drop restores egress.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn windows_failclosed_permits_server_and_resolver_blocks_other_egress() {
    use std::net::TcpStream;
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();
    let resolver_ip: std::net::IpAddr = "9.9.9.9".parse().unwrap();

    // External-event probe with a graceful failure bound: the timeout is the
    // failure-to-human signal, not a sync sleep; assertions are Ok/Err, not timing.
    let connect = |addr: &str| TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5));

    // Baseline (PRE-cover): all three hosts reachable — self-validates the probe so
    // a network blip is never a false pass.
    let (bp, br, bn) = (connect(PERMITTED), connect(RESOLVER), connect(NON_PERMITTED));
    assert!(
        bp.is_ok() && br.is_ok() && bn.is_ok(),
        "NETWORK/ENVIRONMENT problem (not the cover): baseline egress must reach all three hosts; \
         {PERMITTED}={:?} {RESOLVER}={:?} {NON_PERMITTED}={:?}",
        bp.err().map(|e| e.kind()),
        br.err().map(|e| e.kind()),
        bn.err().map(|e| e.kind()),
    );

    let cover = engage(server_ip, &[resolver_ip], dir.path(), None).expect("engage real WFP transient cover");

    let (p, r, n) = (connect(PERMITTED), connect(RESOLVER), connect(NON_PERMITTED));
    assert!(
        p.is_ok(),
        "server-IP permit must beat block-all: {PERMITTED}={:?}",
        p.err().map(|e| e.kind())
    );
    assert!(
        r.is_ok(),
        "resolver-IP permit must beat block-all: {RESOLVER}={:?}",
        r.err().map(|e| e.kind())
    );
    assert!(
        n.is_err(),
        "transient cover must block a non-permitted host (leak!): {NON_PERMITTED} connected"
    );

    drop(cover);
    assert!(
        connect(NON_PERMITTED).is_ok(),
        "disengage must restore egress: {NON_PERMITTED}={:?}",
        connect(NON_PERMITTED).err().map(|e| e.kind()),
    );
}

/// macOS real-engage verification for the transient block-until-connected cover
/// (#553). Engages the REAL pf transient cover (`block out all` with `quick`
/// permits for loopback, the server IP, and the resolver IP), proves (a) the live
/// ruleset carries our block + resolver pass, (b) it is SELECTIVE, and (c) Drop
/// restores `/etc/pf.conf`.
#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn macos_failclosed_permits_server_and_resolver_blocks_other_egress() {
    use std::net::TcpStream;
    use std::process::Command;
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();
    let resolver_ip: std::net::IpAddr = "9.9.9.9".parse().unwrap();

    let connect = |addr: &str| TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5));

    let (bp, br, bn) = (connect(PERMITTED), connect(RESOLVER), connect(NON_PERMITTED));
    assert!(
        bp.is_ok() && br.is_ok() && bn.is_ok(),
        "NETWORK/ENVIRONMENT problem (not the cover): baseline egress must reach all three hosts; \
         {PERMITTED}={:?} {RESOLVER}={:?} {NON_PERMITTED}={:?}",
        bp.err().map(|e| e.kind()),
        br.err().map(|e| e.kind()),
        bn.err().map(|e| e.kind()),
    );

    let cover = engage(server_ip, &[resolver_ip], dir.path(), None).expect("engage real pf transient cover");

    // (a) The live ruleset carries our block-all + the resolver pass.
    let sr = Command::new("pfctl").args(["-sr"]).output().unwrap();
    let rules = String::from_utf8_lossy(&sr.stdout);
    assert!(
        rules.contains("block") && rules.contains("all"),
        "ruleset must carry the block:\n{rules}"
    );
    assert!(
        rules.contains("9.9.9.9"),
        "ruleset must carry the resolver pass:\n{rules}"
    );

    let (p, r, n) = (connect(PERMITTED), connect(RESOLVER), connect(NON_PERMITTED));
    assert!(
        p.is_ok(),
        "server-IP permit must beat block-all: {PERMITTED}={:?}",
        p.err().map(|e| e.kind())
    );
    assert!(
        r.is_ok(),
        "resolver-IP permit must beat block-all: {RESOLVER}={:?}",
        r.err().map(|e| e.kind())
    );
    assert!(
        n.is_err(),
        "transient cover must block a non-permitted host (leak!): {NON_PERMITTED} connected"
    );

    // (c) Drop restores /etc/pf.conf: egress restored.
    drop(cover);
    assert!(
        connect(NON_PERMITTED).is_ok(),
        "disengage must restore egress: {NON_PERMITTED}={:?}",
        connect(NON_PERMITTED).err().map(|e| e.kind()),
    );
}
