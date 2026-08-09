//! Privileged-lane real-engage verification for the standing lockdown cover and
//! the transient block-until-connected cover. Unlike the pure builder unit tests
//! (`windows_tests` / `macos_tests`, the #165 isolation contract), these engage
//! the REAL OS cover (Windows: live
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
//! COUPLED NAMES: that group's filter matches these tests by the name substrings
//! `windows_lockdown_permits_`, `macos_lockdown_permits_` (every real-engage
//! standing-lockdown test, server-IP and resolver-IP alike), and
//! `failclosed_permits_` (the transient-cover tests). Renaming one, or adding a
//! new real-engage test that doesn't share one of these substrings, WITHOUT
//! updating `.config/nextest.toml` drops the test from the group → a silent
//! cross-binary race with the bridge's live-egress `e2e_none_full_tunnel_roundtrip`.
//! Change both together.

use super::*;

#[skuld::label]
const TUN: skuld::Label;

// Two routable anycast hosts on :443 (the runner has outbound internet). IP
// literals only — the cover blocks DNS, so a hostname connect would fail for the
// wrong reason. PERMITTED is engaged as the server IP; NON_PERMITTED proves the
// block holds.
#[cfg(any(target_os = "windows", target_os = "macos"))]
const PERMITTED: &str = "1.1.1.1:443";
// A third routable anycast host, standing in for the pinned DoH resolver.
#[cfg(any(target_os = "windows", target_os = "macos"))]
const RESOLVER: &str = "9.9.9.9:443";
// The SAME resolver host, but on its DNS-over-TLS port rather than 443 — Quad9
// serves both. Proves the resolver permit is scoped to TCP/443, not the whole
// IP: a permit that (wrongly) covered every port on RESOLVER would let this
// through too.
#[cfg(any(target_os = "windows", target_os = "macos"))]
const RESOLVER_OTHER_PORT: &str = "9.9.9.9:853";
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
    let cover = engage_lockdown(
        server_ip,
        None,
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

/// Windows real-engage verification that the STANDING lockdown cover's
/// OPTIONAL resolver permit is real and selective — the Windows counterpart of
/// `windows_failclosed_permits_resolver_blocks_other_egress` for the transient
/// cover. With `resolver_ip = Some`, both the server AND the resolver stay
/// reachable while a third, non-permitted host is still blocked, and the
/// resolver permit is scoped to TCP/443 (the same resolver on a different port
/// stays blocked).
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn windows_lockdown_permits_resolver_blocks_other_egress() {
    use std::net::TcpStream;
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let resolver = SystemLuidResolver;
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();
    let resolver_ip: std::net::IpAddr = "9.9.9.9".parse().unwrap();

    let connect = |addr: &str| TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5));

    let (bp, br, bpo, bn) = (
        connect(PERMITTED),
        connect(RESOLVER),
        connect(RESOLVER_OTHER_PORT),
        connect(NON_PERMITTED),
    );
    assert!(
        bp.is_ok() && br.is_ok() && bpo.is_ok() && bn.is_ok(),
        "NETWORK/ENVIRONMENT problem (not the cover): baseline egress must reach all hosts; \
         {PERMITTED}={:?} {RESOLVER}={:?} {RESOLVER_OTHER_PORT}={:?} {NON_PERMITTED}={:?}",
        bp.err().map(|e| e.kind()),
        br.err().map(|e| e.kind()),
        bpo.err().map(|e| e.kind()),
        bn.err().map(|e| e.kind()),
    );

    let cover = engage_lockdown(
        server_ip,
        Some(resolver_ip),
        "Loopback Pseudo-Interface 1",
        &resolver,
        &[],
        dir.path(),
        None,
    )
    .expect("engage real WFP lockdown cover with a resolver permit");

    let (p, r, po, n) = (
        connect(PERMITTED),
        connect(RESOLVER),
        connect(RESOLVER_OTHER_PORT),
        connect(NON_PERMITTED),
    );
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
        po.is_err(),
        "the resolver permit must be scoped to TCP/443, not the whole IP (leak!): \
         {RESOLVER_OTHER_PORT} connected"
    );
    assert!(
        n.is_err(),
        "a third, non-permitted host must still be blocked (leak!): {NON_PERMITTED} connected"
    );

    drop(cover);
    let (rn, rpo) = (connect(NON_PERMITTED), connect(RESOLVER_OTHER_PORT));
    assert!(
        rn.is_ok() && rpo.is_ok(),
        "disengage must restore egress: {NON_PERMITTED}={:?} {RESOLVER_OTHER_PORT}={:?}",
        rn.err().map(|e| e.kind()),
        rpo.err().map(|e| e.kind()),
    );
}

/// Windows real-engage verification for the Phase-0 EARLY engage
/// (`engage_lockdown_permits`, #753). No RAII guard is returned (see that
/// fn's doc), so this test manually disengages via `disengage_lockdown` at
/// the end -- proving the fixed-GUID sweep machinery a normal Phase-6
/// disengage/recovery already uses fully restores egress even though no
/// in-memory guard ever owned these particular filters. Proves (a) the
/// server AND resolver permits are real and selective (a third,
/// non-permitted host stays blocked) with NO TUN permit installed, and (b)
/// the resolver permit stays scoped to TCP/443.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn windows_lockdown_permits_early_engage_admits_nothing_beyond_the_gated_addresses() {
    use std::net::TcpStream;
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();
    let resolver_ip: std::net::IpAddr = "9.9.9.9".parse().unwrap();

    let connect = |addr: &str| TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5));

    let (bp, br, bpo, bn) = (
        connect(PERMITTED),
        connect(RESOLVER),
        connect(RESOLVER_OTHER_PORT),
        connect(NON_PERMITTED),
    );
    assert!(
        bp.is_ok() && br.is_ok() && bpo.is_ok() && bn.is_ok(),
        "NETWORK/ENVIRONMENT problem (not the cover): baseline egress must reach all hosts; \
         {PERMITTED}={:?} {RESOLVER}={:?} {RESOLVER_OTHER_PORT}={:?} {NON_PERMITTED}={:?}",
        bp.err().map(|e| e.kind()),
        br.err().map(|e| e.kind()),
        bpo.err().map(|e| e.kind()),
        bn.err().map(|e| e.kind()),
    );

    engage_lockdown_permits(server_ip, Some(resolver_ip), &[], dir.path(), None)
        .expect("engage the real WFP lockdown cover's Phase-0 permits");

    let (p, r, po, n) = (
        connect(PERMITTED),
        connect(RESOLVER),
        connect(RESOLVER_OTHER_PORT),
        connect(NON_PERMITTED),
    );
    assert!(
        p.is_ok(),
        "server-IP permit must beat block-all even with no TUN permit installed: {PERMITTED}={:?}",
        p.err().map(|e| e.kind())
    );
    assert!(
        r.is_ok(),
        "resolver-IP permit must beat block-all: {RESOLVER}={:?}",
        r.err().map(|e| e.kind())
    );
    assert!(
        po.is_err(),
        "the resolver permit must be scoped to TCP/443, not the whole IP (leak!): \
         {RESOLVER_OTHER_PORT} connected"
    );
    assert!(
        n.is_err(),
        "a third, non-permitted host must still be blocked (leak!): {NON_PERMITTED} connected"
    );

    // No RAII guard exists to disengage on drop -- prove the fixed-GUID sweep
    // (the same `disengage_lockdown` a normal Phase-6 cover's stop/unlock
    // path uses) still fully restores egress for filters no guard ever owned.
    disengage_lockdown(dir.path()).expect("disengage the Phase-0-only cover via the fixed-GUID sweep");
    let (rn, rpo) = (connect(NON_PERMITTED), connect(RESOLVER_OTHER_PORT));
    assert!(
        rn.is_ok() && rpo.is_ok(),
        "disengage must restore egress: {NON_PERMITTED}={:?} {RESOLVER_OTHER_PORT}={:?}",
        rn.err().map(|e| e.kind()),
        rpo.err().map(|e| e.kind()),
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

    let cover = engage_lockdown(server_ip, None, "utun-absent", &resolver, &[], dir.path(), None)
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

/// macOS real-engage verification that the STANDING lockdown cover's
/// OPTIONAL resolver permit is real and selective — the macOS counterpart of
/// `windows_lockdown_permits_resolver_blocks_other_egress`. Also proves the
/// permit is scoped to TCP/443, not the whole resolver IP.
#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn macos_lockdown_permits_resolver_blocks_other_egress() {
    use std::net::TcpStream;
    use std::process::Command;
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let resolver = SystemLuidResolver;
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();
    let resolver_ip: std::net::IpAddr = "9.9.9.9".parse().unwrap();

    let connect = |addr: &str| TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5));

    let (bp, br, bpo, bn) = (
        connect(PERMITTED),
        connect(RESOLVER),
        connect(RESOLVER_OTHER_PORT),
        connect(NON_PERMITTED),
    );
    assert!(
        bp.is_ok() && br.is_ok() && bpo.is_ok() && bn.is_ok(),
        "NETWORK/ENVIRONMENT problem (not the cover): baseline egress must reach all hosts; \
         {PERMITTED}={:?} {RESOLVER}={:?} {RESOLVER_OTHER_PORT}={:?} {NON_PERMITTED}={:?}",
        bp.err().map(|e| e.kind()),
        br.err().map(|e| e.kind()),
        bpo.err().map(|e| e.kind()),
        bn.err().map(|e| e.kind()),
    );

    let cover = engage_lockdown(
        server_ip,
        Some(resolver_ip),
        "utun-absent",
        &resolver,
        &[],
        dir.path(),
        None,
    )
    .expect("engage real pf lockdown cover with a resolver permit");

    let sr = Command::new("pfctl").args(["-sr"]).output().unwrap();
    let rules = String::from_utf8_lossy(&sr.stdout);
    assert!(
        rules.contains("9.9.9.9"),
        "live lockdown ruleset must carry the resolver permit:\n{rules}"
    );

    let (p, r, po, n) = (
        connect(PERMITTED),
        connect(RESOLVER),
        connect(RESOLVER_OTHER_PORT),
        connect(NON_PERMITTED),
    );
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
        po.is_err(),
        "the resolver permit must be scoped to TCP/443, not the whole IP (leak!): \
         {RESOLVER_OTHER_PORT} connected"
    );
    assert!(
        n.is_err(),
        "a third, non-permitted host must still be blocked (leak!): {NON_PERMITTED} connected"
    );

    drop(cover);
    let (rn, rpo) = (connect(NON_PERMITTED), connect(RESOLVER_OTHER_PORT));
    assert!(
        rn.is_ok() && rpo.is_ok(),
        "disengage must restore egress: {NON_PERMITTED}={:?} {RESOLVER_OTHER_PORT}={:?}",
        rn.err().map(|e| e.kind()),
        rpo.err().map(|e| e.kind()),
    );
}

/// macOS real-engage verification for the Phase-0 EARLY engage
/// (`engage_lockdown_permits`, #753). No RAII guard is returned (see that
/// fn's doc), so this test manually disengages via `disengage_lockdown` at
/// the end -- proving the persisted lockdown-state-file recovery machinery a
/// normal Phase-6 disengage/recovery already uses fully restores egress even
/// though no in-memory guard ever owned this particular pf load. Proves (a)
/// the live ruleset carries NO TUN pass line, (b) the server AND resolver
/// permits are real and selective, and (c) the resolver permit stays scoped
/// to TCP/443.
#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn macos_lockdown_permits_early_engage_admits_nothing_beyond_the_gated_addresses() {
    use std::net::TcpStream;
    use std::process::Command;
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();
    let resolver_ip: std::net::IpAddr = "9.9.9.9".parse().unwrap();

    let connect = |addr: &str| TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5));

    let (bp, br, bpo, bn) = (
        connect(PERMITTED),
        connect(RESOLVER),
        connect(RESOLVER_OTHER_PORT),
        connect(NON_PERMITTED),
    );
    assert!(
        bp.is_ok() && br.is_ok() && bpo.is_ok() && bn.is_ok(),
        "NETWORK/ENVIRONMENT problem (not the cover): baseline egress must reach all hosts; \
         {PERMITTED}={:?} {RESOLVER}={:?} {RESOLVER_OTHER_PORT}={:?} {NON_PERMITTED}={:?}",
        bp.err().map(|e| e.kind()),
        br.err().map(|e| e.kind()),
        bpo.err().map(|e| e.kind()),
        bn.err().map(|e| e.kind()),
    );

    engage_lockdown_permits(server_ip, Some(resolver_ip), &[], dir.path(), None)
        .expect("engage the real pf lockdown cover's Phase-0 permits");

    let sr = Command::new("pfctl").args(["-sr"]).output().unwrap();
    let rules = String::from_utf8_lossy(&sr.stdout);
    assert!(
        !rules.contains("pass out quick on"),
        "no TUN pass line must be live before routing.install has resolved the adapter:\n{rules}"
    );

    let (p, r, po, n) = (
        connect(PERMITTED),
        connect(RESOLVER),
        connect(RESOLVER_OTHER_PORT),
        connect(NON_PERMITTED),
    );
    assert!(
        p.is_ok(),
        "server-IP permit must beat block-all even with no TUN permit installed: {PERMITTED}={:?}",
        p.err().map(|e| e.kind())
    );
    assert!(
        r.is_ok(),
        "resolver-IP permit must beat block-all: {RESOLVER}={:?}",
        r.err().map(|e| e.kind())
    );
    assert!(
        po.is_err(),
        "the resolver permit must be scoped to TCP/443, not the whole IP (leak!): \
         {RESOLVER_OTHER_PORT} connected"
    );
    assert!(
        n.is_err(),
        "a third, non-permitted host must still be blocked (leak!): {NON_PERMITTED} connected"
    );

    // No RAII guard exists to disengage on drop -- prove the persisted-state
    // recovery (the same `disengage_lockdown` a normal Phase-6 cover's
    // stop/unlock path uses) still fully restores egress.
    disengage_lockdown(dir.path()).expect("disengage the Phase-0-only cover via the persisted state file");
    let (rn, rpo) = (connect(NON_PERMITTED), connect(RESOLVER_OTHER_PORT));
    assert!(
        rn.is_ok() && rpo.is_ok(),
        "disengage must restore egress: {NON_PERMITTED}={:?} {RESOLVER_OTHER_PORT}={:?}",
        rn.err().map(|e| e.kind()),
        rpo.err().map(|e| e.kind()),
    );
}

/// Windows real-engage verification for the transient block-until-connected
/// cover. Engages the REAL WFP transient cover with `server_ip = 1.1.1.1` and
/// proves it is SELECTIVE: egress to the permitted server IP stays Ok (the permit
/// beats block-all — catches the block-everything arbitration bug) while a
/// non-permitted host is blocked (no leak). Drop restores egress.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn windows_failclosed_permits_server_blocks_other_egress() {
    use std::net::TcpStream;
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    // External-event probe with a graceful failure bound: the timeout is the
    // failure-to-human signal, not a sync sleep; assertions are Ok/Err, not timing.
    let connect = |addr: &str| TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5));

    // Baseline (PRE-cover): both hosts reachable — self-validates the probe so a
    // network blip is never a false pass.
    let (bp, bn) = (connect(PERMITTED), connect(NON_PERMITTED));
    assert!(
        bp.is_ok() && bn.is_ok(),
        "NETWORK/ENVIRONMENT problem (not the cover): baseline egress must reach both hosts; \
         {PERMITTED}={:?} {NON_PERMITTED}={:?}",
        bp.err().map(|e| e.kind()),
        bn.err().map(|e| e.kind()),
    );

    let cover = engage(server_ip, None, dir.path(), None).expect("engage real WFP transient cover");

    let (p, n) = (connect(PERMITTED), connect(NON_PERMITTED));
    assert!(
        p.is_ok(),
        "server-IP permit must beat block-all: {PERMITTED}={:?}",
        p.err().map(|e| e.kind())
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

/// Real-engage verification that the OPTIONAL resolver permit is
/// real and selective: with `resolver_ip = Some`, both the server AND the
/// resolver stay reachable while a THIRD, non-permitted host is still
/// blocked — proving the widening is exactly one address, not a leak. Also
/// proves the permit is scoped to TCP/443, not the whole resolver IP: the
/// SAME resolver on a different port stays blocked.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn windows_failclosed_permits_resolver_blocks_other_egress() {
    use std::net::TcpStream;
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();
    let resolver_ip: std::net::IpAddr = "9.9.9.9".parse().unwrap();

    let connect = |addr: &str| TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5));

    let (bp, br, bpo, bn) = (
        connect(PERMITTED),
        connect(RESOLVER),
        connect(RESOLVER_OTHER_PORT),
        connect(NON_PERMITTED),
    );
    assert!(
        bp.is_ok() && br.is_ok() && bpo.is_ok() && bn.is_ok(),
        "NETWORK/ENVIRONMENT problem (not the cover): baseline egress must reach all hosts; \
         {PERMITTED}={:?} {RESOLVER}={:?} {RESOLVER_OTHER_PORT}={:?} {NON_PERMITTED}={:?}",
        bp.err().map(|e| e.kind()),
        br.err().map(|e| e.kind()),
        bpo.err().map(|e| e.kind()),
        bn.err().map(|e| e.kind()),
    );

    let cover = engage(server_ip, Some(resolver_ip), dir.path(), None)
        .expect("engage real WFP transient cover with a resolver permit");

    let (p, r, po, n) = (
        connect(PERMITTED),
        connect(RESOLVER),
        connect(RESOLVER_OTHER_PORT),
        connect(NON_PERMITTED),
    );
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
        po.is_err(),
        "the resolver permit must be scoped to TCP/443, not the whole IP (leak!): \
         {RESOLVER_OTHER_PORT} connected"
    );
    assert!(
        n.is_err(),
        "a third, non-permitted host must still be blocked (leak!): {NON_PERMITTED} connected"
    );

    drop(cover);
    let (rn, rpo) = (connect(NON_PERMITTED), connect(RESOLVER_OTHER_PORT));
    assert!(
        rn.is_ok() && rpo.is_ok(),
        "disengage must restore egress: {NON_PERMITTED}={:?} {RESOLVER_OTHER_PORT}={:?}",
        rn.err().map(|e| e.kind()),
        rpo.err().map(|e| e.kind()),
    );
}

/// macOS real-engage verification for the transient block-until-connected cover.
/// Engages the REAL pf transient cover (`block out all` with `quick` permits for
/// loopback and the server IP), proves (a) the live ruleset carries our block,
/// (b) it is SELECTIVE, and (c) Drop restores `/etc/pf.conf`.
#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn macos_failclosed_permits_server_blocks_other_egress() {
    use std::net::TcpStream;
    use std::process::Command;
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    let connect = |addr: &str| TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5));

    let (bp, bn) = (connect(PERMITTED), connect(NON_PERMITTED));
    assert!(
        bp.is_ok() && bn.is_ok(),
        "NETWORK/ENVIRONMENT problem (not the cover): baseline egress must reach both hosts; \
         {PERMITTED}={:?} {NON_PERMITTED}={:?}",
        bp.err().map(|e| e.kind()),
        bn.err().map(|e| e.kind()),
    );

    let cover = engage(server_ip, None, dir.path(), None).expect("engage real pf transient cover");

    // (a) The live ruleset carries our block-all.
    let sr = Command::new("pfctl").args(["-sr"]).output().unwrap();
    let rules = String::from_utf8_lossy(&sr.stdout);
    assert!(
        rules.contains("block") && rules.contains("all"),
        "ruleset must carry the block:\n{rules}"
    );

    let (p, n) = (connect(PERMITTED), connect(NON_PERMITTED));
    assert!(
        p.is_ok(),
        "server-IP permit must beat block-all: {PERMITTED}={:?}",
        p.err().map(|e| e.kind())
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

/// macOS counterpart of `windows_failclosed_permits_resolver_blocks_other_egress`.
/// Also proves the permit is scoped to TCP/443, not the whole resolver IP: the
/// SAME resolver on a different port stays blocked.
#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn macos_failclosed_permits_resolver_blocks_other_egress() {
    use std::net::TcpStream;
    use std::process::Command;
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();
    let resolver_ip: std::net::IpAddr = "9.9.9.9".parse().unwrap();

    let connect = |addr: &str| TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5));

    let (bp, br, bpo, bn) = (
        connect(PERMITTED),
        connect(RESOLVER),
        connect(RESOLVER_OTHER_PORT),
        connect(NON_PERMITTED),
    );
    assert!(
        bp.is_ok() && br.is_ok() && bpo.is_ok() && bn.is_ok(),
        "NETWORK/ENVIRONMENT problem (not the cover): baseline egress must reach all hosts; \
         {PERMITTED}={:?} {RESOLVER}={:?} {RESOLVER_OTHER_PORT}={:?} {NON_PERMITTED}={:?}",
        bp.err().map(|e| e.kind()),
        br.err().map(|e| e.kind()),
        bpo.err().map(|e| e.kind()),
        bn.err().map(|e| e.kind()),
    );

    let cover = engage(server_ip, Some(resolver_ip), dir.path(), None)
        .expect("engage real pf transient cover with a resolver permit");

    let sr = Command::new("pfctl").args(["-sr"]).output().unwrap();
    let rules = String::from_utf8_lossy(&sr.stdout);
    assert!(
        rules.contains("9.9.9.9"),
        "live ruleset must carry the resolver permit:\n{rules}"
    );

    let (p, r, po, n) = (
        connect(PERMITTED),
        connect(RESOLVER),
        connect(RESOLVER_OTHER_PORT),
        connect(NON_PERMITTED),
    );
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
        po.is_err(),
        "the resolver permit must be scoped to TCP/443, not the whole IP (leak!): \
         {RESOLVER_OTHER_PORT} connected"
    );
    assert!(
        n.is_err(),
        "a third, non-permitted host must still be blocked (leak!): {NON_PERMITTED} connected"
    );

    drop(cover);
    let (rn, rpo) = (connect(NON_PERMITTED), connect(RESOLVER_OTHER_PORT));
    assert!(
        rn.is_ok() && rpo.is_ok(),
        "disengage must restore egress: {NON_PERMITTED}={:?} {RESOLVER_OTHER_PORT}={:?}",
        rn.err().map(|e| e.kind()),
        rpo.err().map(|e| e.kind()),
    );
}
