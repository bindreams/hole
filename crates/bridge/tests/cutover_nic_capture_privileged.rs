//! Privileged-lane WIRE-LEVEL no-leak proof for the standing lockdown cover
//! (#527, PR2). Where the sibling `lockdown_privileged_tests` connect()-probe
//! infers no-leak from an Ok/Err on egress, this captures the PHYSICAL egress
//! NIC and asserts at the wire what did and did not leave the box.
//!
//! Windows only, in-box `pktmon` (no `pcap` crate, no Npcap — the free Npcap
//! has no silent CI install). macOS gets NO NIC capture here: its BPF tap sits
//! UPSTREAM of pf, so an en0 capture would record packets pf later drops — an
//! unsound proof. macOS keeps the connect()-probe in
//! `tun-engine/.../lockdown_privileged_tests.rs` by design.
//!
//! Matching is by a per-marker 16-byte nonce in the UDP PAYLOAD, never by
//! destination alone, so ambient runner UDP can never alias the verdict.
//!
//! THIS TEST CANNOT RUN UNELEVATED OR OFF-CI: it engages a system-wide WFP
//! block-all (would sever a dev box) and drives `pktmon`, which needs the
//! elevated token. The `TUN` label gates it to the elevated Windows tun lane
//! (excluded from the `SKULD_LABELS="!tun"` unprivileged pass) — the same lane
//! that already runs the bridge integration tests under the elevated token.
//! Local verification is COMPILE + clippy only.
//!
//! Cross-binary serialization of the global WFP/pf/TUN state lives in
//! `.config/nextest.toml` (`global-net-state` test-group). COUPLED NAMES: that
//! group's filter matches by the `cutover_global_net_state_` prefix — renaming
//! it WITHOUT updating the filter drops the test from the group (a silent
//! cross-binary race). Change both together.

hole_test_observability::register!();

fn main() {
    skuld::run_all();
}

#[skuld::label]
const TUN: skuld::Label;

#[cfg(target_os = "windows")]
use std::net::{IpAddr, SocketAddr};
#[cfg(target_os = "windows")]
use std::path::Path;
#[cfg(target_os = "windows")]
use std::process::Command;

// Engaged as the server IP — the WFP server permit at ALE_AUTH_CONNECT keys on
// RemoteIp, which is protocol-agnostic, so a UDP datagram to it egresses. That
// permitted tail is the rendezvous proving the would-leak datagram's ALE
// decision already completed (see the Phase-B comment).
#[cfg(target_os = "windows")]
const SERVER_IP: &str = "1.1.1.1";
// A routable, NON-permitted destination: a leak would show up egressing here.
#[cfg(target_os = "windows")]
const NON_PERMITTED_IP: &str = "8.8.8.8";
// DNS port — a plausible real UDP destination, so the filter (and the leak it
// would represent) is realistic.
#[cfg(target_os = "windows")]
const DST_PORT: u16 = 53;

/// External-event probe with a graceful failure bound: the timeout is the
/// failure-to-human signal for baseline reachability, not a sync sleep.
#[cfg(target_os = "windows")]
fn tcp_reachable(addr: SocketAddr) -> bool {
    use std::time::Duration;
    std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).is_ok()
}

/// Run a `pktmon` subcommand, failing loud on a non-zero exit. `pktmon` is the
/// proof's measurement apparatus — a missing or broken pktmon must FAIL the
/// test, never silently skip it.
#[cfg(target_os = "windows")]
fn pktmon(args: &[&str]) -> std::process::Output {
    let out = Command::new("pktmon")
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("pktmon is the measurement apparatus and must be present: spawn {args:?}: {e}"));
    assert!(
        out.status.success(),
        "pktmon {args:?} failed ({}): stdout={} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    out
}

/// RAII guard that always tears down the live pktmon session and filters, so a
/// panicking assertion never leaves a capture running or filters installed on
/// the runner. Mirrors the cover guard / EtwGuard discipline.
///
/// `stop` ends the capture, `filter remove` clears the filter set (`reset` only
/// zeroes counters, so it does NOT remove filters), `reset` clears counters as a
/// final tidy. Best-effort: Drop must not panic, so failures are swallowed here —
/// the positive assertions live in the test body.
#[cfg(target_os = "windows")]
struct PktmonGuard;

#[cfg(target_os = "windows")]
impl Drop for PktmonGuard {
    fn drop(&mut self) {
        for args in [
            ["stop"].as_slice(),
            ["filter", "remove"].as_slice(),
            ["reset"].as_slice(),
        ] {
            let _ = Command::new("pktmon").args(args).output();
        }
    }
}

/// Send `nonce` followed by 16 zero filler bytes (a 32-byte datagram) to `dst`
/// from the NIC-bound `socket`. The nonce is the wire fingerprint matched in the
/// capture.
///
/// A bound, unconnected UDP `send_to` does no handshake: the datagram either
/// egresses (and is captured) or is dropped at `ALE_AUTH_CONNECT` by the cover.
/// `send_to` returning `Ok` means the kernel accepted it for transmission, not
/// that WFP let it leave — the capture is the authority on what left.
#[cfg(target_os = "windows")]
fn send_marker(
    rt: &tokio::runtime::Runtime,
    socket: &tokio::net::UdpSocket,
    dst: SocketAddr,
    nonce: [u8; 16],
) -> std::io::Result<()> {
    let mut payload = [0u8; 32];
    payload[..16].copy_from_slice(&nonce);
    rt.block_on(socket.send_to(&payload, dst)).map(|_| ())
}

/// Whether the pktmon capture contains `nonce` anywhere in its bytes. The pktmon
/// filter scopes the capture to UDP, the nonce is the leading 16 bytes of our UDP
/// payload, and pktmon logs the full frame verbatim (`--pkt-size 0`), so the
/// nonce appears contiguously in the file iff its packet was captured. A 16-byte
/// random nonce cannot alias unrelated bytes, so a raw scan is sound — and it
/// sidesteps both the pcapng-block quirks that trip strict pure-Rust pcapng
/// parsers on pktmon output and any link-layer (Ethernet II vs raw IP) assumption.
#[cfg(target_os = "windows")]
fn capture_contains_nonce(pcapng: &Path, nonce: [u8; 16]) -> bool {
    let bytes = std::fs::read(pcapng)
        .unwrap_or_else(|e| panic!("pktmon must have produced the capture {}: {e}", pcapng.display()));
    bytes.windows(16).any(|w| w == nonce)
}

/// Generate a fresh random 16-byte nonce per marker so two markers in one
/// capture never collide and a stale prior-run capture can never match.
#[cfg(target_os = "windows")]
fn nonce() -> [u8; 16] {
    use rand::RngExt;
    rand::rng().random::<[u8; 16]>()
}

/// Wire-level no-leak proof across the standing lockdown cover.
///
/// Phase A (cover OFF) is the LOAD-BEARING positive control: start a capture,
/// send a nonce marker, and assert it IS on the wire. Without this an empty
/// Phase-B capture would be a tautology (it could be empty because the capture
/// pipeline / NIC / filter is broken, not because the cover works).
///
/// Phase B (cover ON) sends, from the SAME socket+NIC and IN ORDER, a
/// would-leak marker (nonce A → non-permitted) then a permitted-tail marker
/// (nonce B → the server IP). Both share one socket+NIC egress FIFO, so
/// observing tail B on the wire proves marker A's ALE_AUTH_CONNECT decision
/// already completed — A absent therefore means A was DROPPED, not still
/// pending. That is what makes the proof sleep-free: tail B is the rendezvous,
/// not a timer. Assert B PRESENT (the server permit holds) and A ABSENT (no
/// leak).
///
/// The name carries the `cutover_global_net_state_` substring so it auto-joins
/// the `global-net-state` nextest group (cross-binary serialization of the
/// system-wide WFP state). `serial = TUN` serializes it within this binary.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn cutover_global_net_state_nic_capture_no_udp_leak() {
    use tun_engine::gateway::get_default_gateway_info;
    use tun_engine::helpers::bypass::create_bypass_udp;
    use tun_engine::routing::failclosed::{disengage_lockdown, engage_lockdown, lockdown_state, SystemLuidResolver};

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime for the bound UDP socket");
    let dir = tempfile::tempdir().unwrap();
    let server_ip: IpAddr = SERVER_IP.parse().unwrap();
    let non_permitted: SocketAddr = SocketAddr::new(NON_PERMITTED_IP.parse().unwrap(), DST_PORT);
    let permitted_tail: SocketAddr = SocketAddr::new(server_ip, DST_PORT);

    // The PHYSICAL egress NIC's interface index pins the sentinel socket so every
    // marker egresses the real NIC (not loopback). The capture targets ALL NIC
    // components (`--comp nics`): no fragile friendly-name→component-id mapping
    // (pktmon names a component by adapter description, not the connection name),
    // and an SR-IOV VF datapath can't dodge an all-NIC capture. The nonce-payload
    // match — not the component — is what attributes a captured frame to a marker.
    let gw = get_default_gateway_info().expect("default egress NIC must be discoverable");
    assert!(
        !gw.gateway_ip.is_loopback() && !gw.interface_name.trim().is_empty(),
        "egress NIC must be a real non-loopback interface, got {:?}",
        gw.interface_name
    );
    assert_ne!(
        gw.interface_name.trim().to_ascii_lowercase(),
        "hole-tun",
        "the capture NIC must be the physical egress, never hole-tun"
    );

    // Baseline (PRE-cover) reachability self-check: the egress path is healthy
    // before we touch the cover, so a Phase-B verdict is the cover's doing, not a
    // dead network. Fail loud (a network blip must never be a false pass).
    assert!(
        tcp_reachable(non_permitted) && tcp_reachable(permitted_tail),
        "NETWORK/ENVIRONMENT problem (not the cover): pre-cover baseline egress must reach both hosts"
    );

    // One UDP socket pinned to the physical NIC index — used for every marker so
    // the egress FIFO ordering argument holds across both phases.
    let socket = rt
        .block_on(create_bypass_udp(gw.interface_index, false))
        .expect("bind a UDP socket to the egress NIC index");

    // Phase A: cover OFF — positive control. ==========================================================================
    let nonce_a_ctrl = nonce();
    {
        let cap = dir.path().join("phase_a.etl");
        let pcap = dir.path().join("phase_a.pcapng");
        // Filter to UDP only, capture all NIC components, log the whole packet.
        pktmon(&["filter", "remove"]); // start from a clean filter set
        pktmon(&["filter", "add", "hole-nic-capture", "-t", "UDP"]);
        let _guard = PktmonGuard;
        pktmon(&[
            "start",
            "--capture",
            "--comp",
            "nics",
            "--pkt-size",
            "0",
            "--file-name",
            &cap.to_string_lossy(),
        ]);

        send_marker(&rt, &socket, non_permitted, nonce_a_ctrl).expect("positive-control marker send");

        pktmon(&["stop"]);
        pktmon(&["etl2pcap", &cap.to_string_lossy(), "--out", &pcap.to_string_lossy()]);
        drop(_guard); // remove the Phase-A filter before Phase-B re-adds it

        assert!(
            capture_contains_nonce(&pcap, nonce_a_ctrl),
            "POSITIVE CONTROL FAILED: the capture pipeline/NIC/filter did not record a marker sent with NO cover \
             engaged — an empty Phase-B capture would be meaningless. NIC={:?} (comp nics)",
            gw.interface_name
        );
    }

    // Phase B: cover ON — the no-leak proof. ==========================================================================
    lockdown_state::set_enabled(dir.path(), true).expect("persist lockdown intent");
    let cover = engage_lockdown(
        server_ip,
        "Loopback Pseudo-Interface 1", // always-present LUID source; the block governs the probed egress
        &SystemLuidResolver,
        &[],
        dir.path(),
    )
    .expect("engage the real standing lockdown cover");

    let nonce_leak = nonce(); // → non-permitted: must NOT appear (a leak)
    let nonce_tail = nonce(); // → server IP: MUST appear (permit holds) + rendezvous
    {
        let cap = dir.path().join("phase_b.etl");
        let pcap = dir.path().join("phase_b.pcapng");
        pktmon(&["filter", "remove"]);
        pktmon(&["filter", "add", "hole-nic-capture", "-t", "UDP"]);
        let _guard = PktmonGuard;
        pktmon(&[
            "start",
            "--capture",
            "--comp",
            "nics",
            "--pkt-size",
            "0",
            "--file-name",
            &cap.to_string_lossy(),
        ]);

        // ORDER MATTERS: the would-leak marker first, the permitted tail second,
        // both from the same socket+NIC. ALE classification is synchronous on the
        // send path and pktmon records a single NIC component in egress order, so
        // the FIFO holds at BOTH layers: the tail's presence proves the leak
        // marker's ALE decision already resolved (same egress FIFO), so its
        // absence is a DROP, not a pending send. No sleep, no poll.
        //
        // The leak send is allowed to FAIL: a WFP block at ALE_AUTH_CONNECT can
        // surface as a synchronous `send_to` error (WSAEACCES), which is itself
        // no-leak evidence — but the capture is still the authority, so swallow
        // the result and let the wire decide. The tail send MUST succeed (it is
        // permitted), and is the rendezvous, so it stays strict.
        let _ = send_marker(&rt, &socket, non_permitted, nonce_leak);
        send_marker(&rt, &socket, permitted_tail, nonce_tail).expect("permitted-tail marker send");

        pktmon(&["stop"]);
        pktmon(&["etl2pcap", &cap.to_string_lossy(), "--out", &pcap.to_string_lossy()]);

        let tail_seen = capture_contains_nonce(&pcap, nonce_tail);
        let leak_seen = capture_contains_nonce(&pcap, nonce_leak);

        // Tear the cover down BEFORE the asserts so a failure never leaves the box
        // severed. The capture verdicts are already in hand.
        drop(cover);
        lockdown_state::set_enabled(dir.path(), false).ok();
        disengage_lockdown(dir.path()).ok();

        // Rendezvous: the permitted tail egressed (server permit beats block-all),
        // proving the capture window covered the leak marker's decision too.
        assert!(
            tail_seen,
            "permitted-tail marker (→ server IP {server_ip}) must egress the NIC: the server permit must beat \
             block-all AND the capture must have been live for the leak marker's decision"
        );
        // The invariant: no UDP leaked to the non-permitted destination.
        assert!(
            !leak_seen,
            "UDP LEAK: a datagram to the non-permitted host {non_permitted} egressed the physical NIC while the \
             standing cover was engaged"
        );
    }
}
