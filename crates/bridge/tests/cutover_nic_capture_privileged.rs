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
//! `.config/nextest.toml` (`global_net_state` test-group). COUPLED NAMES: that
//! group's filter matches by the `cutover_global_net_state_` prefix — renaming
//! it WITHOUT updating the filter drops the test from the group (a silent
//! cross-binary race). Change both together.

hole_test_observability::register!();

fn main() {
    skuld::run_all();
}

#[skuld::label]
const TUN: skuld::Label;

/// Cross-binary serialization for tests that mutate GLOBAL OS network state —
/// the `.config/nextest.toml` `global_net_state` test-group's `max-threads = 1`
/// gate. This is a separate compiled binary, not part of `hole-bridge`'s lib
/// target, so it needs its own declaration (bindreams/hole#894).
#[skuld::label]
const GLOBAL_NET_STATE: skuld::Label;

#[cfg(target_os = "windows")]
use std::net::{IpAddr, SocketAddr};

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

// `pktmon`, `PktmonGuard`, `send_marker`, `capture_contains_nonce`, and
// `nonce` live in `tun_engine::test_utils::pktmon` — promoted there so this
// crate and `tun-engine`'s own `dns_confine` privileged tests share one copy
// instead of drifting (see that module's doc and this crate's `Cargo.toml`
// dev-dependency comment on `tun-engine`).
#[cfg(target_os = "windows")]
use tun_engine::test_utils::{capture_contains_nonce, nonce, pktmon, send_marker, PktmonGuard};

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
/// the `global_net_state` nextest group (cross-binary serialization of the
/// system-wide WFP state). `serial = TUN` serializes it within this binary.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
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
    lockdown_state::set_enabled(dir.path(), true, None).expect("persist lockdown intent");
    let cover = engage_lockdown(
        server_ip,
        "Loopback Pseudo-Interface 1", // always-present LUID source; the block governs the probed egress
        &SystemLuidResolver,
        &[],
        dir.path(),
        None,
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
        lockdown_state::set_enabled(dir.path(), false, None).ok();
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
