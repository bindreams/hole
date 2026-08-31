//! Privileged-lane live proof for the DNS-egress confinement (#846).
//!
//! The claim under test is a kernel behaviour that cannot be proven from
//! sources: that `IP_LOCAL_INTERFACE` at `ALE_AUTH_CONNECT` really does
//! discriminate a DNS query routed into a named `hole-tun`-shaped adapter
//! from one routed out any other interface, and that a **dynamic** FWPM
//! session's filters really do vanish the instant its engine handle closes.
//! Same argument as `routing::failclosed::live_tun_permit_privileged_tests`
//! (#874) and `lockdown_privileged_tests` (#527) — this module follows their
//! shape.
//!
//! **Assertions are on the wire, never on elapsed time.** A WFP block fails
//! synchronously; it does not stall. But for the UDP probes below, "the wire"
//! means an actual `pktmon` capture
//! ([`crate::test_utils::pktmon`]), not the `send_to` call's own return
//! value: a bound, unconnected UDP socket's `send_to` returns `Ok` whether
//! the datagram left or was dropped at `ALE_AUTH_CONNECT`, so `Ok(22)` is
//! exactly what a successfully blocked send looks like too. Only the one TCP
//! probe here (`leaves_other_ports_alone`) can trust its own `connect`
//! result: a completed three-way handshake is proof no firewall drop can
//! manufacture. Every UDP test instead sends a per-marker nonce and asks the
//! capture whether it egressed, using a rendezvous tail on the same socket
//! where the claim under test is an absence (see each test's own doc) — no
//! sleep, no poll.
//!
//! **`serial = TUN` reuses `crate::TUN`** — the crate-root serial token
//! declared once for the whole binary — rather than minting a second
//! `#[skuld::label] const TUN`, which would race the cover tests that label
//! excludes. Plus the `global_net_state` nextest test-group
//! (`.config/nextest.toml`) for cross-binary serialization. COUPLED NAMES:
//! every test below carries the literal substring
//! `dns_confine_global_net_state_`, which that group's filter matches by
//! substring — renaming one without updating `.config/nextest.toml` silently
//! drops it from the group. Each also carries the `GLOBAL_NET_STATE` skuld
//! label so `cargo xtask verify-global-net-state-labels` can bind the
//! filter's membership to the label's live membership.
//!
//! No `EscapeGuard` / recovery-record machinery here, unlike the fail-closed
//! cover's privileged tests: the confinement persists NO state file by
//! design (F6) — its entire disengage is `DnsConfinement`'s `Drop`, which
//! this module relies on directly. A killed test leaves nothing on the host
//! but a leaked wintun adapter (cleared the same way any other test's is —
//! `scripts/network-reset.py`), never a stranded firewall block.
//!
//! **What a real run does to the machine**: opens several real wintun
//! adapters and engages a real, process-scoped WFP confinement more than
//! once. Not `#[ignore]`d; runs under the elevated `tun` lane
//! (`SKULD_LABELS="tun"`) and fails loud, un-elevated, under the default
//! unprivileged pass.
//!
//! `dns_confine_global_net_state_adapter_reports_back_its_requested_guid` at
//! the bottom of this file is the create→read-back ship gate for the
//! adapter-GUID identity in `device::identity` — it tests THAT mechanism,
//! not the confinement, and lives here only because the
//! `dns_confine_global_net_state_` name prefix is what the nextest group
//! matches on.

#![cfg(target_os = "windows")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

use tun::AbstractDeviceExt;

use super::engage;
use crate::test_utils::{capture_contains_nonce, nonce, pktmon, send_marker, OwnedRoute, PktmonGuard};
use crate::{GLOBAL_NET_STATE, TUN};

/// TEST-NET-2 (RFC 5737) — never routable on the real internet, so its only
/// route is the one a test installs itself.
const PROBE_NET: &str = "198.51.100.0/24";
const PROBE_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 53);
/// A real, routable, port-53-listening host that this test never owns — a
/// destination that "routes out the physical adapter", not the tunnel.
/// Google Public DNS; distinct from `SERVER_IP` so the server permit and the
/// interface permit are never accidentally exercised by the same address.
const OFF_TUNNEL_DNS: &str = "8.8.8.8:53";
const OFF_TUNNEL_OTHER_PORT: &str = "8.8.8.8:443";
/// Engaged as the confinement's permitted Shadowsocks server IP. Cloudflare
/// anycast — same reliability rationale as
/// `lockdown_privileged_tests::PERMITTED`.
const SERVER_IP: &str = "1.1.1.1";

fn open_device(name: &str, addr: &str, netmask: &str) -> tun::AsyncDevice {
    crate::device::wintun::ensure_loaded().expect("HARNESS: ensure_loaded (wintun.dll)");
    let mut cfg = tun::Configuration::default();
    cfg.tun_name(name).mtu(1500).up().address(addr).netmask(netmask);
    tun::create_as_async(&cfg).unwrap_or_else(|e| panic!("HARNESS: create_as_async({name}) failed: {e}"))
}

fn server_ip() -> IpAddr {
    SERVER_IP.parse().expect("literal")
}

/// A tokio runtime plus a bound, unconnected UDP socket — the pair
/// [`send_marker`] needs. Not bound to any interface: which one a marker
/// actually egresses is left to the OS route lookup for its destination,
/// which is exactly the thing each test below is probing.
fn probe_socket() -> (tokio::runtime::Runtime, tokio::net::UdpSocket) {
    let rt = tokio::runtime::Runtime::new().expect("HARNESS: tokio runtime for the probe socket");
    let socket = rt
        .block_on(tokio::net::UdpSocket::bind("0.0.0.0:0"))
        .expect("HARNESS: bind probe socket");
    (rt, socket)
}

/// Run `body` inside a fresh pktmon UDP capture window scoped to `label`
/// under `dir`, returning the resulting pcapng path. Mirrors the proven
/// phase structure in `cutover_nic_capture_privileged.rs`'s no-leak proof:
/// filter to UDP only, capture every NIC component — the real physical
/// egress AND any live wintun adapter, since pktmon's component discovery is
/// not limited to physical hardware — at full packet size, `PktmonGuard` for
/// teardown, then convert the trace to pcapng once the window closes.
fn capture_udp_window(dir: &Path, label: &str, body: impl FnOnce()) -> std::path::PathBuf {
    let cap = dir.join(format!("{label}.etl"));
    let pcap = dir.join(format!("{label}.pcapng"));
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
    body();
    pktmon(&["stop"]);
    pktmon(&["etl2pcap", &cap.to_string_lossy(), "--out", &pcap.to_string_lossy()]);
    pcap
}

/// Control + positive case: with the confinement engaged naming the device
/// carrying the only route to `PROBE_IP`, a UDP send to `PROBE_IP:53` must
/// actually egress — proven at the wire (module doc): `send_to`'s `Ok` alone
/// cannot attest that on an unconnected UDP socket.
///
/// Not a separate harness-control gate for the tests below: a prior design
/// made this test that gate, but as its own nextest test it gated nothing —
/// alphabetical ordering ran `blocks_dns_off_the_tun` first, it failed, and
/// fail-fast killed this one before it ever ran. Every UDP test below proves
/// its own capture pipeline live within its own window instead (its
/// rendezvous tail, or — for a lone must-egress marker like this one — the
/// marker itself: a broken pipeline fails this test loud, it does not pass
/// it vacuously).
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn dns_confine_global_net_state_permits_dns_on_the_named_tun() {
    let name = "dns-confine-test-tun-a";
    let dev = open_device(name, "10.255.250.1", "255.255.255.0");
    let luid = dev.tun_luid();
    let route = OwnedRoute::add(PROBE_NET, name, None);
    route.assert_wins_for(IpAddr::V4(PROBE_IP));

    let confinement = engage(luid, server_ip(), &[]).expect("engage real DNS confinement");

    let (rt, socket) = probe_socket();
    let dir = tempfile::tempdir().expect("HARNESS: tempdir for the pktmon capture");
    let marker = nonce();
    let pcap = capture_udp_window(dir.path(), "permits-named-tun", || {
        send_marker(&rt, &socket, SocketAddr::from((PROBE_IP, 53)), marker)
            .expect("DNS to the address routed through the named tun must be accepted for send");
    });

    drop(confinement);

    assert!(
        capture_contains_nonce(&pcap, marker),
        "DNS to the address routed through the named tun must egress: marker not found in the capture"
    );
}

/// Negative case: a UDP send to a port-53 destination reached via the
/// physical adapter (never the tunnel) must be blocked while the confinement
/// is engaged — proven at the wire (module doc). The rendezvous tail, sent to
/// the server IP on the same socket, is both the ordering proof (its
/// presence means the leak marker's `ALE_AUTH_CONNECT` decision already
/// resolved, so absence is a drop, not a still-pending send) and this test's
/// own non-vacuous evidence that the server permit holds.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn dns_confine_global_net_state_blocks_dns_off_the_tun() {
    let dev = open_device("dns-confine-test-tun-b", "10.255.249.1", "255.255.255.0");
    let luid = dev.tun_luid();

    let confinement = engage(luid, server_ip(), &[]).expect("engage real DNS confinement");

    let (rt, socket) = probe_socket();
    let dir = tempfile::tempdir().expect("HARNESS: tempdir for the pktmon capture");
    let leak = nonce();
    let tail = nonce();
    let pcap = capture_udp_window(dir.path(), "blocks-off-tun", || {
        // The leak send is allowed to fail: a WFP block at ALE_AUTH_CONNECT
        // can surface as a synchronous `send_to` error, itself no-leak
        // evidence — but the capture is the authority, so swallow the result
        // and let the wire decide. The tail send must succeed (it is
        // permitted) and is the rendezvous, so it stays strict.
        let _ = send_marker(&rt, &socket, OFF_TUNNEL_DNS.parse().expect("literal"), leak);
        send_marker(&rt, &socket, SocketAddr::from((server_ip(), 53)), tail).expect("permitted-tail marker send");
    });

    drop(confinement);

    assert!(
        capture_contains_nonce(&pcap, tail),
        "permitted-tail marker (→ server IP {SERVER_IP}) must egress: the server permit must hold AND the \
         capture must have been live for the leak marker's decision"
    );
    assert!(
        !capture_contains_nonce(&pcap, leak),
        "DNS LEAK: a datagram to the off-tunnel host {OFF_TUNNEL_DNS} egressed while the confinement was engaged"
    );
}

/// The confinement must not be a general egress block: the SAME off-tunnel
/// host on a non-DNS port must stay reachable.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn dns_confine_global_net_state_leaves_other_ports_alone() {
    let dev = open_device("dns-confine-test-tun-c", "10.255.248.1", "255.255.255.0");
    let luid = dev.tun_luid();

    let confinement = engage(luid, server_ip(), &[]).expect("engage real DNS confinement");
    let result = TcpStream::connect_timeout(&OFF_TUNNEL_OTHER_PORT.parse().expect("literal"), Duration::from_secs(5));
    drop(confinement);

    assert!(
        result.is_ok(),
        "a non-DNS port on an off-tunnel host must stay unaffected by the confinement: {result:?}"
    );
}

/// Anti-vacuity: engage naming device A (a real, live, uninvolved TUN), then
/// send DNS that actually routes via device B. A confinement that (wrongly)
/// permitted any live TUN-shaped interface would pass
/// `permits_dns_on_the_named_tun` AND this test; only a permit genuinely
/// keyed on the named LUID fails this one. Proven at the wire, same
/// leak/tail shape as `blocks_dns_off_the_tun`: the leak marker routes via
/// device B and must be absent, the tail (→ the server IP, permitted
/// regardless of interface) must be present.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn dns_confine_global_net_state_is_sensitive_to_the_interface_it_names() {
    let name_a = "dns-confine-test-tun-d";
    let name_b = "dns-confine-test-tun-e";
    let dev_a = open_device(name_a, "10.255.247.1", "255.255.255.0");
    let dev_b = open_device(name_b, "10.255.246.1", "255.255.255.0");
    let luid_a = dev_a.tun_luid();

    // The route carries the probe via device B, not device A.
    let route = OwnedRoute::add(PROBE_NET, name_b, None);
    route.assert_wins_for(IpAddr::V4(PROBE_IP));

    // Engage naming ONLY device A.
    let confinement = engage(luid_a, server_ip(), &[]).expect("engage real DNS confinement naming device A");

    let (rt, socket) = probe_socket();
    let dir = tempfile::tempdir().expect("HARNESS: tempdir for the pktmon capture");
    let leak = nonce();
    let tail = nonce();
    let pcap = capture_udp_window(dir.path(), "sensitive-to-interface", || {
        // The leak routes via device B, which the confinement does not name
        // — allowed to fail synchronously, same as blocks_dns_off_the_tun.
        let _ = send_marker(&rt, &socket, SocketAddr::from((PROBE_IP, 53)), leak);
        send_marker(&rt, &socket, SocketAddr::from((server_ip(), 53)), tail).expect("permitted-tail marker send");
    });

    drop(confinement);
    drop(dev_b);

    assert!(
        capture_contains_nonce(&pcap, tail),
        "permitted-tail marker (→ server IP {SERVER_IP}) must egress: the capture must have been live for the \
         leak marker's decision"
    );
    assert!(
        !capture_contains_nonce(&pcap, leak),
        "a confinement naming device A must NOT permit DNS actually routed via device B — the permit is not \
         sensitive to the interface it names: marker egressed"
    );
}

/// Rule #0, asserted rather than assumed: dropping the guard must fully
/// release the confinement — a dynamic session's filters vanish with the
/// engine handle, with no by-key sweep and nothing left to strand a user.
/// Proven at the wire, after the guard is dropped: `send_to`'s `Ok` alone
/// cannot attest that DNS is unblocked again.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn dns_confine_global_net_state_filters_die_with_the_session() {
    let dev = open_device("dns-confine-test-tun-f", "10.255.245.1", "255.255.255.0");
    let luid = dev.tun_luid();

    let confinement = engage(luid, server_ip(), &[]).expect("engage real DNS confinement");
    drop(confinement);

    let (rt, socket) = probe_socket();
    let dir = tempfile::tempdir().expect("HARNESS: tempdir for the pktmon capture");
    let marker = nonce();
    let pcap = capture_udp_window(dir.path(), "filters-die-with-session", || {
        send_marker(&rt, &socket, OFF_TUNNEL_DNS.parse().expect("literal"), marker)
            .expect("dropping the confinement guard must restore off-tunnel DNS send");
    });

    assert!(
        capture_contains_nonce(&pcap, marker),
        "dropping the confinement guard must restore off-tunnel DNS: marker not found in the capture"
    );
}

/// R0-3's live proof: the Shadowsocks server permit matches on port 53 too —
/// a server configured on port 53 (a standard censorship-evasion setup) must
/// not be locked out of its own tunnel by the very confinement meant to
/// protect it. Proven at the wire.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn dns_confine_global_net_state_permits_the_server_on_port_53() {
    let dev = open_device("dns-confine-test-tun-g", "10.255.244.1", "255.255.255.0");
    let luid = dev.tun_luid();

    let confinement = engage(luid, server_ip(), &[]).expect("engage real DNS confinement");

    let (rt, socket) = probe_socket();
    let dir = tempfile::tempdir().expect("HARNESS: tempdir for the pktmon capture");
    let marker = nonce();
    let pcap = capture_udp_window(dir.path(), "permits-server-53", || {
        send_marker(&rt, &socket, SocketAddr::from((server_ip(), 53)), marker)
            .expect("the server IP must be accepted for send on port 53");
    });

    drop(confinement);

    assert!(
        capture_contains_nonce(&pcap, marker),
        "the server IP must stay reachable on port 53 even though it is not the tunnel LUID: marker not found \
         in the capture"
    );
}

/// SHIP GATE (Task 6, #846 plan). The vendor header calls the
/// `RequestedGUID` API "completely undocumented, and so there could be
/// minor interesting complications with its usage"
/// (`wintun-bindings-0.7.39/wintun/include/wintun.h:50-53`), and
/// `wintun-bindings` ships a live GUID-mismatch handler — so this is not a
/// formality. Creates a real adapter through the PRODUCTION path
/// (`Device::build`, which requests `HOLE_ADAPTER_GUID`), drops it, then
/// re-opens by NAME (not by handle) and reads the GUID back via
/// `probe_incumbent` — the exact ADOPT-path read `Device::build` itself
/// performs on its next start. If this fails, the ownership gate is
/// worthless as designed: **stop and raise it, do not weaken this test.**
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn dns_confine_global_net_state_adapter_reports_back_its_requested_guid() {
    let name = "dns-confine-test-tun-guid";
    let device = crate::Device::build(|c| {
        c.tun_name = name.into();
        c.mtu = 1400;
        c.ipv4 = Some("10.255.243.1/24".parse().expect("literal"));
    })
    .unwrap_or_else(|e| panic!("HARNESS: Device::build({name}) failed: {e}"));
    drop(device);

    let incumbent = crate::device::identity::probe_incumbent(name, crate::device::identity::HOLE_ADAPTER_GUID)
        .unwrap_or_else(|e| panic!("HARNESS: probe_incumbent({name}) failed: {e}"));

    assert_eq!(
        incumbent,
        crate::device::identity::Incumbent::Ours,
        "SHIP GATE: a re-opened adapter must report back the GUID Hole requested at create time \
         (RequestedGUID is vendor-undocumented — do not weaken this assertion, raise it instead)"
    );
}
