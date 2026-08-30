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
//! **Assertions are on the error the probe's `send`/`connect` call returns,
//! never on elapsed time.** A WFP block fails the operation synchronously; it
//! does not stall it. [`crate::test_utils::classify`] turns the raw
//! `io::Result` into a [`crate::test_utils::ProbeFate`] so a probe that never
//! reached the network stack at all (a harness fault) can never be
//! misreported as a firewall verdict.
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

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use tun::AbstractDeviceExt;

use super::engage;
use crate::test_utils::{classify, OwnedRoute, ProbeFate};
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

fn send_udp(dest: SocketAddr) -> std::io::Result<usize> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.send_to(b"hole-dns-confine-probe", dest)
}

/// Control + positive case: with the confinement engaged naming the device
/// carrying the only route to `PROBE_IP`, a UDP send to `PROBE_IP:53` must be
/// permitted.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn dns_confine_global_net_state_permits_dns_on_the_named_tun() {
    let name = "dns-confine-test-tun-a";
    let dev = open_device(name, "10.255.250.1", "255.255.255.0");
    let luid = dev.tun_luid();
    let route = OwnedRoute::add(PROBE_NET, name, None);
    route.assert_wins_for(IpAddr::V4(PROBE_IP));

    let confinement = engage(luid, server_ip(), &[]).expect("engage real DNS confinement");
    let result = send_udp(SocketAddr::from((PROBE_IP, 53)));
    drop(confinement);

    assert_eq!(
        classify(&result),
        ProbeFate::Delivered,
        "DNS to the address routed through the named tun must be permitted: {result:?}"
    );
}

/// Negative case: a UDP send to a port-53 destination reached via the
/// physical adapter (never the tunnel) must be blocked while the confinement
/// is engaged.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn dns_confine_global_net_state_blocks_dns_off_the_tun() {
    let dev = open_device("dns-confine-test-tun-b", "10.255.249.1", "255.255.255.0");
    let luid = dev.tun_luid();

    let confinement = engage(luid, server_ip(), &[]).expect("engage real DNS confinement");
    let result = send_udp(OFF_TUNNEL_DNS.parse().expect("literal"));
    drop(confinement);

    let fate = classify(&result);
    assert!(
        matches!(fate, ProbeFate::Rejected(_)),
        "off-tunnel DNS must be blocked while the confinement is engaged: {result:?} (fate={fate:?})"
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
/// keyed on the named LUID fails this one.
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
    let result = send_udp(SocketAddr::from((PROBE_IP, 53)));
    drop(confinement);
    drop(dev_b);

    let fate = classify(&result);
    assert!(
        matches!(fate, ProbeFate::Rejected(_)),
        "a confinement naming device A must NOT permit DNS actually routed via device B — \
         the permit is not sensitive to the interface it names: {result:?} (fate={fate:?})"
    );
}

/// Rule #0, asserted rather than assumed: dropping the guard must fully
/// release the confinement — a dynamic session's filters vanish with the
/// engine handle, with no by-key sweep and nothing left to strand a user.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn dns_confine_global_net_state_filters_die_with_the_session() {
    let dev = open_device("dns-confine-test-tun-f", "10.255.245.1", "255.255.255.0");
    let luid = dev.tun_luid();

    let confinement = engage(luid, server_ip(), &[]).expect("engage real DNS confinement");
    drop(confinement);

    let result = send_udp(OFF_TUNNEL_DNS.parse().expect("literal"));
    assert_eq!(
        classify(&result),
        ProbeFate::Delivered,
        "dropping the confinement guard must restore off-tunnel DNS: {result:?}"
    );
}

/// R0-3's live proof: the Shadowsocks server permit matches on port 53 too —
/// a server configured on port 53 (a standard censorship-evasion setup) must
/// not be locked out of its own tunnel by the very confinement meant to
/// protect it.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn dns_confine_global_net_state_permits_the_server_on_port_53() {
    let dev = open_device("dns-confine-test-tun-g", "10.255.244.1", "255.255.255.0");
    let luid = dev.tun_luid();

    let confinement = engage(luid, server_ip(), &[]).expect("engage real DNS confinement");
    let result = send_udp(SocketAddr::from((server_ip(), 53)));
    drop(confinement);

    assert_eq!(
        classify(&result),
        ProbeFate::Delivered,
        "the server IP must stay reachable on port 53 even though it is not the tunnel LUID: {result:?}"
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
