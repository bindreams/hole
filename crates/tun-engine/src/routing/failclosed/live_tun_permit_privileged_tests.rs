//! Live-interface falsification for the standing lockdown cover's
//! tunnel-permit rule.
//!
//! `lockdown_privileged_tests.rs` proves the cover is selective (permit beats
//! block-all, a non-permitted host is dropped) but engages against an
//! interface picked only to exercise the resolve path — macOS uses a name
//! that matches nothing at all, Windows a live-but-irrelevant loopback alias.
//! Neither proves the permit is sensitive to the interface it names. A rule
//! naming the wrong live interface — the realistic failure once the macOS TUN
//! name becomes kernel-assigned, or with a stale/duplicate Windows adapter —
//! produces a kill switch that blocks everything while the UI reports it
//! armed and the real tunnel Running.
//!
//! This module opens two real TUN devices and drives one probe route through
//! the first. Four phases per platform:
//!
//! 1. **Control** (no cover): the probe must surface on the device — proves
//!    the harness itself, not the cover.
//! 2. **Positive**: engage the real cover naming device 1 (the one carrying
//!    the route). The probe (UDP and a TCP SYN) must be PERMITTED, a
//!    non-permitted host still blocked, and the server IP still reachable.
//! 3. **Mutation**: re-engage naming device 2 — a second interface that is
//!    genuinely live, just not the one carrying the traffic. The SAME probes
//!    must now be DROPPED. This is the anti-vacuity mechanism: a permit that
//!    (wrongly) matched any live TUN-shaped interface would pass phase 2 and
//!    ALSO pass phase 3, proving nothing. Only a permit that is actually
//!    keyed on the named interface fails phase 3's mutation.
//! 4. **Restore**: with nothing engaged, the probe surfaces again and the
//!    non-permitted host is reachable — the box was left open.
//!
//! Every phase's negative rests on the FIFO ordering of one device's frame
//! queue: a probe sent while covered has its firewall fate decided
//! synchronously on the send path, before the cover is dropped, so a "tail"
//! probe sent AFTER the drop — and confirmed to arrive — proves the earlier
//! probes' fate was already sealed. No sleeps, no poll-until-true.
//!
//! `serial = TUN` (the crate-root label — a second `#[skuld::label] const
//! TUN` in this binary would mint a DIFFERENT serial token and race the very
//! cover tests this must exclude) plus the
//! `global_net_state` nextest test-group serialize this across the whole
//! elevated lane; see `.config/nextest.toml`.
//!
//! ## The mid-stream proof (macOS)
//!
//! `macos_live_tun_permit_cover_carries_a_mid_stream_segment_after_a_state_purge`
//! reuses this module's devices, route and frame reader for a different
//! question: whether a cover permit is stateless enough to carry a segment of
//! an ALREADY-ESTABLISHED flow after pf's state table is purged. It completes
//! a TCP handshake by hand — reading the kernel's SYN off the device and
//! writing a crafted SYN-ACK back — so the flow exists with no peer and no
//! internet. See that test's own doc for its three legs.
//!
//! COUPLED NAMES: every test name below contains the literal substring
//! `live_tun_permit_`, which `.config/nextest.toml`'s `global_net_state`
//! filter matches. Renaming one without updating that filter silently
//! drops it from the group.
//!
//! ## One state directory, written before the first engage
//!
//! [`EscapeGuard`] owns a single `TempDir` for the whole test, reused by all
//! three engages, and writes the recovery record from it before anything is
//! armed. A fresh directory per engage would let a silently-failed teardown
//! (macOS `engage_pf_action`'s `FreshEnable` snapshots whatever is LIVE when
//! it sees no persisted state) capture a PRIOR cover's block-everything
//! ruleset as "the host" — and every later restore, including the escape
//! guard itself, would then reload block-everything as the host and erase the
//! evidence. Do not reintroduce a directory-per-phase habit here.
//!
//! ## What a real run does to the machine
//!
//! **This engages a real, system-wide block-all firewall cover on the host
//! running it, for a few seconds, more than once.** It is not `#[ignore]`d
//! and a plain `cargo nextest run` on an unelevated box fails loud (the
//! privilege check), but on an elevated box it WILL arm the kill switch. If
//! interrupted, the recovery record written before the first engage names the
//! platform command to clear it by hand.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

#[cfg(target_os = "macos")]
use tun::AbstractDevice;

use super::{engage_lockdown, SystemLuidResolver};
use crate::test_utils::{classify, classify_send, EscapeGuard, OwnedRoute, RecordSpec};
use crate::{GLOBAL_NET_STATE, TUN};

// Constants ===========================================================================================================

/// TEST-NET-2 (RFC 5737) — never routable on the real internet, so its only
/// route is the one this test installs.
const PROBE_NET: &str = "198.51.100.0/24";
/// UDP probe destination inside [`PROBE_NET`].
const PROBE_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 53);
/// TCP probe destination inside [`PROBE_NET`] — a different host than
/// [`PROBE_IP`] so the UDP and TCP probes never collide on the wire.
const PROBE_TCP_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
/// Destination ports for the phase-2 (positive) and phase-3 (mutation) TCP
/// SYN probes. Distinct per phase so a frame queued in one phase can never
/// be mistaken for another's.
const TCP_PROBE_PORT_PHASE2: u16 = 54321;
const TCP_PROBE_PORT_PHASE3: u16 = 54322;
/// Engaged as the cover's permitted server IP.
const SERVER_IP: &str = "1.1.1.1";
/// A routable host the cover must block in every engaged phase.
const NON_PERMITTED: &str = "8.8.8.8:443";
/// 16-byte marker prefixing every UDP probe payload, followed by a 4-byte
/// big-endian nonce. Lets [`Frame::udp_nonce`] tell a probe frame apart from
/// ordinary link noise (multicast, NDP, ...) without any state beyond the
/// frame itself.
const PROBE_MARKER: &[u8; 16] = b"hole-tun-permit!";
/// Device 1's own address. A const, not a literal at the opener: the
/// mid-stream test binds its socket to this address so the frames it reads
/// back off device 1 have a source it chose rather than one the kernel picked,
/// and a drift between the two would surface as "no SYN ever arrived".
const DEV1_ADDR: &str = "10.255.253.1";
#[cfg(target_os = "macos")]
const DEV1_PEER: &str = "10.255.253.2";

// Mid-stream probe (the `no state` proof) -----------------------------------------------------------------------------

/// Mid-stream TCP probe destination inside [`PROBE_NET`], distinct from both
/// probe hosts above. Engaged as the transient cover's PERMITTED server IP, so
/// the rule under test is the cover's own server permit.
#[cfg(target_os = "macos")]
const MID_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 9);
/// The mid-stream probe's destination port.
#[cfg(target_os = "macos")]
const MID_PORT: u16 = 54330;
/// One local port per leg, so a socket lingering from an earlier leg can never
/// collide with the next one's 4-tuple.
#[cfg(target_os = "macos")]
const MID_LOCAL_PORT_UNCOVERED: u16 = 54331;
#[cfg(target_os = "macos")]
const MID_LOCAL_PORT_PREFIX: u16 = 54332;
#[cfg(target_os = "macos")]
const MID_LOCAL_PORT_PRODUCTION: u16 = 54333;
/// Marker prefixing every mid-stream segment's payload, followed by a 4-byte
/// big-endian nonce — [`PROBE_MARKER`]'s TCP counterpart. Distinct bytes, so a
/// UDP probe can never read as a mid-stream segment or the reverse.
const MID_MARKER: &[u8; 16] = b"hole-midstream!!";
/// The initial sequence number of the synthetic peer whose SYN-ACK completes
/// the handshake. Arbitrary — nothing else ever picks it.
#[cfg(target_os = "macos")]
const MID_PEER_ISN: u32 = 0x0001_0000;
/// UDP nonce of the tail probe that closes the pre-fix leg's FIFO argument.
#[cfg(target_os = "macos")]
const MID_TAIL_NONCE: u32 = 40;
/// Failure bound for a frame the KERNEL may never produce — a pf drop under
/// `block-policy drop` is silent, and a discarded SYN-ACK leaves a connect
/// pending forever. The sanctioned exception (an external event that might
/// never happen, with the bound surfaced to a human), never a sleep
/// sequencing this test's own steps. Same 5s every phase above uses.
#[cfg(target_os = "macos")]
const MID_BUDGET: Duration = Duration::from_secs(5);

/// The escape record the mid-stream test writes before its first engage. Its
/// own, so a stranded cover's recovery note names the test that armed it.
#[cfg(target_os = "macos")]
const MID_RECORD: RecordSpec = RecordSpec {
    file_name: "hole-live-tun-permit-midstream-RECOVERY.txt",
    what: "hole live-tun-permit mid-stream test",
};

/// The escape record this test writes before its first engage.
const RECORD: RecordSpec = RecordSpec {
    file_name: "hole-live-tun-permit-RECOVERY.txt",
    what: "hole live-tun-permit test",
};

fn server_ip() -> IpAddr {
    SERVER_IP.parse().expect("literal")
}

// Frame parsing =======================================================================================================

/// One parsed IPv4 UDP or TCP frame — the shape both probe kinds need: a
/// nonce-keyed UDP match and a port-keyed TCP SYN match.
struct Frame {
    proto: u8,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    /// TCP flag bits (header byte 13); 0 for UDP.
    flags: u8,
    /// TCP sequence number; 0 for UDP.
    seq: u32,
    /// Layer-4 payload: the UDP datagram's, or the TCP segment's data past
    /// its data offset. TCP carries it so a MID-STREAM segment can be told
    /// from the handshake packets sharing its 4-tuple — the handshake has no
    /// data, [`MID_MARKER`] identifies the one that does.
    payload: Vec<u8>,
}

impl Frame {
    /// The nonce carried by a UDP probe frame, or `None` if this frame's
    /// payload doesn't start with [`PROBE_MARKER`] (ordinary traffic, or a
    /// UDP frame that isn't one of ours).
    fn udp_nonce(&self) -> Option<u32> {
        if self.proto != 17 {
            return None;
        }
        let marker = self.payload.get(0..16)?;
        if marker != PROBE_MARKER.as_slice() {
            return None;
        }
        let n = self.payload.get(16..20)?;
        Some(u32::from_be_bytes([n[0], n[1], n[2], n[3]]))
    }

    /// The nonce carried by a mid-stream TCP probe segment, keyed on
    /// [`MID_MARKER`] exactly as [`Frame::udp_nonce`] is on [`PROBE_MARKER`].
    /// A distinct marker and a distinct rendering token (`tcpmark=`) from the
    /// UDP one, so a search over a `seen` log can never confuse the two.
    fn tcp_mark(&self) -> Option<u32> {
        if self.proto != 6 {
            return None;
        }
        let marker = self.payload.get(0..16)?;
        if marker != MID_MARKER.as_slice() {
            return None;
        }
        let n = self.payload.get(16..20)?;
        Some(u32::from_be_bytes([n[0], n[1], n[2], n[3]]))
    }

    /// A bare SYN — SYN set, ACK clear — which is what identifies the
    /// kernel's own connection attempt among the frames on the device.
    #[cfg(target_os = "macos")]
    fn is_syn(&self) -> bool {
        const SYN: u8 = 0x02;
        const ACK: u8 = 0x10;
        self.proto == 6 && self.flags & SYN != 0 && self.flags & ACK == 0
    }

    /// Human-readable rendering pushed into a `capture` call's `seen` log —
    /// must carry enough information (in particular the decoded nonce) that
    /// a later substring search over the log can answer "was probe N here",
    /// since a second `capture` call is never issued to re-check (see the
    /// module doc on ordering).
    fn render(&self) -> String {
        match self.proto {
            17 => match self.udp_nonce() {
                Some(n) => format!(
                    "UDP {}:{} -> {}:{} nonce={n}",
                    self.src, self.sport, self.dst, self.dport
                ),
                None => format!(
                    "UDP {}:{} -> {}:{} (non-probe, {}B payload)",
                    self.src,
                    self.sport,
                    self.dst,
                    self.dport,
                    self.payload.len()
                ),
            },
            6 => {
                let tail = match self.tcp_mark() {
                    Some(n) => format!(" tcpmark={n}"),
                    None => format!(" ({}B payload)", self.payload.len()),
                };
                format!(
                    "TCP {}:{} -> {}:{} flags=0x{:02x} seq={}{tail}",
                    self.src, self.sport, self.dst, self.dport, self.flags, self.seq
                )
            }
            other => format!("proto={other} {} -> {}", self.src, self.dst),
        }
    }
}

fn u16_be(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

/// Parse one IPv4 UDP/TCP frame starting at `offset`. Every access is
/// `.get()`-checked — this runs inside a covered window in phases 2 and 3,
/// where a panic would skip the release guard entirely (Rule #0). Anything
/// that isn't a well-formed IPv4 UDP or TCP header is `None`, never a panic.
fn parse_ipv4_at(buf: &[u8], offset: usize) -> Option<Frame> {
    let b = buf.get(offset..)?;
    let first = *b.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let ihl = ((first & 0x0f) as usize) * 4;
    if ihl < 20 {
        return None;
    }
    let header = b.get(..ihl)?;
    let proto = *header.get(9)?;
    let src = Ipv4Addr::new(*header.get(12)?, *header.get(13)?, *header.get(14)?, *header.get(15)?);
    let dst = Ipv4Addr::new(*header.get(16)?, *header.get(17)?, *header.get(18)?, *header.get(19)?);
    let l4 = b.get(ihl..)?;
    match proto {
        17 => {
            let sport = u16_be(l4, 0)?;
            let dport = u16_be(l4, 2)?;
            let payload = l4.get(8..).unwrap_or(&[]).to_vec();
            Some(Frame {
                proto,
                src,
                dst,
                sport,
                dport,
                flags: 0,
                seq: 0,
                payload,
            })
        }
        6 => {
            let sport = u16_be(l4, 0)?;
            let dport = u16_be(l4, 2)?;
            let seq = u32::from_be_bytes([*l4.get(4)?, *l4.get(5)?, *l4.get(6)?, *l4.get(7)?]);
            let data_offset = ((*l4.get(12)? >> 4) as usize) * 4;
            if data_offset < 20 {
                return None;
            }
            let flags = *l4.get(13)?;
            let payload = l4.get(data_offset..).unwrap_or(&[]).to_vec();
            Some(Frame {
                proto,
                src,
                dst,
                sport,
                dport,
                flags,
                seq,
                payload,
            })
        }
        _ => None,
    }
}

/// Tolerate an optional leading 4-byte packet-information prefix: with the
/// `tun` crate's default macOS config (`packet_information = true`) the
/// reader already strips it, so a frame normally starts at the IP header —
/// but that is a property of configuration, not of the fd, so a mistake
/// there must surface as a parse failure at offset 0 that succeeds at offset
/// 4, not as "no packet arrived". Wintun frames are raw IP with no prefix, so
/// offset 0 is always correct on Windows.
fn parse_frame(buf: &[u8]) -> Option<Frame> {
    parse_ipv4_at(buf, 0).or_else(|| parse_ipv4_at(buf, 4))
}

fn udp_matches(nonce: u32) -> impl Fn(&Frame) -> bool {
    move |f: &Frame| f.udp_nonce() == Some(nonce)
}

fn tcp_syn_matches(dst: Ipv4Addr, port: u16) -> impl Fn(&Frame) -> bool {
    move |f: &Frame| f.proto == 6 && f.dst == dst && f.dport == port
}

fn seen_has_udp_nonce(seen: &[String], nonce: u32) -> bool {
    let needle = format!("nonce={nonce}");
    seen.iter().any(|s| s.contains(&needle))
}

#[cfg(target_os = "macos")]
fn tcp_mark_matches(nonce: u32) -> impl Fn(&Frame) -> bool {
    move |f: &Frame| f.tcp_mark() == Some(nonce)
}

#[cfg(target_os = "macos")]
fn seen_has_tcp_mark(seen: &[String], nonce: u32) -> bool {
    let needle = format!("tcpmark={nonce}");
    seen.iter().any(|s| s.contains(&needle))
}

fn seen_has_tcp_syn(seen: &[String], dst: Ipv4Addr, port: u16) -> bool {
    let needle = format!("-> {dst}:{port}");
    seen.iter().any(|s| s.starts_with("TCP") && s.contains(&needle))
}

/// One UDP datagram to `PROBE_IP:53` carrying [`PROBE_MARKER`] plus `nonce`,
/// from a freshly bound ephemeral socket. Callers keep the `Result`: whether
/// the send reached the network stack is a classification input in phases 2
/// and 3 (a bind-class failure must never read as a firewall verdict).
fn send_udp_probe(nonce: u32) -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut payload = PROBE_MARKER.to_vec();
    payload.extend_from_slice(&nonce.to_be_bytes());
    sock.send_to(&payload, (PROBE_IP, 53))?;
    Ok(())
}

// LiveTun =============================================================================================================

/// One opened TUN device and its discovered/assigned interface name. The
/// probe route is owned separately (by an [`OwnedRoute`] the opener returns)
/// so it is removed while both devices are still up.
struct LiveTun {
    device: tun::AsyncDevice,
    name: String,
}

impl LiveTun {
    fn tun_name(&self) -> &str {
        &self.name
    }

    /// Read frames until one satisfies `want` or `budget` elapses, appending
    /// a rendering of every frame examined (matched or not) to `seen`. One
    /// timeout wraps the whole loop — an individual `recv` is never given
    /// its own timeout, since a future dropped mid-read is not documented
    /// cancel-safe on the wintun side, and repeatedly creating/dropping read
    /// futures would multiply that risk for no benefit.
    async fn capture(&self, budget: Duration, seen: &mut Vec<String>, want: impl Fn(&Frame) -> bool) -> bool {
        self.capture_matching(budget, seen, want).await.is_some()
    }

    /// [`LiveTun::capture`]'s body, handing the matched frame back rather than
    /// a bare yes/no. The handshake completed by hand for the mid-stream probe
    /// needs the SYN's own sequence number to acknowledge; every other caller
    /// only asks whether a frame arrived, and goes through `capture` above.
    async fn capture_matching(
        &self,
        budget: Duration,
        seen: &mut Vec<String>,
        want: impl Fn(&Frame) -> bool,
    ) -> Option<Frame> {
        let mut buf = vec![0u8; 65536];
        let inner = async {
            loop {
                let n = match self.device.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        seen.push(format!("<recv error: {e}>"));
                        return None;
                    }
                };
                match parse_frame(&buf[..n]) {
                    Some(frame) => {
                        let matched = want(&frame);
                        seen.push(frame.render());
                        if matched {
                            return Some(frame);
                        }
                    }
                    None => seen.push(format!("<unparsed {n}B>")),
                }
            }
        };
        tokio::time::timeout(budget, inner).await.unwrap_or(None)
    }
}

// Platform device + route setup =======================================================================================

#[cfg(target_os = "windows")]
fn open_windows_device(name: &str, addr: &str, netmask: &str) -> tun::AsyncDevice {
    let mut cfg = tun::Configuration::default();
    cfg.tun_name(name).mtu(1500).up().address(addr).netmask(netmask);
    tun::create_as_async(&cfg).unwrap_or_else(|e| panic!("HARNESS: create_as_async({name}) failed: {e}"))
}

#[cfg(target_os = "windows")]
fn print_diagnostics(name1: &str, name2: &str) {
    eprintln!("[live_tun_permit] device1={name1} device2={name2}");
    if let Ok(out) = Command::new("route").args(["print", "-4"]).output() {
        eprintln!(
            "[live_tun_permit] route print -4:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}

/// Open both TUN devices and install the probe route on device 1 only.
/// Device 2 stays live and addressed but carries nothing — its only job is
/// to be a genuinely different, genuinely open interface for phase 3's
/// mutation. Names deliberately do NOT start with `hole-tun`: the bridge's
/// `adapter_cleanup` wildcard sweep matches `hole-tun*` and would delete a
/// live adapter out from under this test on any bridge teardown running
/// concurrently on the box.
#[cfg(target_os = "windows")]
fn open_pair() -> (LiveTun, LiveTun, OwnedRoute) {
    crate::device::wintun::ensure_loaded().expect("HARNESS: ensure_loaded (wintun.dll)");

    let name1 = "permit-test-tun-a".to_string();
    let name2 = "permit-test-tun-b".to_string();
    let dev1 = open_windows_device(&name1, DEV1_ADDR, "255.255.255.0");
    let dev2 = open_windows_device(&name2, "10.255.252.1", "255.255.255.0");

    print_diagnostics(&name1, &name2);
    // Ownership BEFORE verification: `assert_wins_for` panics on a
    // pre-existing route winning the lookup, and this route must unwind with
    // it (see `OwnedRoute`).
    let route = OwnedRoute::add(PROBE_NET, &name1, None);
    route.assert_wins_for(PROBE_IP.into());

    (
        LiveTun {
            device: dev1,
            name: name1,
        },
        LiveTun {
            device: dev2,
            name: name2,
        },
        route,
    )
}

#[cfg(target_os = "macos")]
fn open_macos_device(addr: &str, dest: &str) -> tun::AsyncDevice {
    // Name is NOT requested — XNU assigns utunN, read back below. This is
    // the same discovery shape production must thread through once macOS
    // stops naming its TUN with a compile-time constant.
    let cfg = tun::Configuration::default();
    tun::create_as_async(&cfg)
        .unwrap_or_else(|e| panic!("HARNESS: create_as_async (empty config) failed: {e}"))
        .tap_ifconfig(addr, dest)
}

// Small extension so `open_macos_device` can chain the ifconfig call without
// an intermediate named binding at every call site.
#[cfg(target_os = "macos")]
trait TapIfconfig {
    fn tap_ifconfig(self, addr: &str, dest: &str) -> Self;
}

#[cfg(target_os = "macos")]
impl TapIfconfig for tun::AsyncDevice {
    fn tap_ifconfig(self, addr: &str, dest: &str) -> Self {
        let name = self
            .tun_name()
            .unwrap_or_else(|e| panic!("HARNESS: tun_name() failed: {e}"));
        let out = Command::new("ifconfig")
            .args([
                name.as_str(),
                "inet",
                addr,
                dest,
                "netmask",
                "255.255.255.255",
                "mtu",
                "1500",
                "up",
            ])
            .output()
            .unwrap_or_else(|e| panic!("HARNESS: failed to spawn ifconfig {name}: {e}"));
        if !out.status.success() {
            panic!(
                "HARNESS: ifconfig {name} failed: {}",
                crate::test_utils::describe_output(&out)
            );
        }
        self
    }
}

#[cfg(target_os = "macos")]
fn print_diagnostics(name1: &str, name2: &str) {
    eprintln!("[live_tun_permit] device1={name1} device2={name2}");
    if let Ok(out) = Command::new("netstat").args(["-rn", "-f", "inet"]).output() {
        eprintln!(
            "[live_tun_permit] netstat -rn -f inet:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}

#[cfg(target_os = "macos")]
fn open_pair() -> (LiveTun, LiveTun, OwnedRoute) {
    let dev1 = open_macos_device(DEV1_ADDR, DEV1_PEER);
    let name1 = dev1
        .tun_name()
        .unwrap_or_else(|e| panic!("HARNESS: tun_name() (device 1) failed: {e}"));
    let dev2 = open_macos_device("10.255.252.1", "10.255.252.2");
    let name2 = dev2
        .tun_name()
        .unwrap_or_else(|e| panic!("HARNESS: tun_name() (device 2) failed: {e}"));

    print_diagnostics(&name1, &name2);
    // Ownership BEFORE verification — see the Windows opener's note.
    let route = OwnedRoute::add(PROBE_NET, &name1, None);
    route.assert_wins_for(PROBE_IP.into());

    (
        LiveTun {
            device: dev1,
            name: name1,
        },
        LiveTun {
            device: dev2,
            name: name2,
        },
        route,
    )
}

// The four-phase test =================================================================================================

// `open_pair` and `platform_pin` are taken as parameters, not called
// directly, so this function (unlike its callers below) carries no
// `#[cfg(target_os = ...)]` at all: it is one body, typechecked on every
// platform, and a change that breaks one platform's phases cannot hide until
// that platform's lane runs.
fn run_live_tun_permit_core(
    open_pair: impl FnOnce() -> (LiveTun, LiveTun, OwnedRoute),
    platform_pin: impl FnOnce(&Path),
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("HARNESS: build tokio runtime");

    rt.block_on(async move {
        // `open_pair` must run inside this `block_on`: on Unix, `tun`'s
        // `AsyncDevice` registers its fd with whatever reactor is entered at
        // construction, and panics ("no reactor running") with none entered.
        // Calling it here also keeps device construction on the SAME runtime
        // instance that later drives `.recv()` — a different runtime's
        // reactor wouldn't be the one polling these fds. The route is dropped
        // before either device (reverse declaration order), so it is removed
        // while the interface carrying it is still up.
        let (dev1, dev2, _probe_route) = open_pair();

        // Escape guard + recovery record BEFORE anything is engaged.
        let guard = EscapeGuard::with_temp_dir(&RECORD);
        let resolver = SystemLuidResolver;

        // Phase 1 — control, no cover engaged.
        let mut seen1 = Vec::new();
        send_udp_probe(1).expect("HARNESS: control probe (nonce 1) failed to leave the process");
        let control_ok = dev1.capture(Duration::from_secs(5), &mut seen1, udp_matches(1)).await;
        assert!(
            control_ok,
            "HARNESS/CONTROL FAILED (says NOTHING about the cover — no cover is engaged in this phase): \
             a UDP probe sent to {PROBE_IP} never surfaced on device 1 ('{}'); seen={seen1:?}",
            dev1.tun_name(),
        );

        // Phase 2 — positive: engage naming device 1 (the one carrying the route).
        let cover = engage_lockdown(server_ip(), dev1.tun_name(), &resolver, &[], guard.state_dir(), None)
            .expect("engage real standing lockdown cover naming device 1");

        let send2 = send_udp_probe(2);
        let mut seen2_udp = Vec::new();
        let permit_seen = dev1.capture(Duration::from_secs(5), &mut seen2_udp, udp_matches(2)).await;

        let tcp2 = TcpStream::connect_timeout(
            &SocketAddr::from((PROBE_TCP_IP, TCP_PROBE_PORT_PHASE2)),
            Duration::from_secs(1),
        );
        let mut seen2_tcp = Vec::new();
        let permit_seen_tcp = dev1
            .capture(
                Duration::from_secs(5),
                &mut seen2_tcp,
                tcp_syn_matches(PROBE_TCP_IP, TCP_PROBE_PORT_PHASE2),
            )
            .await;

        let cover_blocking = TcpStream::connect_timeout(&NON_PERMITTED.parse().unwrap(), Duration::from_secs(5)).is_err();
        let server_permit_ok =
            TcpStream::connect_timeout(&format!("{SERVER_IP}:443").parse().unwrap(), Duration::from_secs(5)).is_ok();

        drop(cover);

        // Assert only after the cover is released, in the mandated order.
        // The harness gate asks ONLY whether each probe reached the network
        // stack: a probe the stack rejected — including the
        // `PermissionDenied` a Windows WFP deny at `ALE_AUTH_CONNECT`
        // produces — IS a cover verdict, and belongs to the product assert
        // below, not here. `send2` is a connectionless UDP send, so it goes
        // through `classify_send`, never `classify` — its `Ok` says nothing
        // about the cover on its own (see `test_utils::probe`'s module doc);
        // only `is_verdict()` (shared error-classification logic with
        // `classify`) is read from it, never a `Delivered`-shaped verdict.
        // The real permit/leak evidence for send2 is `permit_seen`, read off
        // `dev1.capture` below — a wire oracle, not this return value.
        let send2_fate = classify_send(&send2);
        let tcp2_fate = classify(&tcp2);
        assert!(
            send2_fate.is_verdict() && tcp2_fate.is_verdict(),
            "HARNESS: a phase-2 probe never reached the network stack (send2={send2_fate:?}, tcp2={tcp2_fate:?}) \
             — this says nothing about the cover, fix the harness first",
        );
        assert!(
            cover_blocking,
            "with the cover engaged, {NON_PERMITTED} must be blocked (if the block is inert nothing else means anything)"
        );
        assert!(
            server_permit_ok,
            "with the cover engaged, the server IP ({SERVER_IP}:443) must stay reachable — distinguishes a \
             broken cover from a general network outage"
        );
        assert!(
            permit_seen && permit_seen_tcp,
            "PRODUCT BUG, not a test bug: the tunnel-permit rule did not match the interface it names \
             (device 1, '{}') — UDP permit_seen={permit_seen} (seen={seen2_udp:?}, send2={send2_fate:?}) \
             TCP permit_seen_tcp={permit_seen_tcp} (seen={seen2_tcp:?}, tcp2={tcp2_fate:?})",
            dev1.tun_name(),
        );

        // Phase 3 — mutation: re-engage naming device 2, a genuinely live but
        // uninvolved interface. The anti-vacuity mechanism (module doc).
        let cover3 = engage_lockdown(server_ip(), dev2.tun_name(), &resolver, &[], guard.state_dir(), None)
            .expect("engage real standing lockdown cover naming device 2 (mutation)");

        let send3 = send_udp_probe(3);
        let tcp3 = TcpStream::connect_timeout(
            &SocketAddr::from((PROBE_TCP_IP, TCP_PROBE_PORT_PHASE3)),
            Duration::from_secs(1),
        );

        drop(cover3);

        // Tail: sent AFTER the cover is dropped. Its arrival is the
        // rendezvous proving the device and the send path are alive, and —
        // by the FIFO ordering of one device's frame queue — that the
        // phase-3 probes' firewall fate was already sealed before this send.
        send_udp_probe(4).expect("HARNESS: tail probe (nonce 4) failed to leave the process");
        let mut seen3 = Vec::new();
        let tail_seen = dev1.capture(Duration::from_secs(5), &mut seen3, udp_matches(4)).await;

        // 1. Classify send3/tcp3: absence from `seen3` is only a firewall
        //    verdict if the probe actually reached the stack. send3 is a
        //    connectionless UDP send — see the classify_send note on send2
        //    above for why it goes through classify_send, not classify.
        let send3_fate = classify_send(&send3);
        let tcp3_fate = classify(&tcp3);
        assert!(
            send3_fate.is_verdict() && tcp3_fate.is_verdict(),
            "HARNESS: a mutation-phase probe never reached the network stack (send3={send3_fate:?}, \
             tcp3={tcp3_fate:?}) — cannot judge the mutation from these; seen={seen3:?}",
        );
        // 2. The tail arrived — device/send path alive, ordering argument holds.
        assert!(
            tail_seen,
            "HARNESS: the tail probe (nonce 4, sent after the cover was dropped) never surfaced on device 1 \
             — device or send path is dead; the mutation phase is inconclusive, not a cover verdict; \
             seen={seen3:?}"
        );
        // 3. Neither phase-3 probe is in the log ahead of the tail.
        let nonce3_present = seen_has_udp_nonce(&seen3, 3);
        let syn3_present = seen_has_tcp_syn(&seen3, PROBE_TCP_IP, TCP_PROBE_PORT_PHASE3);
        assert!(
            !nonce3_present && !syn3_present,
            "the tunnel permit is not sensitive to the interface it names — the positive phase proved \
             nothing. seen={seen3:?}"
        );

        // Phase 4 — restore: nothing engaged.
        send_udp_probe(5).expect("HARNESS: restore probe (nonce 5) failed to leave the process");
        let mut seen4 = Vec::new();
        let restored = dev1.capture(Duration::from_secs(5), &mut seen4, udp_matches(5)).await;
        assert!(restored, "restore: probe must surface with no cover engaged; seen={seen4:?}");
        assert!(
            TcpStream::connect_timeout(&NON_PERMITTED.parse().unwrap(), Duration::from_secs(5)).is_ok(),
            "restore: {NON_PERMITTED} must be reachable again — the box was left open"
        );

        platform_pin(guard.state_dir());

        drop(guard);
    });
}

/// F5: Windows fails loud on an unknown interface alias. macOS's
/// silent-accept is exactly the dangerous asymmetry this whole module exists
/// to catch by naming a LIVE wrong interface instead, so it has no
/// counterpart there.
#[cfg(target_os = "windows")]
fn windows_unknown_alias_pin(state_dir: &Path) {
    let bad = engage_lockdown(
        server_ip(),
        "hole-live-tun-permit-does-not-exist",
        &SystemLuidResolver,
        &[],
        state_dir,
        None,
    );
    let is_err = bad.is_err();
    drop(bad); // release immediately if it somehow engaged
    assert!(
        is_err,
        "ConvertInterfaceAliasToLuid must fail loud on an unknown alias (F5)"
    );
}

/// Windows: see the module doc for the four-phase shape and the anti-vacuity
/// argument. `serial = TUN` (the crate-root label) +
/// the `global_net_state` test-group serialize this across the elevated lane.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn windows_live_tun_permit_passes_traffic_on_the_interface_it_names() {
    run_live_tun_permit_core(open_pair, windows_unknown_alias_pin);
}

/// macOS: see the module doc for the four-phase shape and the anti-vacuity
/// argument. Unlike `lockdown_privileged_tests`'s macOS cover test, this
/// engages against a REAL, kernel-assigned `utunN` — the mutation phase
/// re-engages against a second, different, live `utunN`, so this is the
/// first test that would fail if `pass out quick on <tun>` matched any live
/// interface rather than the one it names.
#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn macos_live_tun_permit_passes_traffic_on_the_interface_it_names() {
    run_live_tun_permit_core(open_pair, |_| {});
}

// The mid-stream `no state` proof (macOS) =============================================================================

/// Establish a REAL TCP connection to [`MID_IP`] over `dev`, by reading the
/// kernel's own SYN off the device and writing a crafted SYN-ACK back. No peer
/// exists anywhere; the far end of this connection is three lines of
/// `smoltcp::wire`.
///
/// This is what makes an on-host mid-stream proof possible at all. A local
/// listener would put the flow on `lo0`, which every cover ruleset exempts
/// with `set skip` — so nothing about a non-`lo0` permit could be learned from
/// it, and the only alternative anyone had named was an off-host peer (an
/// internet-dependent probe, a flake source). Traffic to a utun-routed
/// TEST-NET-2 address is neither.
#[cfg(target_os = "macos")]
async fn establish_over_tun(dev: &LiveTun, local_port: u16, seen: &mut Vec<String>) -> tokio::net::TcpStream {
    let local = SocketAddr::from((DEV1_ADDR.parse::<Ipv4Addr>().expect("literal"), local_port));
    let peer = SocketAddr::from((MID_IP, MID_PORT));

    let sock = tokio::net::TcpSocket::new_v4().unwrap_or_else(|e| panic!("HARNESS: TcpSocket::new_v4: {e}"));
    sock.bind(local)
        .unwrap_or_else(|e| panic!("HARNESS: bind the mid-stream socket to {local}: {e}"));
    let mut connecting = Box::pin(sock.connect(peer));

    // `biased`, so the connect is polled FIRST: that poll is what issues
    // `connect(2)`, which is what puts the SYN on the device. It cannot
    // resolve here — the only thing that could answer it is the SYN-ACK
    // written below — so the capture arm is the one that returns.
    let syn = tokio::select! {
        biased;
        early = &mut connecting => panic!(
            "HARNESS: the connect to {peer} resolved before its SYN was ever read off device 1 — \
             something other than this test answered it (ok={})",
            early.is_ok()
        ),
        syn = dev.capture_matching(MID_BUDGET, seen, |f| {
            f.is_syn() && f.dst == MID_IP && f.dport == MID_PORT && f.sport == local_port
        }) => syn,
    };
    let syn = syn.unwrap_or_else(|| {
        panic!(
            "HARNESS: the kernel's SYN for {local} -> {peer} never surfaced on device 1 ('{}') — the \
             probe route is not carrying this destination, or the device is not readable; seen={seen:?}",
            dev.tun_name()
        )
    });

    let syn_ack = crate::sim::packet::tcp_syn_ack(peer, local, MID_PEER_ISN, syn.seq.wrapping_add(1));
    dev.device
        .send(&syn_ack)
        .await
        .unwrap_or_else(|e| panic!("HARNESS: write the SYN-ACK for {peer} onto device 1: {e}"));

    match tokio::time::timeout(MID_BUDGET, connecting).await {
        Ok(Ok(stream)) => {
            // Nagle would hold a small write back behind unacknowledged data.
            // Nothing is outstanding on a freshly established connection, but
            // the whole test turns on a single small write reaching the wire
            // at the instant it is issued, so do not leave that to a
            // heuristic.
            stream
                .set_nodelay(true)
                .unwrap_or_else(|e| panic!("HARNESS: set_nodelay on the mid-stream connection: {e}"));
            stream
        }
        Ok(Err(e)) => panic!("HARNESS: the connect to {peer} failed after the injected SYN-ACK: {e}"),
        Err(_) => panic!(
            "HARNESS: the kernel never completed the handshake to {peer} within {MID_BUDGET:?} — the \
             injected SYN-ACK (seq={MID_PEER_ISN}, ack={}) was discarded; seen={seen:?}",
            syn.seq.wrapping_add(1)
        ),
    }
}

/// Write ONE mid-stream segment carrying [`MID_MARKER`] plus `nonce`. The
/// resulting PSH/ACK is the exact packet a `flags S/SA` permit cannot match.
#[cfg(target_os = "macos")]
async fn write_mid_stream(stream: &mut tokio::net::TcpStream, nonce: u32) {
    use tokio::io::AsyncWriteExt;

    let mut payload = MID_MARKER.to_vec();
    payload.extend_from_slice(&nonce.to_be_bytes());
    stream
        .write_all(&payload)
        .await
        .unwrap_or_else(|e| panic!("HARNESS: write mid-stream segment {nonce}: {e}"));
}

/// Abort a mid-stream connection: `SO_LINGER 0`, so the close discards the
/// send buffer and RSTs instead of retransmitting.
///
/// Load-bearing, not tidiness. The synthetic peer never acknowledges anything,
/// so every segment written above stays unacked and the kernel retransmits it
/// on its own clock — indefinitely, and across every later leg. In the pre-fix
/// leg that would put a copy of the very segment whose ABSENCE is the verdict
/// back on the device the instant the cover comes down, racing the tail probe
/// that the absence argument depends on. Aborting the connection first leaves
/// nothing to retransmit, so the race does not exist rather than being won.
///
/// Set through `socket2` rather than `TcpStream::set_linger`, which is
/// deprecated for blocking the thread on drop — a hazard of a NON-zero linger,
/// where close waits for the peer to acknowledge. A zero one aborts at once.
#[cfg(target_os = "macos")]
fn abort_mid_stream(stream: tokio::net::TcpStream) {
    socket2::SockRef::from(&stream)
        .set_linger(Some(Duration::ZERO))
        .unwrap_or_else(|e| panic!("HARNESS: SO_LINGER 0 on a mid-stream connection: {e}"));
    drop(stream);
}

/// The kernel's own verdict on the claim this whole PR rests on: a cover
/// permit must carry a mid-stream segment of a flow it names ACROSS the
/// engage's host-wide `pfctl -F states` purge.
///
/// Everything else behind that claim is `pfctl -vn` TEXT — that a bare `pass`
/// normalizes to `flags S/SA keep state` and that `no state` suppresses it.
/// This module's neighbours prove the same property for `lo0`, which is
/// `set skip`-exempt and therefore says nothing about a permit on a real
/// interface. Nothing in the suite showed the kernel DELIVERING a mid-stream
/// segment on a non-`lo0` permit after a purge, and this mechanism has been
/// wrong three review rounds running.
///
/// Three legs, in this order:
///
/// 1. **Harness control**, no cover: establish and write. The segment MUST
///    surface. A failure here is the harness (the injected handshake, the
///    route, the device), and it is deliberately first so a broken harness
///    can never be read as either verdict below.
/// 2. **Positive control**, the PRE-FIX ruleset: the production ruleset with
///    `no state` stripped from its server permit alone — a one-line swap
///    derived from the production builder's own output, so it cannot drift
///    from what production emits, and gated on actually matching so the
///    mutation can never silently no-op. The segment MUST NOT surface.
/// 3. **Production**: the real `engage`, which loads the real ruleset and
///    issues its own purge. The segment MUST surface.
///
/// Leg 2's negative rests on the same two properties as every other phase in
/// this module. A segment's firewall fate is decided SYNCHRONOUSLY on the
/// send path — `send(2)` runs `tcp_output` inline, so pf has already ruled by
/// the time `write_all` returns — and one device's frame queue is FIFO, so a
/// tail UDP probe sent after the cover is dropped, and confirmed to arrive,
/// proves the segment's fate was sealed before it. Leg 1 is what shows that
/// first property holds for THIS write: the same call, the same capture, and
/// the segment is there.
///
/// A dropped segment would ordinarily come back on the kernel's retransmit
/// clock and could then overtake the tail; [`abort_mid_stream`] is why none
/// exists to.
#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn macos_live_tun_permit_cover_carries_a_mid_stream_segment_after_a_state_purge() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("HARNESS: build tokio runtime");

    rt.block_on(async move {
        // Inside `block_on` for the same reason `run_live_tun_permit_core`
        // does it: `AsyncDevice` registers its fd with the reactor entered at
        // construction. Device 2 is unused here — this test asks nothing about
        // WHICH interface a permit names — but it comes with the opener, and
        // sharing that opener is what keeps the device, address and route
        // setup from existing twice.
        let (dev1, _dev2, probe_route) = open_pair();
        probe_route.assert_wins_for(MID_IP.into());

        let guard = EscapeGuard::with_temp_dir(&MID_RECORD);

        // Leg 1 — HARNESS CONTROL, nothing engaged.
        let mut seen1 = Vec::new();
        let mut uncovered = establish_over_tun(&dev1, MID_LOCAL_PORT_UNCOVERED, &mut seen1).await;
        write_mid_stream(&mut uncovered, 1).await;
        let uncovered_seen = dev1.capture(MID_BUDGET, &mut seen1, tcp_mark_matches(1)).await;
        assert!(
            uncovered_seen,
            "HARNESS/CONTROL FAILED (says NOTHING about any cover — none is engaged in this leg): a \
             mid-stream segment on an established connection to {MID_IP} never surfaced on device 1 \
             ('{}'); seen={seen1:?}",
            dev1.tun_name(),
        );
        abort_mid_stream(uncovered);

        // The pre-fix ruleset: production, with `no state` stripped from the
        // SERVER permit only. Loopback's own passes keep theirs — this leg
        // must not sever the runner's local sockets to make its point, and
        // the rule under test is the server permit.
        let production = super::platform::build_pf_ruleset(MID_IP.into(), None);
        let stateless = format!("pass out quick from any to {MID_IP} no state\n");
        assert!(
            production.contains(&stateless),
            "the pre-fix control is derived from the production builder's own output, and the line it \
             rewrites is no longer there — the swap below would silently no-op and leg 2 would be \
             asserting against production twice:\n{production}"
        );
        let pre_fix = production.replace(&stateless, &format!("pass out quick from any to {MID_IP}\n"));
        assert_ne!(
            pre_fix, production,
            "the pre-fix control ruleset is identical to production"
        );

        // Leg 2 — POSITIVE CONTROL: the pre-fix, SYN-only permit.
        let mut seen2 = Vec::new();
        let mut covered = establish_over_tun(&dev1, MID_LOCAL_PORT_PREFIX, &mut seen2).await;
        let cover = super::engage(MID_IP.into(), None, guard.state_dir(), None)
            .expect("engage the real transient cover for the control leg");
        super::platform::real_load_ruleset(&pre_fix).expect("HARNESS: load the pre-fix control ruleset");
        // The engage already purged, and a `no state` permit leaves nothing
        // behind — but this leg's whole premise is "no state entry exists for
        // this flow", so state it rather than inherit it.
        super::platform::real_flush_states().expect("HARNESS: purge pf state under the control ruleset");
        write_mid_stream(&mut covered, 2).await;
        // Before the cover comes down — see `abort_mid_stream`.
        abort_mid_stream(covered);
        drop(cover);

        send_udp_probe(MID_TAIL_NONCE).expect("HARNESS: the tail probe failed to leave the process");
        let mut seen2_tail = Vec::new();
        let tail_seen = dev1
            .capture(MID_BUDGET, &mut seen2_tail, udp_matches(MID_TAIL_NONCE))
            .await;
        assert!(
            tail_seen,
            "HARNESS: the tail probe (nonce {MID_TAIL_NONCE}, sent after the control cover was dropped) \
             never surfaced on device 1 — the device or the send path is dead, so leg 2 is \
             inconclusive rather than a verdict; seen={seen2_tail:?}"
        );
        assert!(
            !seen_has_tcp_mark(&seen2_tail, 2),
            "POSITIVE CONTROL FAILED: a SYN-only (`flags S/SA keep state`) server permit DELIVERED a \
             mid-stream segment after a state purge. Either this pf does not apply the `flags S/SA` \
             default to a bare `pass`, or the probe cannot see the difference — in both cases leg 3 \
             below proves nothing and must not be silenced. seen={seen2_tail:?}"
        );

        // Leg 3 — PRODUCTION.
        let mut seen3 = Vec::new();
        let mut production_flow = establish_over_tun(&dev1, MID_LOCAL_PORT_PRODUCTION, &mut seen3).await;
        let cover = super::engage(MID_IP.into(), None, guard.state_dir(), None)
            .expect("engage the real transient cover for the production leg");
        write_mid_stream(&mut production_flow, 3).await;
        let carried = dev1.capture(MID_BUDGET, &mut seen3, tcp_mark_matches(3)).await;
        // Released before asserting, so a failure does not leave the machine
        // behind a block-all cover while the panic unwinds.
        drop(cover);
        assert!(
            carried,
            "PRODUCT BUG, not a test bug: the transient cover's server permit did NOT carry a \
             mid-stream segment of the flow it names across the engage's own `pfctl -F states` purge. \
             Leg 1 proves the segment is observable and leg 2 proves this probe can see a SYN-only \
             permit sever it, so the permit has lost its `no state`; seen={seen3:?}"
        );
        abort_mid_stream(production_flow);

        drop(guard);
    });
}

// Frame-parser coverage (unprivileged) ================================================================================
//
// Everything above needs root and a real TUN device, so the parsing the
// mid-stream verdict keys on would otherwise be exercised ONLY in the elevated
// lane — where a field-offset mistake surfaces as "the segment never arrived",
// i.e. as the very verdict the test exists to report. These two run in the
// ordinary pass.

/// The TCP fields [`Frame`] gained for the mid-stream probe, read off a
/// HAND-BUILT segment rather than round-tripped through this crate's own
/// emitter, so a shared mistake cannot cancel out.
///
/// The header deliberately carries OPTIONS: the payload starts at the data
/// offset, not at a fixed 20 bytes, and reading it from the wrong place puts
/// four option bytes in front of [`MID_MARKER`] — which is not a parse error,
/// just a marker that silently never matches.
#[skuld::test]
fn frame_parse_reads_tcp_flags_seq_and_the_payload_past_its_options() {
    const PSH_ACK: u8 = 0x18;
    let mut payload = MID_MARKER.to_vec();
    payload.extend_from_slice(&7u32.to_be_bytes());

    let mut tcp = vec![
        0xd4, 0x44, // src port 54340
        0xd4, 0x3a, // dst port 54330
        0x00, 0x00, 0x30, 0x39, // seq 12345
        0x00, 0x00, 0x00, 0x01, // ack
        0x60, // data offset 6 words = 24 bytes (20 + 4 of options)
        PSH_ACK, 0xff, 0xff, // window
        0x00, 0x00, // checksum (unverified by the parser)
        0x00, 0x00, // urgent
        0x01, 0x01, 0x01, 0x00, // options: NOP NOP NOP EOL
    ];
    tcp.extend_from_slice(&payload);

    let total = (20 + tcp.len()) as u16;
    let mut frame = vec![
        0x45,
        0x00,
        (total >> 8) as u8,
        total as u8,
        0x00,
        0x00,
        0x00,
        0x00,
        0x40,
        0x06, // TTL, proto TCP
        0x00,
        0x00, // header checksum (unverified by the parser)
        198,
        51,
        100,
        9,
        10,
        255,
        253,
        1,
    ];
    frame.extend_from_slice(&tcp);

    let parsed = parse_frame(&frame).expect("a well-formed IPv4 TCP segment must parse");
    assert_eq!(parsed.proto, 6);
    assert_eq!(parsed.sport, 54340);
    assert_eq!(parsed.dport, 54330);
    assert_eq!(parsed.seq, 12345);
    assert_eq!(parsed.flags, PSH_ACK);
    assert_eq!(
        parsed.tcp_mark(),
        Some(7),
        "the payload must be read from the DATA OFFSET, not from a fixed 20 bytes: {}",
        parsed.render()
    );
    assert_eq!(
        parsed.udp_nonce(),
        None,
        "a TCP segment must never read as a UDP probe, whatever its payload"
    );
}

/// [`Frame::is_syn`] selects the kernel's connection attempt and nothing else
/// on the same 4-tuple. A SYN-ACK sharing it must NOT match, or the handshake
/// helper would acknowledge the wrong sequence number.
#[cfg(target_os = "macos")]
#[skuld::test]
fn frame_parse_identifies_a_bare_syn_and_not_a_syn_ack() {
    let client = SocketAddr::from((Ipv4Addr::new(10, 255, 253, 1), MID_LOCAL_PORT_UNCOVERED));
    let peer = SocketAddr::from((MID_IP, MID_PORT));

    let syn = parse_frame(&crate::sim::packet::tcp_syn(client, peer, 99)).expect("a built SYN must parse");
    assert!(syn.is_syn(), "{}", syn.render());
    assert_eq!(syn.seq, 99);
    assert_eq!(syn.tcp_mark(), None, "a SYN carries no data");

    let syn_ack =
        parse_frame(&crate::sim::packet::tcp_syn_ack(peer, client, 4096, 100)).expect("a built SYN-ACK must parse");
    assert!(
        !syn_ack.is_syn(),
        "a SYN-ACK is not the bare SYN the handshake helper is looking for: {}",
        syn_ack.render()
    );
}
