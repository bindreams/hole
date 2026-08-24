//! Live-interface falsification for the standing lockdown cover's
//! tunnel-permit rule (#874).
//!
//! `lockdown_privileged_tests.rs` proves the cover is selective (permit beats
//! block-all, a non-permitted host is dropped) but engages against an
//! interface picked only to exercise the resolve path — macOS uses a name
//! that matches nothing at all, Windows a live-but-irrelevant loopback alias.
//! Neither proves the permit is sensitive to the interface it names. A rule
//! naming the wrong live interface — the realistic failure after #850 makes
//! the macOS TUN name kernel-assigned, or a stale/duplicate Windows adapter —
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
//! `serial = TUN` (reusing `lockdown_privileged_tests`'s label — a second
//! `#[skuld::label] const TUN` in this binary would mint a DIFFERENT serial
//! token and race the very cover tests this must exclude) plus the
//! `global-net-state` nextest test-group serialize this across the whole
//! elevated lane; see `.config/nextest.toml`.
//!
//! COUPLED NAMES: both test names below contain the literal substring
//! `live_tun_permit_`, which `.config/nextest.toml`'s `global-net-state`
//! filter matches. Renaming either without updating that filter silently
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
//! guard itself, would then reload block-everything as the host and erase
//! the evidence. See the plan's F7/F8 for the full argument; do not
//! reintroduce a directory-per-phase habit here.
//!
//! ## What a real run does to the machine
//!
//! **This engages a real, system-wide block-all firewall cover on the host
//! running it, for a few seconds, more than once.** It is not `#[ignore]`d
//! and a plain `cargo nextest run` on an unelevated box fails loud (the
//! privilege check), but on an elevated box it WILL arm the kill switch. If
//! interrupted, [`EscapeGuard::new`] has already written the recovery text to
//! `%TEMP%\hole-live-tun-permit-RECOVERY.txt` (or `/dev/tty`'s mirror on
//! macOS) naming the platform command to clear it by hand.

use std::io::{self, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[cfg(target_os = "macos")]
use tun::AbstractDevice;

use super::lockdown_privileged_tests::TUN;
use super::{engage_lockdown, release_all, SystemLuidResolver};

// Constants ===========================================================================================================

/// TEST-NET-2 (RFC 5737) — never routable on the real internet, so its only
/// route is the one this test installs. A prefix distinct from the other
/// probe addresses used across this crate's privileged tests keeps a
/// stranded route attributable to this test alone.
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
    /// UDP payload (empty for TCP — only the header fields matter there).
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
            6 => format!("TCP {}:{} -> {}:{}", self.src, self.sport, self.dst, self.dport),
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
                payload,
            })
        }
        6 => {
            let sport = u16_be(l4, 0)?;
            let dport = u16_be(l4, 2)?;
            Some(Frame {
                proto,
                src,
                dst,
                sport,
                dport,
                payload: Vec::new(),
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

fn seen_has_tcp_syn(seen: &[String], dst: Ipv4Addr, port: u16) -> bool {
    let needle = format!("-> {dst}:{port}");
    seen.iter().any(|s| s.starts_with("TCP") && s.contains(&needle))
}

/// One UDP datagram to `PROBE_IP:53` carrying [`PROBE_MARKER`] plus `nonce`,
/// from a freshly bound ephemeral socket. Callers keep the `Result`: whether
/// the send itself left the process is a classification input in phase 3
/// (a bind-class failure must never read as a firewall block).
fn send_udp_probe(nonce: u32) -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut payload = PROBE_MARKER.to_vec();
    payload.extend_from_slice(&nonce.to_be_bytes());
    sock.send_to(&payload, (PROBE_IP, 53))?;
    Ok(())
}

// LiveTun =============================================================================================================

/// One opened TUN device, its discovered/assigned interface name, and
/// (device 1 only) ownership of the probe route this test installed. `Drop`
/// removes only a route it confirmed creating (F9) and never panics —
/// failures are `eprintln!`ed so a developer whose box is left modified
/// finds out, without risking a double panic during an unwind that would
/// skip the release guards downstream.
struct LiveTun {
    device: tun::AsyncDevice,
    name: String,
    owns_probe_route: bool,
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
        let mut buf = vec![0u8; 65536];
        let inner = async {
            loop {
                let n = match self.device.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        seen.push(format!("<recv error: {e}>"));
                        return false;
                    }
                };
                match parse_frame(&buf[..n]) {
                    Some(frame) => {
                        let matched = want(&frame);
                        seen.push(frame.render());
                        if matched {
                            return true;
                        }
                    }
                    None => seen.push(format!("<unparsed {n}B>")),
                }
            }
        };
        tokio::time::timeout(budget, inner).await.unwrap_or(false)
    }
}

impl Drop for LiveTun {
    fn drop(&mut self) {
        if !self.owns_probe_route {
            return;
        }
        #[cfg(target_os = "windows")]
        windows_remove_probe_route(&self.name);
        #[cfg(target_os = "macos")]
        macos_remove_probe_route(&self.name);
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
fn ps_output(script: &str) -> String {
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output()
        .unwrap_or_else(|e| panic!("HARNESS: failed to spawn powershell: {e}"));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[cfg(target_os = "windows")]
fn windows_add_probe_route(name: &str) {
    // F9: own only what we install. A pre-existing route to PROBE_NET on any
    // interface must not be silently doubled up or later deleted out from
    // under something this test never created.
    let existing = ps_output(&format!(
        "(Get-NetRoute -DestinationPrefix '{PROBE_NET}' -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String).Trim()"
    ));
    if !existing.is_empty() {
        panic!("HARNESS: a pre-existing route to {PROBE_NET} already exists — refusing to add a second:\n{existing}");
    }

    let out = Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "add",
            "route",
            &format!("prefix={PROBE_NET}"),
            &format!("interface=\"{name}\""),
            "store=active",
        ])
        .output()
        .unwrap_or_else(|e| panic!("HARNESS: failed to spawn netsh add route: {e}"));
    if !out.status.success() {
        panic!(
            "HARNESS: netsh add route prefix={PROBE_NET} interface=\"{name}\" failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // Read the table back: the ADD can succeed while a pre-existing
    // same-length prefix on another interface still wins the lookup (F9).
    let winner = ps_output(&format!(
        "(Find-NetRoute -RemoteIPAddress '{PROBE_IP}' -ErrorAction Stop | Select-Object -First 1 -ExpandProperty InterfaceAlias)"
    ));
    if winner != name {
        panic!(
            "HARNESS: after adding the probe route, traffic to {PROBE_IP} would actually leave via \
             '{winner}', not device 1 ('{name}') — a pre-existing route may be winning a metric tiebreak"
        );
    }
}

#[cfg(target_os = "windows")]
fn windows_remove_probe_route(name: &str) {
    let out = Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "delete",
            "route",
            &format!("prefix={PROBE_NET}"),
            &format!("interface=\"{name}\""),
            "store=active",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => {}
        Ok(o) => eprintln!(
            "HARNESS: netsh delete route prefix={PROBE_NET} interface=\"{name}\" failed: {}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => eprintln!("HARNESS: failed to spawn netsh delete route for {name}: {e}"),
    }
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
fn open_pair() -> (LiveTun, LiveTun) {
    crate::device::wintun::ensure_loaded().expect("HARNESS: ensure_loaded (wintun.dll)");

    let name1 = "permit-test-tun-a".to_string();
    let name2 = "permit-test-tun-b".to_string();
    let dev1 = open_windows_device(&name1, "10.255.253.1", "255.255.255.0");
    let dev2 = open_windows_device(&name2, "10.255.252.1", "255.255.255.0");

    print_diagnostics(&name1, &name2);
    windows_add_probe_route(&name1);

    (
        LiveTun {
            device: dev1,
            name: name1,
            owns_probe_route: true,
        },
        LiveTun {
            device: dev2,
            name: name2,
            owns_probe_route: false,
        },
    )
}

#[cfg(target_os = "macos")]
fn open_macos_device(addr: &str, dest: &str) -> tun::AsyncDevice {
    // Name is NOT requested — XNU assigns utunN, read back below. This is
    // the same discovery shape #850 must thread into production.
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
                String::from_utf8_lossy(&out.stderr)
            );
        }
        self
    }
}

#[cfg(target_os = "macos")]
fn macos_existing_probe_route() -> Option<String> {
    let out = Command::new("netstat").args(["-rn", "-f", "inet"]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.lines()
        .find(|l| {
            l.split_whitespace()
                .next()
                .map(|dest| dest.starts_with("198.51.100"))
                .unwrap_or(false)
        })
        .map(|s| s.to_string())
}

#[cfg(target_os = "macos")]
fn macos_add_probe_route(name: &str) {
    // F9: own only what we install.
    if let Some(existing) = macos_existing_probe_route() {
        panic!(
            "HARNESS: a pre-existing route touching {PROBE_NET} already exists — refusing to add a second:\n{existing}"
        );
    }

    let out = Command::new("route")
        .args(["-n", "add", "-net", PROBE_NET, "-interface", name])
        .output()
        .unwrap_or_else(|e| panic!("HARNESS: failed to spawn route add: {e}"));
    if !out.status.success() {
        panic!(
            "HARNESS: route -n add -net {PROBE_NET} -interface {name} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // Read the table back via the kernel's own lookup for PROBE_IP, not a
    // static prefix-match re-implementation (F9).
    let out = Command::new("route")
        .args(["-n", "get", &PROBE_IP.to_string()])
        .output()
        .unwrap_or_else(|e| panic!("HARNESS: failed to spawn route get: {e}"));
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let winner = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("interface:").map(|s| s.trim().to_string()));
    match winner {
        Some(w) if w == name => {}
        Some(w) => panic!(
            "HARNESS: after adding the probe route, traffic to {PROBE_IP} would actually leave via \
             '{w}', not device 1 ('{name}') — a pre-existing route may be winning:\n{text}"
        ),
        None => panic!("HARNESS: could not parse `route -n get {PROBE_IP}` output:\n{text}"),
    }
}

#[cfg(target_os = "macos")]
fn macos_remove_probe_route(name: &str) {
    let out = Command::new("route")
        .args(["-n", "delete", "-net", PROBE_NET, "-interface", name])
        .output();
    match out {
        Ok(o) if o.status.success() => {}
        Ok(o) => eprintln!(
            "HARNESS: route -n delete -net {PROBE_NET} -interface {name} failed: {}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => eprintln!("HARNESS: failed to spawn route delete for {name}: {e}"),
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
fn open_pair() -> (LiveTun, LiveTun) {
    let dev1 = open_macos_device("10.255.253.1", "10.255.253.2");
    let name1 = dev1
        .tun_name()
        .unwrap_or_else(|e| panic!("HARNESS: tun_name() (device 1) failed: {e}"));
    let dev2 = open_macos_device("10.255.252.1", "10.255.252.2");
    let name2 = dev2
        .tun_name()
        .unwrap_or_else(|e| panic!("HARNESS: tun_name() (device 2) failed: {e}"));

    print_diagnostics(&name1, &name2);
    macos_add_probe_route(&name1);

    (
        LiveTun {
            device: dev1,
            name: name1,
            owns_probe_route: true,
        },
        LiveTun {
            device: dev2,
            name: name2,
            owns_probe_route: false,
        },
    )
}

// Recovery record =====================================================================================================

#[cfg(target_os = "windows")]
fn recovery_command() -> &'static str {
    "hole bridge unlock"
}

#[cfg(target_os = "macos")]
fn recovery_command() -> &'static str {
    // NEVER `hole bridge unlock` here (#882): that resolves the fixed
    // production `service_state_dir()`, not this test's tempdir, and would
    // report success while the real cover (engaged into OUR state dir)
    // stays live.
    "sudo pfctl -f /etc/pf.conf"
}

#[cfg(target_os = "windows")]
fn open_controlling_terminal() -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new().write(true).open("CONOUT$")
}

#[cfg(target_os = "macos")]
fn open_controlling_terminal() -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new().write(true).open("/dev/tty")
}

/// Write the escape-from-a-stranded-cover record BEFORE the first engage —
/// never from a `Drop`, which is exactly as absent as the banner it replaces
/// on any path that skips destructors (SIGINT, a double-panic abort). Writes
/// a fixed, predictable file AND the controlling terminal (best-effort — no
/// terminal in CI is not an error): the terminal write is the one an
/// interactive developer actually sees, since nextest's captured-stdout pipe
/// is rendered only on completion of the test, never on an abort mid-run.
fn write_recovery_record(state_dir: &Path) -> io::Result<PathBuf> {
    let path = std::env::temp_dir().join("hole-live-tun-permit-RECOVERY.txt");
    let text = format!(
        "hole live-tun-permit test: a real system-wide fail-closed cover may be engaged.\n\
         State directory: {}\n\
         If this file still exists and the test process is gone, the host may be stranded\n\
         fail-closed. Recover with:\n\
         \n    {}\n\n",
        state_dir.display(),
        recovery_command(),
    );
    std::fs::write(&path, &text)?;
    if let Ok(mut tty) = open_controlling_terminal() {
        let _ = tty.write_all(text.as_bytes());
    }
    Ok(path)
}

/// Unconditional escape, alive from before the first engage to the end of
/// the test. Owns the single state directory (F7): `release_all` reads that
/// directory's state file to decide what to clear, and an ABSENT file reads
/// as a clean host — so this guard owning the `TempDir` itself (not just its
/// path) guarantees `release_all` never runs against a directory some other
/// cleanup already deleted, which would silently report success over a live
/// cover.
struct EscapeGuard {
    dir: tempfile::TempDir,
    record_path: PathBuf,
}

impl EscapeGuard {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("HARNESS: create state tempdir");
        let record_path = write_recovery_record(dir.path()).expect("HARNESS: write recovery record");
        Self { dir, record_path }
    }

    fn state_dir(&self) -> &Path {
        self.dir.path()
    }
}

impl Drop for EscapeGuard {
    fn drop(&mut self) {
        // Must not panic: this may run during an unwind.
        if let Err(e) = release_all(self.dir.path()) {
            eprintln!(
                "HARNESS: release_all failed during EscapeGuard::drop over {:?}: {e} — host may still be \
                 fail-closed; see {:?}",
                self.dir.path(),
                self.record_path
            );
        }
        if let Err(e) = std::fs::remove_file(&self.record_path) {
            eprintln!("HARNESS: failed to remove recovery record {:?}: {e}", self.record_path);
        }
    }
}

// The four-phase test =================================================================================================

fn run_live_tun_permit_core(dev1: LiveTun, dev2: LiveTun) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("HARNESS: build tokio runtime");

    rt.block_on(async move {
        // Escape guard + recovery record BEFORE anything is engaged (F8).
        let guard = EscapeGuard::new();
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
        let send2_left_process = send2.is_ok();
        let tcp2_consistent = matches!(
            tcp2.as_ref().map_err(|e| e.kind()),
            Err(io::ErrorKind::TimedOut) | Err(io::ErrorKind::ConnectionRefused) | Err(io::ErrorKind::ConnectionReset)
        );
        assert!(
            send2_left_process && tcp2_consistent,
            "HARNESS: a phase-2 probe did not reach the network stack for a reason unrelated to the cover \
             (send2={:?}, tcp2={:?}) — this says nothing about the cover, fix the harness first",
            send2.as_ref().err().map(|e| e.kind()),
            tcp2.as_ref().err().map(|e| e.kind()),
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
             (device 1, '{}') — UDP permit_seen={permit_seen} (seen={seen2_udp:?}) TCP permit_seen_tcp={permit_seen_tcp} \
             (seen={seen2_tcp:?})",
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
        //    verdict if the probe actually reached the stack.
        let send3_consistent = matches!(send3, Ok(())) || matches!(&send3, Err(e) if e.kind() == io::ErrorKind::PermissionDenied);
        let tcp3_consistent = tcp3.is_ok()
            || matches!(
                tcp3.as_ref().map_err(|e| e.kind()),
                Err(io::ErrorKind::PermissionDenied) | Err(io::ErrorKind::TimedOut)
            );
        assert!(
            send3_consistent && tcp3_consistent,
            "HARNESS: a mutation-phase probe failed for a reason unrelated to firewall blocking \
             (send3={:?}, tcp3={:?}) — cannot judge the mutation from these; seen={seen3:?}",
            send3.as_ref().err().map(|e| e.kind()),
            tcp3.as_ref().err().map(|e| e.kind()),
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

        // Windows-only, cheap: pins F5 (Windows fails loud on an unknown
        // alias; macOS's silent-accept is exactly the dangerous asymmetry
        // this whole module exists to catch by naming a LIVE wrong
        // interface instead).
        #[cfg(target_os = "windows")]
        {
            let bad = engage_lockdown(
                server_ip(),
                "hole-live-tun-permit-does-not-exist",
                &resolver,
                &[],
                guard.state_dir(),
                None,
            );
            let is_err = bad.is_err();
            drop(bad); // release immediately if it somehow engaged
            assert!(is_err, "ConvertInterfaceAliasToLuid must fail loud on an unknown alias (F5)");
        }

        drop(guard);
    });
}

/// Windows: see the module doc for the four-phase shape and the anti-vacuity
/// argument. `serial = TUN` (reusing `lockdown_privileged_tests`'s label) +
/// the `global-net-state` test-group serialize this across the elevated lane.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn windows_live_tun_permit_passes_traffic_on_the_interface_it_names() {
    let (dev1, dev2) = open_pair();
    run_live_tun_permit_core(dev1, dev2);
}

/// macOS: see the module doc for the four-phase shape and the anti-vacuity
/// argument. Unlike `lockdown_privileged_tests`'s macOS cover test, this
/// engages against a REAL, kernel-assigned `utunN` — the mutation phase
/// re-engages against a second, different, live `utunN`, so this is the
/// first test that would fail if `pass out quick on <tun>` matched any live
/// interface rather than the one it names.
#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn macos_live_tun_permit_passes_traffic_on_the_interface_it_names() {
    let (dev1, dev2) = open_pair();
    run_live_tun_permit_core(dev1, dev2);
}
