//! Privileged-lane live proof for [`super::engage`] (Task 2, refs #868).
//!
//! Harness shape lifted directly from PR #877's spike
//! (`macos_dns_supplemental_spike.rs`), which proved the underlying mechanism
//! on real hardware in CI, on both darwin arches (`MECHANISM: YES`,
//! `Test hole (darwin/amd64)` and `Test hole (darwin/arm64)`, run
//! `32661621358`, commit `e8717d669dff75d9a8e19fa78895297beec8fbda`). This
//! test is that spike's mechanism, minus the hand-rolled `SCDynamicStore`
//! calls the spike used to explore the shape: it drives the real
//! [`super::engage`]/[`super::Steering`] production API instead, so what is
//! proven here is that the PRODUCTION guard — its session-scoped key (D3),
//! its dedicated store thread, its confirmable `withdraw` — steers the OS
//! resolver the same way the spike's raw calls did, not merely that the
//! mechanism exists in the abstract.
//!
//! **Assertions are on the wire and on `scutil --dns`, never on elapsed
//! time.** Every wait below rendezvous on configd's own
//! `com.apple.system.SystemConfiguration.dns_configuration` notification
//! (registered before the mutation that could cause it, so the wait cannot
//! miss a post it caused) or on a real UDP frame arriving on a real utun; the
//! `budget` deadlines passed to both are the failure bound surfaced to a
//! human when an external event — configd deciding to republish, the OS
//! resolver deciding to query — never happens, not a sleep standing in for
//! synchronisation.
//!
//! **HARNESS CONTROL, first.** Our own datagram to the synthetic resolver
//! address must surface on the utun before anything about the mechanism is
//! judged — see [`send_control`]'s call site. A `CONTROL FAILED` failure is a
//! harness/routing defect, not a verdict on `engage`.
//!
//! `serial = TUN` (the crate-root label) + the `global_net_state` nextest
//! test-group serialize this across the whole elevated lane — this test
//! points the WHOLE MACHINE's DNS at a black hole for its own duration
//! (`SupplementalMatchDomains = [""]`), so it must never run beside another
//! test that resolves a name. COUPLED NAMES: this test's name carries the
//! literal substring `dns_steer_global_net_state_`, which
//! `.config/nextest.toml`'s `global_net_state` filter matches by substring —
//! renaming it without updating that filter silently drops it from the
//! group.
//!
//! **What a real run does to the machine**: opens a real utun, installs a
//! TEST-NET-1 route into it, and publishes a real synthetic-service DNS key
//! for the duration of the test body. Not `#[ignore]`d; runs under the
//! elevated `tun` lane (`SKULD_LABELS=tun`) and fails loud, un-elevated,
//! under the default unprivileged pass — opening a utun and writing the
//! dynamic store both need root.

use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs, UdpSocket};
use std::process::Command;
use std::time::{Duration, Instant};

use tun::AbstractDevice;

use super::engage;
use crate::{GLOBAL_NET_STATE, TUN};

/// TEST-NET-1 (RFC 5737). Not a real public resolver — a runner whose own
/// DNS already pointed here would make the assertion pass by coincidence;
/// nothing reaches 192.0.2.53 by accident.
const RESOLVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);
const RESOLVER_NET: &str = "192.0.2.0/24";
const TUN_LOCAL: Ipv4Addr = Ipv4Addr::new(10, 255, 254, 5);
const TUN_PEER: Ipv4Addr = Ipv4Addr::new(10, 255, 254, 6);

const CONTROL_MARKER: &[u8] = b"HOLE-DNS-STEER-CONTROL";
const DNS_CONFIG_NOTIFY_KEY: &str = "com.apple.system.SystemConfiguration.dns_configuration";

fn budget(secs: u64) -> Instant {
    Instant::now() + Duration::from_secs(secs)
}

fn run(cmd: &str, args: &[&str]) -> (bool, String) {
    match Command::new(cmd).args(args).output() {
        Ok(out) => (
            out.status.success(),
            format!(
                "$ {cmd} {}\n[{}]\n{}{}",
                args.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            ),
        ),
        Err(e) => (false, format!("$ {cmd} {}\n[spawn failed] {e}", args.join(" "))),
    }
}

fn scutil_dns() -> String {
    run("scutil", &["--dns"]).1
}

/// Every `nameserver[N] : ADDR` line, sorted and deduped — the structural
/// shape of "which resolvers does this machine use", stable enough to
/// compare before against after.
fn nameservers(scutil_dns_output: &str) -> Vec<String> {
    let mut out: Vec<String> = scutil_dns_output
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("nameserver["))
        .map(str::to_owned)
        .collect();
    out.sort();
    out.dedup();
    out
}

// configd change notification =========================================================================================

extern "C" {
    fn notify_register_file_descriptor(
        name: *const libc::c_char,
        notify_fd: *mut libc::c_int,
        flags: libc::c_int,
        out_token: *mut libc::c_int,
    ) -> u32;
    fn notify_cancel(token: libc::c_int) -> u32;
}

/// A live registration for configd's DNS-configuration-changed notification.
/// See [`super`]'s and this module's doc for why every wait here rendezvous
/// on this rather than on elapsed time.
struct DnsConfigNotify {
    fd: libc::c_int,
    token: libc::c_int,
}

impl DnsConfigNotify {
    fn register() -> Option<Self> {
        let name = CString::new(DNS_CONFIG_NOTIFY_KEY).expect("notify key has no interior NUL");
        let mut fd: libc::c_int = -1;
        let mut token: libc::c_int = 0;
        // SAFETY: `name` is a valid NUL-terminated string that outlives the
        // call; `fd`/`token` are live out-params.
        let status = unsafe { notify_register_file_descriptor(name.as_ptr(), &mut fd, 0, &mut token) };
        (status == 0).then_some(Self { fd, token })
    }

    /// Block until configd posts a DNS-configuration change, or `deadline`
    /// passes. `deadline` is a failure bound on an EXTERNAL event, not a
    /// sync sleep — see the module doc.
    fn wait(&self, deadline: Instant) -> bool {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let millis = libc::c_int::try_from(remaining.as_millis().max(1)).unwrap_or(libc::c_int::MAX);
            let mut pfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: single live pollfd, count matches.
            match unsafe { libc::poll(&mut pfd, 1, millis) } {
                -1 if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => continue,
                -1 => return false,
                0 => return false,
                _ => {
                    let mut token_be = [0u8; 4];
                    // SAFETY: reading 4 bytes into a 4-byte buffer.
                    let n = unsafe { libc::read(self.fd, token_be.as_mut_ptr().cast(), 4) };
                    return n == 4;
                }
            }
        }
    }

    /// Block until `scutil --dns` mentioning `needle` equals `want`, driven
    /// by configd's own change posts. Checks the predicate first so an
    /// already-satisfied state needs no event at all.
    fn settle(&self, deadline: Instant, needle: &str, want: bool) -> bool {
        loop {
            if scutil_dns().contains(needle) == want {
                return true;
            }
            if !self.wait(deadline) {
                return scutil_dns().contains(needle) == want;
            }
        }
    }
}

impl Drop for DnsConfigNotify {
    fn drop(&mut self) {
        // SAFETY: token was produced by a successful registration.
        unsafe {
            notify_cancel(self.token);
        }
    }
}

// Packet inspection ===================================================================================================

/// A macOS utun fd frames every packet with a 4-byte address family. `tun`'s
/// reader strips it when `packet_information` is on (the default), so a
/// frame normally starts at the IP header; tolerate both so a PI-handling
/// mistake reads as a parse failure rather than as "no packet arrived".
fn ip_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.first().is_some_and(|b| b >> 4 == 4) {
        return Some(frame);
    }
    if frame.len() > 4 && frame[4] >> 4 == 4 {
        return Some(&frame[4..]);
    }
    None
}

struct Udp<'a> {
    dst: Ipv4Addr,
    dport: u16,
    payload: &'a [u8],
}

fn parse_udp_v4(frame: &[u8]) -> Option<Udp<'_>> {
    let ip = ip_payload(frame)?;
    if ip.len() < 20 {
        return None;
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ip.len() < ihl + 8 || ip[9] != 17 {
        return None;
    }
    let udp = &ip[ihl..];
    Some(Udp {
        dst: Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]),
        dport: u16::from_be_bytes([udp[2], udp[3]]),
        payload: &udp[8..],
    })
}

/// Read frames off the utun until one satisfies `want` or `deadline` passes.
/// Every frame seen is appended to `seen` so a miss is diagnosable.
fn capture(dev: &tun::Device, deadline: Instant, seen: &mut Vec<String>, want: impl Fn(&Udp<'_>) -> bool) -> bool {
    let mut buf = vec![0u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match dev.recv_timeout(&mut buf[..], remaining) {
            Ok(n) => match parse_udp_v4(&buf[..n]) {
                Some(udp) => {
                    seen.push(format!(
                        "UDP -> {}:{} payload={} bytes {:02x?}",
                        udp.dst,
                        udp.dport,
                        udp.payload.len(),
                        &udp.payload[..udp.payload.len().min(48)],
                    ));
                    if want(&udp) {
                        return true;
                    }
                }
                None => seen.push(format!("non-UDPv4 frame, {n} bytes: {:02x?}", &buf[..n.min(16)])),
            },
            Err(e) if e.kind() == io::ErrorKind::TimedOut => return false,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                seen.push(format!("utun recv error: {e}"));
                return false;
            }
        }
    }
}

// Probes ==============================================================================================================

fn send_control() -> io::Result<()> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    sock.send_to(CONTROL_MARKER, (RESOLVER, 53))?;
    Ok(())
}

/// A nonce label under a real delegated domain, so a resolver that IS
/// working answers NXDOMAIN promptly instead of doing something special
/// (`.invalid`/`.local`/`.test` are short-circuited by the OS resolver and
/// would never hit the wire).
fn probe_name() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("h{nanos:x}p{:x}.hole-dns-steer.example.com", std::process::id())
}

/// The OS's own resolver, via `getaddrinfo(3)` — deliberately not a
/// hand-rolled DNS client bound to the interface, which would prove only
/// that the interface works. Detached, never joined: if the query does reach
/// the black-holed resolver, `getaddrinfo` blocks retransmitting for as long
/// as mDNSResponder wants to, and the thread dies with the process.
fn spawn_os_lookup(name: String) {
    std::thread::spawn(move || {
        let outcome = (name.as_str(), 0u16).to_socket_addrs().map(|it| it.count());
        println!("[dns_steer] [os-lookup] getaddrinfo({name}) -> {outcome:?}");
    });
}

// The test ============================================================================================================

/// SHIP GATE (Task 2, #868). If this fails, `engage` does not steer macOS DNS
/// as designed — the module doc's cross-reference to PR #877's CI-confirmed
/// spike is what justifies treating that as a stop-and-escalate rather than
/// a routine regression: the underlying mechanism is proven, so a failure
/// here means the production wiring around it (the session-scoped key, the
/// store thread, `Steering`) — not the mechanism itself — regressed.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn dns_steer_global_net_state_steers_the_os_resolver() {
    let before_dns = scutil_dns();
    let before_nameservers = nameservers(&before_dns);
    println!("[dns_steer] before:\n{before_dns}");

    // 1. Open a real utun. Name is NOT requested — kernel-assigned, read back
    //    below; the exact discovery shape Task 4/6 thread through production.
    let cfg = tun::Configuration::default();
    let dev = tun::create(&cfg).expect("HARNESS: open a kernel-assigned utun");
    let tun_name = dev
        .tun_name()
        .expect("HARNESS: read back the kernel-assigned utun name");
    println!("[dns_steer] utun opened as {tun_name}");

    let (local, peer) = (TUN_LOCAL.to_string(), TUN_PEER.to_string());
    let (ok, out) = run(
        "ifconfig",
        &[
            tun_name.as_str(),
            "inet",
            local.as_str(),
            peer.as_str(),
            "netmask",
            "255.255.255.255",
            "mtu",
            "1500",
            "up",
        ],
    );
    println!("{out}");
    assert!(ok, "HARNESS: addressing {tun_name} failed");

    let (ok, out) = run(
        "route",
        &["-n", "add", "-net", RESOLVER_NET, "-interface", tun_name.as_str()],
    );
    println!("{out}");
    assert!(ok, "HARNESS: routing {RESOLVER_NET} into {tun_name} failed");
    // Removed on every path below, before returning — see the final block.

    // 2. HARNESS CONTROL, first (module doc).
    let mut seen = Vec::new();
    send_control().expect("HARNESS: send the control datagram to the synthetic resolver");
    let control = capture(&dev, budget(20), &mut seen, |udp| {
        udp.dst == RESOLVER && udp.payload.windows(CONTROL_MARKER.len()).any(|w| w == CONTROL_MARKER)
    });
    assert!(
        control,
        "CONTROL FAILED — our OWN datagram to {RESOLVER} never surfaced on {tun_name}. This is a \
         harness/routing defect and says NOTHING about `engage`. Frames seen: {seen:#?}"
    );
    println!("[dns_steer] CONTROL PASSED");

    // 3. Engage the PRODUCTION guard. Register for configd's change post
    //    BEFORE calling it, so the settle below cannot miss the post it
    //    causes.
    let notify = DnsConfigNotify::register().expect("register for configd's dns_configuration notification");
    let steering = engage(&[IpAddr::V4(RESOLVER)]).expect("engage() must succeed against a real dynamic-store session");
    println!("[dns_steer] engaged, key = {}", steering.key());

    let merged = notify.settle(budget(30), &RESOLVER.to_string(), true);
    println!("[dns_steer] configd merged the synthetic resolver into the DNS configuration: {merged}");

    // 4. Judge the OPERATING SYSTEM's resolver, not our own socket.
    let name = probe_name();
    spawn_os_lookup(name.clone());
    let label = name
        .split('.')
        .next()
        .expect("the probe name has a first label")
        .to_owned();

    let mut seen = Vec::new();
    let steered = capture(&dev, budget(60), &mut seen, |udp| {
        udp.dst == RESOLVER && udp.dport == 53 && udp.payload.windows(label.len()).any(|w| w == label.as_bytes())
    });
    println!("[dns_steer] frames seen during the OS lookup: {seen:#?}");

    // 5. Withdraw through the PRODUCTION API and prove the machine is back to
    //    where it started. `withdraw` blocks for the store thread's own
    //    confirmation (Decided-without-asking #6) — no additional wait is
    //    needed before checking `key_present`-equivalent state.
    let withdraw_result = steering.withdraw();
    let unmerged = notify.settle(budget(30), &RESOLVER.to_string(), false);

    let (_, out) = run("route", &["-n", "delete", "-net", RESOLVER_NET]);
    println!("{out}");

    let after_dns = scutil_dns();
    let after_nameservers = nameservers(&after_dns);
    println!("[dns_steer] after:\n{after_dns}");

    println!(
        "\n========== dns_steer VERDICT ==========\n\
         control passed  : true\n\
         engage succeeded: true\n\
         configd merged  : {merged}\n\
         OS query steered: {steered}\n\
         withdraw()       : {withdraw_result:?}\n\
         removal clean    : {unmerged}\n\
         =========================================\n"
    );

    assert!(
        withdraw_result.is_ok(),
        "withdraw() must confirm removal: {withdraw_result:?}"
    );
    assert!(
        unmerged,
        "REMOVAL NOT CLEAN: {RESOLVER} still appears in the DNS configuration after withdraw() reported success. \
         scutil --dns:\n{after_dns}"
    );
    assert_eq!(
        before_nameservers, after_nameservers,
        "REMOVAL NOT CLEAN: the machine's resolver set changed across the test; nothing of the user's is ever \
         captured, so nothing should have moved"
    );
    assert!(
        steered,
        "engage() published the key and configd {} it, but the OS's own resolver never sent the probe query \
         for {name} to {RESOLVER}. Frames seen on {tun_name} during the lookup: {seen:#?}",
        if merged { "DID merge" } else { "did NOT merge" }
    );
}
