//! macOS-only privileged smoke test for a real Full-mode start — the #893
//! seam (refs bindreams/hole#850, #868).
//!
//! Every other Full-mode e2e in this crate (`proxy_manager_e2e_tests.rs`'s
//! `mod tun`, `proxy_manager_live_tun_permit_e2e_tests.rs`) is driven through
//! `BridgeRequest::Start`/`Stop` and then judges the session by dialing
//! sockets — never by asking the OS what it actually installed. Before this
//! file, no test on ANY platform asked: after a real Full-mode start, does
//! the OS's own interface list, routing table, and resolver configuration
//! actually show what Hole claims to have done? On macOS that question was
//! previously unanswerable at all — `TUN_DEVICE_NAME` didn't exist as
//! something `Dispatcher::new` could open until Task 6 (closes #850), and
//! `SystemDns::apply` was a no-op until Task 3 (closes #868).
//!
//! Every fact this test asserts is read from the OS — `ifconfig -l`,
//! `netstat -rn -f inet`, `scutil --dns` — never from a `BridgeResponse`
//! field. `BridgeResponse::Status` exposes no TUN device name/alias/interface
//! (checked exhaustively against `hole_common::protocol::BridgeResponse`),
//! so the new interface is identified by diffing the OS's own interface list
//! before and after `Start`, not by reading anything the dispatcher reports
//! back to us — the point of this test is to catch exactly the case where
//! what we report and what the OS actually did have come apart.
//!
//! **Both DNS reads subscribe to configd's own
//! `com.apple.system.SystemConfiguration.dns_configuration` notification
//! before the mutating call (`Start`, then `Stop`) and block on it before
//! reading `scutil --dns`** — a bare read races configd's own
//! recomputation and can pass vacuously in either direction. Harness lifted
//! from `tun_engine::dns_steer::privileged_tests` (this crate cannot import
//! that module's private items, so it is duplicated here rather than made
//! `pub`, matching how that file itself duplicated the pattern rather than
//! sharing it with anything else).
//!
//! `DnsConfig::default()` (real Cloudflare resolvers, DoH) is used rather
//! than a synthetic/unreachable address: the bridge's own start-time
//! forwarder self-test (CLAUDE.md `#dns-forwarder`) would fail Start outright
//! against a resolver nothing can actually answer through the tunnel. Using
//! the default also sidesteps the macOS IPv6-assignment-fatality question —
//! IPv6 assignment is warn-only there, so this test does not need it to
//! succeed to pass; the assignment attempt itself still runs as a side
//! effect of `routing.install` inside `Start` (CLAUDE.md `#ipv6-in-the-tunnel`
//! — `hole-tun` unconditionally holds `TUN_SUBNET6` on the OS interface),
//! making this test's first real run the first execution of that path on the
//! darwin TUN lane. This test does not assert anything about IPv6: what that
//! path actually does must be read out of the run's own logs, not out of
//! any assertion here (see the module doc on
//! `tun_engine::device`/`tun_engine::routing`'s IPv6 handling for the open
//! questions).
//!
//! Requires root (opens a real utun, writes real routes, writes a real
//! dynamic-store DNS key) and needs the staged dist binary (`DIST_BIN`).
//! Runs on the elevated `tun` lane only (`SKULD_LABELS=tun`) — NOT
//! `#[ignore]`d, fails loud unelevated.
//!
//! COUPLED NAME: this test's name carries the literal substrings `e2e_` and
//! `full_tunnel`, which `.config/nextest.toml`'s `global_net_state` filter's
//! `test(/^e2e_.*full_tunnel/)` anchor already matches — no separate filter
//! entry was needed, only the documentation list update alongside this file.

#![cfg(target_os = "macos")]

use std::ffi::CString;
use std::io;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::test_support::dist_fixture::*;
use crate::test_support::dist_harness::DistHarness;
use crate::test_support::port_alloc::allocate_ephemeral_port;
use crate::test_support::rt;
use crate::test_support::skuld_fixtures::*;
use hole_common::config::{DnsConfig, ServerEntry};
use hole_common::protocol::{BridgeRequest, BridgeResponse, ProxyConfig, TunnelMode};
use util::port_alloc::Protocols;

// configd change notification (duplicated from
// `tun_engine::dns_steer::privileged_tests` — private to that crate, see
// module doc) =========================================================================================================

const DNS_CONFIG_NOTIFY_KEY: &str = "com.apple.system.SystemConfiguration.dns_configuration";

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
/// Every wait below rendezvous on this rather than on elapsed time; the
/// `deadline` passed to `wait`/`settle` is the failure bound surfaced to a
/// human when configd never posts, not a sync sleep.
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

fn budget(secs: u64) -> Instant {
    Instant::now() + Duration::from_secs(secs)
}

// OS-state helpers ====================================================================================================

fn scutil_dns() -> String {
    Command::new("scutil")
        .arg("--dns")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_else(|e| format!("HARNESS: failed to spawn scutil --dns: {e}"))
}

/// Every `nameserver[N] : ADDR` line, sorted and deduped — the structural
/// shape of "which resolvers does this machine use", stable enough to
/// compare before against after. Same technique as
/// `tun_engine::dns_steer::privileged_tests::nameservers`.
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

/// Every interface name `ifconfig -l` currently lists, in the order given.
fn ifconfig_list() -> Vec<String> {
    Command::new("ifconfig")
        .arg("-l")
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// The `utunN` interfaces newly present in `after` but absent from `before`.
fn new_utuns(before: &[String], after: &[String]) -> Vec<String> {
    after
        .iter()
        .filter(|name| name.starts_with("utun") && !before.contains(name))
        .cloned()
        .collect()
}

fn netstat_inet() -> String {
    Command::new("netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_else(|e| format!("HARNESS: failed to spawn netstat -rn -f inet: {e}"))
}

/// The interface the kernel's own longest-prefix-match lookup picks for
/// `dest`, per `route -n get <dest>` — a real routing-table read, not a
/// rendering of one. Chosen over parsing `netstat -rn -f inet`'s destination
/// column because that column's format is not the production route strings:
/// macOS's netstat elides trailing zero octets (`128.0.0.0/1` prints as
/// `128.0/1`), so matching it verbatim against `tun_engine::routing`'s own
/// `"128.0.0.0/1"` literal is brittle, and swapping in the abbreviated form
/// would only be brittle in the other direction — it would break on the next
/// rendering variation instead of this one. `route -n get` sidesteps table
/// formatting entirely by asking the kernel a real question ("what would you
/// route this destination through") whose answer needs no un-abbreviating.
///
/// `dest` is each split network's own base address (`0.0.0.0` for the low
/// half, `128.0.0.0` for the high half) — a member of that /1 block — so
/// when the split route is installed it outranks the machine's default
/// route (`0.0.0.0/0`) by longest-prefix match; when the split is absent
/// (before Start, after Stop) the lookup instead answers with whatever
/// route already covers that address (typically the default), which the
/// caller asserts differs from the TUN interface.
fn route_get_interface(dest: &str) -> Option<String> {
    let output = Command::new("route")
        .args(["-n", "get", dest])
        .output()
        .unwrap_or_else(|e| panic!("HARNESS: failed to spawn route -n get {dest}: {e}"));
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find_map(|l| l.trim().strip_prefix("interface: "))
        .map(str::to_owned)
}

// Config ==============================================================================================================

fn entry_from(ss: &SsServerHandle) -> ServerEntry {
    ServerEntry {
        id: "macos-full-tunnel-privileged-e2e".into(),
        name: "macos-full-tunnel-privileged-e2e".into(),
        server: ss.addr.ip().to_string().into(),
        server_port: ss.addr.port(),
        method: ss.method.into(),
        password: ss.password.clone(),
        plugin: ss.plugin.clone(),
        plugin_opts: ss.plugin_opts.clone(),
        validation: None,
    }
}

// The test ============================================================================================================

/// SHIP GATE (#893). Starts a real Full-mode session with DNS enabled
/// through the production `hole bridge run` subprocess, then asserts three
/// facts read from the OS, not from our return values: a live `utun` the OS
/// did not have before; the two IPv4 split routes (`0.0.0.0/1`, `128.0.0.0/1`)
/// leaving via that interface; and the configured resolver present in the
/// OS's own derived DNS configuration. Stops, then asserts all three are
/// gone and the machine's `nameserver[…]` set is back to its pre-start
/// value.
#[skuld::test(labels = [TUN, DIST_BIN, GLOBAL_NET_STATE], serial = TUN)]
fn e2e_macos_full_tunnel_installs_the_os_state_it_claims(
    #[fixture(dist_dir)] dist: &Path,
    #[fixture(ssserver_none)] ss: &SsServerHandle,
) {
    rt().block_on(run_macos_full_tunnel_os_state_e2e(dist, ss));
}

async fn run_macos_full_tunnel_os_state_e2e(dist: &Path, ss: &SsServerHandle) {
    let before_ifaces = ifconfig_list();
    let before_dns = scutil_dns();
    let before_nameservers = nameservers(&before_dns);
    println!("[macos_full_tunnel] before ifconfig -l: {before_ifaces:?}");
    println!("[macos_full_tunnel] before scutil --dns:\n{before_dns}");

    let local_port = allocate_ephemeral_port(Protocols::TCP | Protocols::UDP).await;
    let config = ProxyConfig {
        server: entry_from(ss),
        local_port,
        tunnel_mode: TunnelMode::Full,
        filters: Vec::new(),
        dns: DnsConfig::default(),
        proxy_socks5: true,
        proxy_http: false,
        local_port_http: 4074,
        diagnostic_plugin_tap: false,
    };
    let configured_servers: Vec<String> = config.dns.servers.iter().map(ToString::to_string).collect();

    let mut harness = DistHarness::spawn(dist).await.expect("HARNESS: spawn DistHarness");

    // Register for configd's change post BEFORE the mutating call, so the
    // settle below cannot miss the post it causes.
    let start_notify = DnsConfigNotify::register().expect("register for configd's dns_configuration notification");

    let resp = harness
        .send(BridgeRequest::Start {
            config,
            attempt_id: "macos-full-tunnel-os-state-e2e".into(),
            covered: false,
        })
        .await
        .expect("send Start");
    assert!(
        matches!(resp, BridgeResponse::Ack),
        "expected Ack from Start, got {resp:?}"
    );

    // (a) a live utun the OS did not have before.
    let after_start_ifaces = ifconfig_list();
    let created = new_utuns(&before_ifaces, &after_start_ifaces);
    let iface = match created.as_slice() {
        [one] => one.clone(),
        other => panic!(
            "expected exactly one new utun after Start, got {other:?} (before: {before_ifaces:?}, after: \
             {after_start_ifaces:?})"
        ),
    };
    println!("[macos_full_tunnel] new utun after Start: {iface}");

    // (b) the two IPv4 split routes leaving via that interface. Read via
    // `route -n get` on each split's own base address (see
    // `route_get_interface`'s doc for why), not via parsing the table
    // `netstat_inet` below prints for diagnostic context only.
    let low_half = route_get_interface("0.0.0.0");
    let high_half = route_get_interface("128.0.0.0");
    println!(
        "[macos_full_tunnel] netstat -rn -f inet after Start:\n{}",
        netstat_inet()
    );
    assert_eq!(
        low_half.as_deref(),
        Some(iface.as_str()),
        "expected route -n get 0.0.0.0 to answer '{iface}', got {low_half:?}"
    );
    assert_eq!(
        high_half.as_deref(),
        Some(iface.as_str()),
        "expected route -n get 128.0.0.0 to answer '{iface}', got {high_half:?}"
    );

    // (c) the configured resolver present in the OS's own derived DNS
    // configuration. Settle on configd's own post before reading.
    let merged = start_notify.settle(budget(30), &configured_servers[0], true);
    let dns_after_start = scutil_dns();
    println!(
        "[macos_full_tunnel] configd merged the configured resolver into the DNS configuration: {merged}\n{dns_after_start}"
    );
    for server in &configured_servers {
        assert!(
            dns_after_start.contains(server.as_str()),
            "expected scutil --dns to list configured resolver {server} after Start:\n{dns_after_start}"
        );
    }

    // Register a FRESH notification before the next mutating call (Stop).
    let stop_notify = DnsConfigNotify::register().expect("register for configd's dns_configuration notification");

    let resp = harness.send(BridgeRequest::Stop).await.expect("send Stop");
    assert!(
        matches!(resp, BridgeResponse::Ack),
        "expected Ack from Stop, got {resp:?}"
    );

    // All three facts must now be absent.
    let after_stop_ifaces = ifconfig_list();
    println!("[macos_full_tunnel] ifconfig -l after Stop: {after_stop_ifaces:?}");
    assert!(
        !after_stop_ifaces.contains(&iface),
        "expected {iface} to be gone from ifconfig -l after Stop, still present: {after_stop_ifaces:?}"
    );

    println!(
        "[macos_full_tunnel] netstat -rn -f inet after Stop:\n{}",
        netstat_inet()
    );
    let low_half_after_stop = route_get_interface("0.0.0.0");
    let high_half_after_stop = route_get_interface("128.0.0.0");
    assert_ne!(
        low_half_after_stop.as_deref(),
        Some(iface.as_str()),
        "expected route -n get 0.0.0.0 to no longer answer '{iface}' after Stop, got {low_half_after_stop:?}"
    );
    assert_ne!(
        high_half_after_stop.as_deref(),
        Some(iface.as_str()),
        "expected route -n get 128.0.0.0 to no longer answer '{iface}' after Stop, got {high_half_after_stop:?}"
    );

    let unmerged = stop_notify.settle(budget(30), &configured_servers[0], false);
    let dns_after_stop = scutil_dns();
    let after_nameservers = nameservers(&dns_after_stop);
    println!(
        "[macos_full_tunnel] configd's DNS configuration no longer lists the configured resolver: {unmerged}\n{dns_after_stop}"
    );
    for server in &configured_servers {
        assert!(
            !dns_after_stop.contains(server.as_str()),
            "expected scutil --dns to no longer list configured resolver {server} after Stop:\n{dns_after_stop}"
        );
    }
    assert_eq!(
        before_nameservers, after_nameservers,
        "expected the machine's nameserver[…] set to match its pre-start value after Stop; before:\n{before_nameservers:#?}\nafter:\n{after_nameservers:#?}"
    );

    println!(
        "\n========== macos_full_tunnel VERDICT ==========\n\
         utun created & removed  : {iface}\n\
         split routes installed  : true (removed after Stop)\n\
         resolver merged by configd: {merged}\n\
         resolver removal clean  : {unmerged}\n\
         ==================================================\n"
    );
}
