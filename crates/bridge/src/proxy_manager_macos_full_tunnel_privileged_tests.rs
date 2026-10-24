//! macOS-only privileged smoke test for a real Full-mode start.
//!
//! Every other Full-mode e2e in this crate (`proxy_manager_e2e_tests.rs`'s
//! `mod tun`, `proxy_manager_live_tun_permit_e2e_tests.rs`) is driven through
//! `BridgeRequest::Start`/`Stop` and then judges the session by dialing
//! sockets — never by asking the OS what it actually installed. Before this
//! file, no test on ANY platform asked: after a real Full-mode start, does
//! the OS's own interface list, routing table, and resolver configuration
//! actually show what Hole claims to have done? On macOS that question was
//! previously unanswerable at all — `TUN_DEVICE_NAME` didn't exist as
//! something `Dispatcher::new` could open, and `SystemDns::apply` was a silent no-op.
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
//! recomputation and can pass vacuously in either direction. The notification
//! and the resolver reads are shared with the tun-engine DNS tests
//! (`tun_engine::test_utils::{DnsConfigNotify, resolver_set}`).
//!
//! **The runner's own network is not under test.** The before and after resolver sets are read with
//! a control host answering around them (`tun_engine::test_utils::resolver_set`), and a Start that
//! fails is run through `egress::rerun_uncovered` with the same control: a lost network is waited out,
//! a failure with the network up is a defect. The control has no bypass route, so a failed Start that
//! leaves its split routes behind would starve it: the Hole-state read ([`held_state`]) counts those
//! routes as held, and a route it cannot read as held too, which makes that failure a defect at once
//! and never a wait.
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
#![allow(clippy::disallowed_methods)] // attended test: bare-name host tools

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::proxy::TUN_SUBNET;
use crate::test_support::dist_fixture::*;
use crate::test_support::dist_harness::DistHarness;
use crate::test_support::port_alloc::allocate_ephemeral_port;
use crate::test_support::rt;
use crate::test_support::skuld_fixtures::*;
use hole_common::config::{DnsConfig, ServerEntry};
use hole_common::protocol::{BridgeRequest, BridgeResponse, ProxyConfig, TunnelMode};
use hole_test_observability::egress;
use tun_engine::test_utils::{held_covers, nameservers, resolver_set, DnsConfigNotify, NETWORK_CONTROL};
use util::port_alloc::Protocols;

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

/// What Hole holds right now: a cover, or its split routes through its own TUN. The routes are read
/// from the kernel's lookup and attributed to Hole by the `utun` carrying `TUN_SUBNET`'s address.
fn held_state(state_dir: &Path) -> Option<String> {
    held_covers(state_dir).or_else(split_routes_held)
}

/// A split route that cannot be read counts as held, with the cause: left-behind routes starve the
/// control, so reading "nothing held" off a failed read would wait out a defect as a network loss.
fn split_routes_held() -> Option<String> {
    [SPLIT_LOW_PROBE, SPLIT_HIGH_PROBE].into_iter().find_map(|dest| {
        split_route_held(dest)
            .unwrap_or_else(|why| Some(format!("the split route covering {dest} could not be read: {why}")))
    })
}

fn split_route_held(dest: &str) -> Result<Option<String>, String> {
    let tun_addr = TUN_SUBNET.split('/').next().expect("TUN_SUBNET has an address part");
    let Some(iface) = route_lookup(dest)? else {
        return Ok(None);
    };
    if !iface.starts_with("utun") || !utun_address_held(&iface, tun_addr)? {
        return Ok(None);
    }
    Ok(Some(format!(
        "the split route covering {dest}, through Hole's TUN {iface}"
    )))
}

/// Whether `iface` currently holds `addr`, per `ifconfig <iface>`; `Err` when `ifconfig` could not answer.
fn utun_address_held(iface: &str, addr: &str) -> Result<bool, String> {
    let output = Command::new("ifconfig")
        .arg(iface)
        .output()
        .map_err(|e| format!("ifconfig {iface} could not be spawned: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "ifconfig {iface} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).lines().any(|line| {
        // `ifconfig` prints e.g. "	inet 10.255.0.1 netmask 0xffffff00 ..."
        let mut fields = line.split_whitespace();
        fields.next() == Some("inet") && fields.next() == Some(addr)
    }))
}

/// [`utun_address_held`] for a caller with no way to continue without the answer.
fn utun_holds_address(iface: &str, addr: &str) -> bool {
    utun_address_held(iface, addr).unwrap_or_else(|why| panic!("HARNESS: {why}"))
}

/// Every interface name `ifconfig -l` currently lists, in the order given.
///
/// Panics rather than yielding an empty list if `ifconfig` cannot be run: an
/// empty result is indistinguishable from "no interfaces", which would make
/// the before/after diff report zero new utuns and fail with a misleading
/// message about the tunnel instead of the missing tool.
fn ifconfig_list() -> Vec<String> {
    let output = Command::new("ifconfig")
        .arg("-l")
        .output()
        .expect("HARNESS: run `ifconfig -l`");
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .map(str::to_owned)
        .collect()
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

/// Ordinary addresses inside each IPv4 split, for [`route_get_interface`].
/// Deliberately not the `0.0.0.0` / `128.0.0.0` base addresses — see that
/// function's doc for why the base address answers the wrong question.
const SPLIT_LOW_PROBE: &str = "1.2.3.4";
const SPLIT_HIGH_PROBE: &str = "200.1.2.3";

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
/// `dest` must be an ordinary address *inside* a split — never the split's
/// own base address. macOS treats `route get 0.0.0.0` as a request for the
/// default route and answers with the physical interface even while
/// `0.0.0.0/1` is installed and winning for every real address in that
/// half, so probing the base address asks the wrong question and reports a
/// working tunnel as broken. Any ordinary member of the /1 block outranks
/// the machine's default route (`0.0.0.0/0`) by longest-prefix match once
/// the split is installed; when the split is absent (before Start, after
/// Stop) the lookup answers with whatever route already covers it
/// (typically the default), which the caller asserts differs from the TUN
/// interface.
fn route_get_interface(dest: &str) -> Option<String> {
    route_lookup(dest).unwrap_or_else(|why| panic!("HARNESS: {why}"))
}

/// [`route_get_interface`], with `Err` when `route(8)` could not answer. It exits 0 for a present and an
/// absent destination alike, so presence is its stdout's `interface:` line and absence its stderr's
/// `not in table` (as `tun_engine`'s own `prefix_route` reads it); anything else is no answer.
fn route_lookup(dest: &str) -> Result<Option<String>, String> {
    let output = Command::new("route")
        .args(["-n", "get", dest])
        .output()
        .map_err(|e| format!("route -n get {dest} could not be spawned: {e}"))?;
    if let Some(iface) = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|l| l.trim().strip_prefix("interface: "))
    {
        return Ok(Some(iface.to_owned()));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("not in table") {
        return Ok(None);
    }
    Err(format!(
        "route -n get {dest} reported neither an interface nor a confirmed absence (exit {}): {}",
        output.status,
        stderr.trim()
    ))
}

// Config ==============================================================================================================

fn entry_from(ss: &SsServerHandle) -> ServerEntry {
    ServerEntry {
        id: "macos-full-tunnel-privileged-e2e".into(),
        name: "macos-full-tunnel-privileged-e2e".into(),
        server: ss.addr.ip().to_string().into(),
        server_port: ss.addr.port(),
        method: ss.method.into(),
        password: ss.password.clone().into(),
        plugin: ss.plugin.clone(),
        plugin_opts: ss.plugin_opts.clone(),
        validation: None,
    }
}

// The test ============================================================================================================

/// Starts a real Full-mode session with DNS enabled
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
    // The harness's state directory does not exist yet; the oracle reads the OS (the live pf ruleset),
    // so a directory of its own names nothing.
    let early_dir = tempfile::tempdir().expect("HARNESS: tempdir for the cover oracle");
    let (before_dns, before_nameservers) = resolver_set("macos full tunnel: the resolver set before", &|| {
        held_state(early_dir.path())
    });
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
    let state_dir = harness.state_dir.path().to_path_buf();
    let held = || held_state(&state_dir);

    // Register for configd's change post BEFORE the mutating call, so the
    // settle below cannot miss the post it causes.
    let start_notify = DnsConfigNotify::register().expect("register for configd's dns_configuration notification");

    // A Full-mode Start needs the default route and an upstream, so it fails when the runner loses its
    // network.
    egress::rerun_uncovered("macos full tunnel: Start", NETWORK_CONTROL, &held, async || {
        let resp = harness
            .send(BridgeRequest::Start {
                config: config.clone(),
                attempt_id: "macos-full-tunnel-os-state-e2e".into(),
                on_startup: Some(hole_common::config::StartupBehavior::default()),
            })
            .await
            .expect("send Start");
        match resp {
            BridgeResponse::Ack => Ok(()),
            other => Err(format!("expected Ack from Start, got {other:?}")),
        }
    })
    .await
    .unwrap_or_else(|why| panic!("{why}"));

    // (a) a live utun the OS did not have before.
    let after_start_ifaces = ifconfig_list();
    let created = new_utuns(&before_ifaces, &after_start_ifaces);
    // Identify OURS positively rather than assuming we are the only thing
    // creating utuns: macOS makes them on its own (iCloud Private Relay, the
    // built-in VPN stack, Personal Hotspot), and this test's serialization
    // has no authority over the OS. Hole's TUN is the one carrying
    // `TUN_SUBNET`'s address.
    let tun_addr = TUN_SUBNET.split('/').next().expect("TUN_SUBNET has an address part");
    let mut ours: Vec<String> = created
        .iter()
        .filter(|iface| utun_holds_address(iface, tun_addr))
        .cloned()
        .collect();
    let iface = match ours.as_slice() {
        [_one] => ours.remove(0),
        [] => panic!(
            "no new utun holds {tun_addr}: new utuns {created:?} (before: {before_ifaces:?}, after: \
             {after_start_ifaces:?})"
        ),
        other => panic!("more than one new utun holds {tun_addr}, which should be impossible: {other:?}"),
    };
    println!("[macos_full_tunnel] new utun after Start: {iface}");

    // (b) the two IPv4 split routes leaving via that interface. Read via
    // `route -n get` on an ordinary address INSIDE each split — never the
    // split's base address, which macOS answers from the default route (see
    // `route_get_interface`'s doc) — not by parsing the table `netstat_inet`
    // below prints for diagnostic context only.
    let low_half = route_get_interface(SPLIT_LOW_PROBE);
    let high_half = route_get_interface(SPLIT_HIGH_PROBE);
    println!(
        "[macos_full_tunnel] netstat -rn -f inet after Start:\n{}",
        netstat_inet()
    );
    assert_eq!(
        low_half.as_deref(),
        Some(iface.as_str()),
        "expected route -n get {SPLIT_LOW_PROBE} to answer '{iface}', got {low_half:?}"
    );
    assert_eq!(
        high_half.as_deref(),
        Some(iface.as_str()),
        "expected route -n get {SPLIT_HIGH_PROBE} to answer '{iface}', got {high_half:?}"
    );

    // (c) the configured resolver present in the OS's own derived DNS
    // configuration. Settle on configd's own post before reading.
    let merged = start_notify.settle(budget(30), &configured_servers[0], true);
    let dns_after_start = scutil_dns();
    println!(
        "[macos_full_tunnel] configd merged the configured resolver into the DNS configuration: {merged}\n{dns_after_start}"
    );
    let after_start_nameservers = nameservers(&dns_after_start);
    for server in &configured_servers {
        assert!(
            dns_after_start.contains(server.as_str()),
            "expected scutil --dns to list configured resolver {server} after Start:\n{dns_after_start}"
        );
        // Presence alone proves nothing on a machine whose own resolver is
        // already this address — `DnsConfig::default()` is a public one. Where
        // the baseline did NOT list it, presence does prove Hole put it there,
        // so demand the stronger fact exactly where it is available.
        let was_in_baseline = before_nameservers.iter().any(|l| l.contains(server.as_str()));
        if !was_in_baseline {
            assert_ne!(
                before_nameservers, after_start_nameservers,
                "configured resolver {server} was absent before Start, so the nameserver set must have \
                 changed once it was steered; before:\n{before_nameservers:#?}\nafter:\n{after_start_nameservers:#?}"
            );
        }
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
    let low_half_after_stop = route_get_interface(SPLIT_LOW_PROBE);
    let high_half_after_stop = route_get_interface(SPLIT_HIGH_PROBE);
    assert_ne!(
        low_half_after_stop.as_deref(),
        Some(iface.as_str()),
        "expected route -n get {SPLIT_LOW_PROBE} to no longer answer '{iface}' after Stop, got {low_half_after_stop:?}"
    );
    assert_ne!(
        high_half_after_stop.as_deref(),
        Some(iface.as_str()),
        "expected route -n get {SPLIT_HIGH_PROBE} to no longer answer '{iface}' after Stop, got {high_half_after_stop:?}"
    );

    let unmerged = stop_notify.settle(budget(30), &configured_servers[0], false);
    let (dns_after_stop, after_nameservers) = resolver_set("macos full tunnel: the resolver set after Stop", &held);
    println!(
        "[macos_full_tunnel] configd's DNS configuration no longer lists the configured resolver: {unmerged}\n{dns_after_stop}"
    );
    // No substring check for the configured resolvers here: `DnsConfig::default()`
    // is a public resolver, so on a machine that already uses it the address is
    // still listed after Stop and a `!contains` assertion would fail against a
    // correct implementation. The baseline comparison below is the property that
    // actually matters — the machine is exactly where it started — and it holds
    // either way.
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
