//! macOS IPv6 address assignment, via `ifconfig`.
//!
//! Everything asserted here about runtime behaviour is **reasoned, not
//! measured**: this path could not run in production before bindreams/hole#850
//! (the `tun` crate rejects any macOS device name not starting with `utun`,
//! so `Dispatcher::new` failed before a device existed), and still cannot be
//! built on the maintainer's box. #850 fixes the naming half of that
//! blocker; whether this specific path has since run green on the darwin TUN
//! lane is a separate, still-open fact — `proxy_manager_macos_full_tunnel_privileged_tests.rs`'s
//! Full-mode start exercises this code as a side effect but asserts nothing
//! about it, so its first real run must be read from that test's own CI
//! logs, not assumed from this file.
//!
//! A subprocess rather than FFI: `libc`'s Apple module has `in6_ifreq` but
//! neither `in6_aliasreq` nor `SIOCAIFADDR_IN6`, so an FFI path would mean
//! hand-defining a kernel struct and an ioctl number that nothing here can
//! compile or run. `tun-engine` already shells out on macOS for `route` and
//! `pfctl`.
//!
//! **Failures warn and continue; on Windows they are fatal.** The asymmetry is
//! deliberate, and the condition for removing it is: once this path has run
//! green on the darwin TUN lane, make it fatal like Windows. That condition
//! has not fired yet — the naming fix landing is necessary but not
//! sufficient, since no test asserts success on this path. Until it does, a
//! fatal failure here would first execute in a user's hands. `Ipv6StackAbsent`
//! consequently means only "the alias did not take": macOS has no supported
//! way to unbind the IPv6 stack from an interface, so there is no appearance
//! wait and nothing else it could mean.
//!
//! Two open items:
//!
//! - **Duplicate address detection is left enabled and its cost is
//!   unmeasured.** Nothing on a TUN answers a DAD probe, so it always
//!   succeeds; the only question is how long the address stays tentative, which
//!   costs first-flow latency rather than correctness.
//! - **The alias may not create a prefix route.** wg-quick-style Darwin setups
//!   add the prefix route explicitly after the alias, which suggests it does
//!   not follow from the alias — the same open question as the Windows
//!   `OnLinkPrefixLength` measurement.
//!
//! `assign` logs its `ifconfig` invocation and outcome the same way
//! `routing.rs`'s route runner logs a route command: the argv before it
//! runs (`info`, so a passing darwin-lane run always shows it, not only on
//! an investigation's `debug` level — this call is one-shot per session,
//! not per-packet, so it does not carry the route runner's volume
//! concern), then the outcome with the full exit code, stdout, and stderr
//! (`info` on success, `warn` on failure, matching the asymmetry
//! documented above).
//!
//! On success, it additionally reads back whether the prefix now has a
//! route, via `route -n get -inet6` on an address inside the prefix that is
//! NOT the one just aliased (querying our own address would hit macOS's
//! always-present host-scope local route regardless of whether the wider
//! prefix route exists, which would prove nothing). This is the same
//! real-kernel-lookup technique `proxy_manager_macos_full_tunnel_privileged_tests.rs`'s
//! `route_get_interface` uses for the IPv4 splits, for the same reason: `route(8)`
//! exits `0` unconditionally, so success/absence is read from stderr text
//! (`crate::routing`'s `macos_route_confirmed_absent` convention), never the
//! exit code. This answers the second open item above directly, on every
//! passing run — not by inference.
//!
//! The first open item — DAD's cost — is still NOT measured or logged
//! anywhere in this file. Answering it means observing the address's
//! `tentative` flag clear over time, which this module does not yet do:
//! unlike the prefix-route check above, the exact text `ifconfig` prints for
//! that flag is not confirmed against a real DAD-tentative window on any
//! host available to this change (the man page on this box does not spell
//! it out, and there is no root here to force a real conflict and observe
//! it), so no polling was added on an unverified guess. That gap is
//! unresolved, not silently closed.

use std::process::Command;

use smoltcp::wire::Ipv6Cidr;
use tracing::{info, warn};

use super::Assigned;
use crate::error::DeviceError;

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;

pub(super) fn assign(if_index: u32, cidr: Ipv6Cidr) -> Result<Assigned, DeviceError> {
    let Some(if_name) = interface_name(if_index) else {
        warn!(
            if_index,
            "if_indextoname failed; the TUN interface holds no IPv6 address"
        );
        return Ok(Assigned::Ipv6StackAbsent);
    };

    let argv = ifconfig_alias_argv(&if_name, cidr);
    // Logged before spawning, same as `routing.rs`'s `log_route_command`:
    // the argv carries no PII (an interface name and a link-local-scoped
    // CIDR), so it needs no redaction and no separate extraction point.
    info!(interface = %if_name, cmd = argv.join(" "), "running ifconfig alias command");
    let output = match Command::new(&argv[0]).args(&argv[1..]).output() {
        Ok(output) => output,
        Err(e) => {
            warn!(interface = %if_name, error = %e, "spawning ifconfig failed; no IPv6 address on the TUN");
            return Ok(Assigned::Ipv6StackAbsent);
        }
    };
    let exit_code = output.status.code();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.success() {
        // Answers "did the alias succeed" AND "did the alias create the
        // prefix route" (two of the three open items above) — DAD's cost is
        // the one this still does not speak to; see the module doc.
        let prefix_route_interface = prefix_route_interface(cidr);
        info!(
            interface = %if_name,
            address = %cidr.address(),
            exit = ?exit_code,
            stdout = %stdout.trim(),
            stderr = %stderr.trim(),
            prefix_route_interface = ?prefix_route_interface,
            "ifconfig alias succeeded; the TUN interface holds an IPv6 address"
        );
        return Ok(Assigned::Address);
    }

    warn!(
        interface = %if_name,
        exit = ?exit_code,
        stdout = %stdout.trim(),
        stderr = %stderr.trim(),
        "ifconfig alias failed; the TUN interface holds no IPv6 address"
    );
    Ok(Assigned::Ipv6StackAbsent)
}

/// The interface's kernel-assigned name, or `None` when the lookup fails.
fn interface_name(if_index: u32) -> Option<String> {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: `buf` is exactly the IF_NAMESIZE bytes `if_indextoname` requires.
    if unsafe { libc::if_indextoname(if_index, buf.as_mut_ptr()) }.is_null() {
        return None;
    }
    // SAFETY: on success the buffer holds a NUL-terminated interface name.
    Some(
        unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
            .to_string_lossy()
            .into_owned(),
    )
}

pub(super) fn ifconfig_alias_argv(if_name: &str, cidr: Ipv6Cidr) -> Vec<String> {
    vec![
        "ifconfig".into(),
        if_name.into(),
        "inet6".into(),
        cidr.address().to_string(),
        "prefixlen".into(),
        cidr.prefix_len().to_string(),
        "alias".into(),
    ]
}

/// The interface serving `cidr`'s prefix, per a real kernel routing lookup —
/// `None` when no route answers for it. Queries [`probe_address_for`]'s
/// address, never `cidr.address()` itself: macOS always has a host-scope
/// local route for an address actually assigned to an interface, so probing
/// our own address would report an interface regardless of whether the wider
/// prefix route exists, proving nothing.
///
/// `route(8)` exits `0` unconditionally (confirmed live on this host, both
/// for a present and an absent destination — see the module doc), so success
/// is read from stdout's `"interface: "` line and absence from stderr's
/// `"not in table"` text, mirroring `crate::routing`'s
/// `macos_route_confirmed_absent` convention — never the exit code.
fn prefix_route_interface(cidr: Ipv6Cidr) -> Option<String> {
    let probe = probe_address_for(cidr).to_string();
    let output = Command::new("route")
        .args(["-n", "get", "-inet6", &probe])
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface: ").map(str::to_owned))
}

/// An address inside `cidr`'s prefix that is NOT `cidr.address()` — see
/// [`prefix_route_interface`]'s doc for why that distinction matters. Uses
/// the prefix's network address (all host bits cleared); on the vanishingly
/// unlikely chance that address instance equals `cidr.address()` (only
/// possible if the configured address's own host part is already
/// all-zero), the low bit is flipped instead — still inside the prefix
/// (`prefix_len` `128` aside, which this crate never configures; see
/// `TUN_SUBNET6`), still not the configured address.
fn probe_address_for(cidr: Ipv6Cidr) -> std::net::Ipv6Addr {
    let addr = cidr.address();
    let net = network_address(addr, cidr.prefix_len());
    if net != addr {
        net
    } else {
        std::net::Ipv6Addr::from(u128::from(net) ^ 1)
    }
}

/// `addr` masked down to `prefix_len` leading bits, host bits cleared.
/// Reimplemented here rather than via smoltcp's own `Cidr` masking because
/// that logic lives on a `pub(crate)` trait of smoltcp's, not reachable from
/// this crate.
fn network_address(addr: std::net::Ipv6Addr, prefix_len: u8) -> std::net::Ipv6Addr {
    let bits = u128::from(addr);
    let mask = if prefix_len == 0 {
        0
    } else {
        !0u128 << (128 - u32::from(prefix_len))
    };
    std::net::Ipv6Addr::from(bits & mask)
}
