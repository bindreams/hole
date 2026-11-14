//! macOS IPv6 address assignment, via `ifconfig`.
//!
//! A subprocess rather than FFI: `libc`'s Apple module has `in6_ifreq` but
//! neither `in6_aliasreq` nor `SIOCAIFADDR_IN6`, so FFI would mean
//! hand-defining a kernel struct and an ioctl number. `tun-engine` already
//! shells out on macOS for `route` and `pfctl`.
//!
//! **Failures warn and continue; on Windows they are fatal.** No test asserts
//! that the alias succeeds on a real macOS run, so a failure here is not yet
//! made fatal; the condition for making it fatal like Windows is that this path
//! has run green on the darwin TUN lane. [`Assigned::Ipv6StackAbsent`]
//! therefore means only "the alias did not take": macOS has no supported way to
//! unbind the IPv6 stack from an interface, so there is no appearance wait.
//!
//! `assign` logs the `ifconfig` argv before running it (`info`), then the
//! outcome with exit code, stdout and stderr (`info` on success, `warn` on
//! failure). On success it also reads back whether the prefix has a route, with
//! `route -n get -inet6` on an address inside the prefix other than the one
//! just aliased: an assigned address always has a host-scope local route, so
//! querying it would prove nothing. `route(8)` exits `0` unconditionally, so the
//! answer is read from its output text (see `crate::routing`'s
//! `macos_route_confirmed_absent`), never the exit code.
//!
//! Not measured or logged: how long duplicate address detection keeps the
//! address tentative. It is left enabled, and nothing on a TUN answers a probe,
//! so it always succeeds; the cost is first-flow latency, not correctness.

use smoltcp::wire::Ipv6Cidr;
use tracing::{info, warn};
use util::system_tool::SystemTool;

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

    let args = ifconfig_alias_args(&if_name, cidr);
    // The argv carries no PII (an interface name and the TUN's own CIDR), so it
    // needs no redaction.
    info!(interface = %if_name, cmd = SystemTool::Ifconfig.display_with(&args), "running ifconfig alias command");
    let output = match SystemTool::Ifconfig.command().and_then(|mut c| c.args(&args).output()) {
        Ok(output) => output,
        Err(e) => {
            warn!(interface = %if_name, error = &e as &dyn std::error::Error, "spawning ifconfig failed; no IPv6 address on the TUN");
            return Ok(Assigned::Ipv6StackAbsent);
        }
    };
    let exit_code = output.status.code();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.success() {
        // Whether the alias created the prefix route; see the module doc.
        let prefix_route = prefix_route(cidr);
        info!(
            interface = %if_name,
            address = %cidr.address(),
            exit = ?exit_code,
            stdout = %stdout.trim(),
            stderr = %stderr.trim(),
            prefix_route = %prefix_route,
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

/// The arguments `ifconfig` runs with; the program is always [`SystemTool::Ifconfig`].
pub(super) fn ifconfig_alias_args(if_name: &str, cidr: Ipv6Cidr) -> Vec<String> {
    vec![
        if_name.into(),
        "inet6".into(),
        cidr.address().to_string(),
        "prefixlen".into(),
        cidr.prefix_len().to_string(),
        "alias".into(),
    ]
}

/// What a kernel routing lookup said about `cidr`'s prefix.
enum PrefixRoute {
    /// The kernel routes an address inside the prefix via this interface.
    Via(String),
    /// route(8) positively reported no such route.
    Absent,
    /// The question could not be asked, or its answer could not be read.
    /// Deliberately distinct from [`PrefixRoute::Absent`]: that is a finding,
    /// this is the lack of one, and collapsing them would let a spawn failure
    /// read as evidence that the alias creates no prefix route.
    Indeterminate(&'static str),
}

impl std::fmt::Display for PrefixRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Via(interface) => write!(f, "via {interface}"),
            Self::Absent => f.write_str("absent"),
            Self::Indeterminate(why) => write!(f, "indeterminate ({why})"),
        }
    }
}

/// The interface serving `cidr`'s prefix, per a real kernel routing lookup —
/// [`PrefixRoute::Absent`] when no route answers for it. Queries [`probe_address_for`]'s
/// address, never `cidr.address()` itself: macOS always has a host-scope
/// local route for an address actually assigned to an interface, so probing
/// our own address would report an interface regardless of whether the wider
/// prefix route exists, proving nothing.
///
/// `route(8)` exits `0` unconditionally, so success is read from stdout's
/// `"interface: "` line and absence from stderr's `"not in table"` text, never
/// the exit code (as in `crate::routing::macos_route_confirmed_absent`).
/// Anything else is [`PrefixRoute::Indeterminate`] rather than absence.
fn prefix_route(cidr: Ipv6Cidr) -> PrefixRoute {
    let Some(probe) = probe_address_for(cidr) else {
        return PrefixRoute::Indeterminate("no address inside the prefix differs from the configured one");
    };
    let Ok(output) = SystemTool::Route
        .command()
        .and_then(|mut c| c.args(["-n", "get", "-inet6", &probe.to_string()]).output())
    else {
        return PrefixRoute::Indeterminate("route(8) could not be spawned");
    };
    if let Some(interface) = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface: ").map(str::to_owned))
    {
        return PrefixRoute::Via(interface);
    }
    if String::from_utf8_lossy(&output.stderr).contains("not in table") {
        return PrefixRoute::Absent;
    }
    PrefixRoute::Indeterminate("route(8) reported neither an interface nor a confirmed absence")
}

/// An address inside `cidr`'s prefix that is NOT `cidr.address()` — see
/// [`prefix_route`]'s doc for why that distinction matters. Uses the prefix's
/// network address (host bits cleared), or, when that is `cidr.address()`
/// itself, the address with its low bit flipped. `None` at `/128` (the prefix
/// holds one address) and at `/0` (its network address is the unspecified
/// address, which the default route answers).
fn probe_address_for(cidr: Ipv6Cidr) -> Option<std::net::Ipv6Addr> {
    let addr = cidr.address();
    let net = network_address(addr, cidr.prefix_len());
    if cidr.prefix_len() == 0 {
        return None;
    }
    if net != addr {
        return Some(net);
    }
    // The configured address is its own network address: flip the low bit.
    // At /128 that would leave the prefix, so there is no probe address.
    (cidr.prefix_len() < 128).then(|| std::net::Ipv6Addr::from(u128::from(net) ^ 1))
}

/// `addr` masked down to `prefix_len` leading bits, host bits cleared.
/// (smoltcp's own masking is on a `pub(crate)` trait.)
fn network_address(addr: std::net::Ipv6Addr, prefix_len: u8) -> std::net::Ipv6Addr {
    let bits = u128::from(addr);
    let mask = if prefix_len == 0 {
        0
    } else {
        !0u128 << (128 - u32::from(prefix_len))
    };
    std::net::Ipv6Addr::from(bits & mask)
}
