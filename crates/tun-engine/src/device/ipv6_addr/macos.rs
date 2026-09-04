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

use std::process::Command;

use smoltcp::wire::Ipv6Cidr;
use tracing::warn;

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
    let output = match Command::new(&argv[0]).args(&argv[1..]).output() {
        Ok(output) => output,
        Err(e) => {
            warn!(interface = %if_name, error = %e, "spawning ifconfig failed; no IPv6 address on the TUN");
            return Ok(Assigned::Ipv6StackAbsent);
        }
    };
    if output.status.success() {
        return Ok(Assigned::Address);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    warn!(
        interface = %if_name,
        exit = ?output.status.code(),
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
