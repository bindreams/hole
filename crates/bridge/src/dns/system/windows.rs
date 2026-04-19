//! Windows `netsh`-based system DNS capture / apply / restore.
//!
//! Shelling out rather than calling `SetInterfaceDnsSettings` directly is
//! deliberate: `netsh` output is forward-compatible and the equivalent
//! Win32 API has a narrow Windows-version window. The existing routing
//! layer also uses `netsh`, so we match that convention.
//!
//! ## Command surface
//!
//! - **Capture**: `netsh interface {ipv4,ipv6} show dnsservers name="<alias>"`
//!   parses into [`DnsPrior::Static`], [`DnsPrior::Dhcp`], or
//!   [`DnsPrior::None`].
//! - **Apply**: `netsh interface ipv4 set dnsservers name="<alias>" static
//!   <ip> primary` (plus `ipconfig /flushdns` after).
//! - **Restore**: dispatches on the captured variant.

use std::io;
use std::net::IpAddr;
use std::process::Command;

use super::AppliedAdapter;
use crate::dns_state::{AdapterId, DnsPrior, DnsPriorAdapter};

const NETSH: &str = "netsh";

// Public API ==========================================================================================================

/// Capture the v4+v6 DNS state of every adapter in `aliases`. Adapters
/// that don't exist (e.g. the TUN alias hasn't been created yet) are
/// silently skipped.
pub fn capture_adapters(aliases: &[String]) -> io::Result<Vec<DnsPriorAdapter>> {
    let mut out = Vec::with_capacity(aliases.len());
    for alias in aliases {
        match capture_one(alias) {
            Ok(Some(p)) => out.push(p),
            Ok(None) => {
                tracing::debug!(%alias, "DNS capture: adapter not found; skipping");
            }
            Err(e) => {
                tracing::warn!(%alias, error = %e, "DNS capture failed for adapter");
            }
        }
    }
    Ok(out)
}

/// Apply `loopback_ip` as the DNS server on each adapter in `aliases`.
/// Returns one [`AppliedAdapter`] per adapter that was successfully set.
/// Callers flush the DNS cache separately (via [`flush_dns_cache`]) once
/// the full adapter list is applied.
pub fn apply_loopback(aliases: &[String], loopback_ip: IpAddr) -> io::Result<Vec<AppliedAdapter>> {
    let mut applied = Vec::with_capacity(aliases.len());
    for alias in aliases {
        if let Err(e) = set_dns_ipv4(alias, Some(loopback_ip)) {
            tracing::warn!(%alias, error = %e, "DNS apply failed; continuing");
            continue;
        }
        applied.push(AppliedAdapter {
            id: AdapterId::WindowsAlias { value: alias.clone() },
            name_at_capture: alias.clone(),
        });
    }
    flush_dns_cache();
    Ok(applied)
}

/// Run `ipconfig /flushdns`. Best-effort; a failure here is a log line,
/// not a return value.
pub fn flush_dns_cache() {
    let res = Command::new("ipconfig").arg("/flushdns").output();
    if let Err(e) = res {
        tracing::warn!(error = %e, "ipconfig /flushdns failed");
    }
}

/// Restore one adapter. Invoked from [`super::restore_all`].
pub fn platform_restore_adapter(adapter: &DnsPriorAdapter) -> io::Result<()> {
    let AdapterId::WindowsAlias { value: alias } = &adapter.id else {
        return Err(io::Error::other(format!(
            "expected WindowsAlias in DnsPriorAdapter.id, got {:?}",
            adapter.id
        )));
    };
    restore_v4(alias, &adapter.v4)?;
    restore_v6(alias, &adapter.v6)?;
    Ok(())
}

// Capture =============================================================================================================

fn capture_one(alias: &str) -> io::Result<Option<DnsPriorAdapter>> {
    let v4 = match show_dnsservers("ipv4", alias)? {
        Some(out) => parse_netsh_dnsservers(&out),
        None => return Ok(None),
    };
    let v6 = show_dnsservers("ipv6", alias)?.map(|o| parse_netsh_dnsservers(&o));
    Ok(Some(DnsPriorAdapter {
        id: AdapterId::WindowsAlias {
            value: alias.to_string(),
        },
        name_at_capture: alias.to_string(),
        v4,
        v6: v6.unwrap_or(DnsPrior::None),
    }))
}

fn show_dnsservers(family: &str, alias: &str) -> io::Result<Option<String>> {
    let output = Command::new(NETSH)
        .args(["interface", family, "show", "dnsservers"])
        .arg(format!("name={alias}"))
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // netsh emits "The system cannot find the file specified." on a
        // nonexistent alias; treat that as "adapter not found" not error.
        if stderr.contains("cannot find") || stderr.contains("not found") {
            return Ok(None);
        }
        return Err(io::Error::other(format!(
            "netsh show dnsservers failed: {} (stderr={})",
            output.status, stderr
        )));
    }
    Ok(Some(String::from_utf8_lossy(&output.stdout).to_string()))
}

/// Parse `netsh interface {ipv4,ipv6} show dnsservers name=...` output
/// into a [`DnsPrior`]. The expected shapes (English Windows) are:
///
/// ```text
/// Configuration for interface "Ethernet"
///     Statically Configured DNS Servers:  1.1.1.1
///                                         8.8.8.8
///     Register with which suffix:         Primary only
/// ```
/// or
/// ```text
/// Configuration for interface "Ethernet"
///     DNS servers configured through DHCP:  192.168.1.1
///     Register with which suffix:           Primary only
/// ```
/// or
/// ```text
///     DNS servers configured through DHCP:  None
/// ```
///
/// Localized Windows installs produce different strings and will be
/// misparsed. The feature is opt-in and the failure mode is "we don't
/// know the prior state; treat as Dhcp" — covered by defaulting.
pub(super) fn parse_netsh_dnsservers(stdout: &str) -> DnsPrior {
    let mut kind: Option<&'static str> = None;
    let mut ips: Vec<IpAddr> = Vec::new();

    for raw_line in stdout.lines() {
        let line = raw_line.trim();
        if line.starts_with("Statically Configured DNS Servers") {
            kind = Some("static");
            // Use the *first* colon only — IPv6 addresses contain colons
            // too, so `split(':')` would truncate them.
            if let Some(rhs) = line.find(':').map(|idx| line[idx + 1..].trim()) {
                if let Ok(ip) = rhs.parse::<IpAddr>() {
                    ips.push(ip);
                }
            }
            continue;
        }
        if line.starts_with("DNS servers configured through DHCP") {
            kind = Some("dhcp");
            if let Some(rhs) = line.find(':').map(|idx| line[idx + 1..].trim().to_string()) {
                if rhs.eq_ignore_ascii_case("none") {
                    kind = Some("none");
                } else if let Ok(ip) = rhs.parse::<IpAddr>() {
                    ips.push(ip);
                }
            }
            continue;
        }
        // Continuation line: a raw IP on its own line (the netsh layout
        // aligns multiple IPs under the first column). Only append if the
        // line parses cleanly.
        if let Ok(ip) = line.parse::<IpAddr>() {
            ips.push(ip);
        }
    }

    match kind {
        Some("static") => {
            if ips.is_empty() {
                DnsPrior::None
            } else {
                DnsPrior::Static { servers: ips }
            }
        }
        Some("dhcp") => DnsPrior::Dhcp,
        Some("none") | None => DnsPrior::None,
        Some(_) => DnsPrior::None,
    }
}

// Apply ===============================================================================================================

fn set_dns_ipv4(alias: &str, ip: Option<IpAddr>) -> io::Result<()> {
    let mut cmd = Command::new(NETSH);
    cmd.args(["interface", "ipv4", "set", "dnsservers"])
        .arg(format!("name={alias}"));
    match ip {
        Some(ip) => {
            cmd.arg("static").arg(ip.to_string()).arg("primary");
        }
        None => {
            cmd.arg("static").arg("none");
        }
    }
    let status = cmd.status()?;
    if !status.success() {
        return Err(io::Error::other(format!("netsh set dnsservers failed: {status}")));
    }
    Ok(())
}

fn set_dhcp_ipv4(alias: &str) -> io::Result<()> {
    let status = Command::new(NETSH)
        .args(["interface", "ipv4", "set", "dnsservers"])
        .arg(format!("name={alias}"))
        .arg("dhcp")
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!("netsh set dnsservers dhcp failed: {status}")));
    }
    Ok(())
}

fn add_dns_ipv4(alias: &str, ip: IpAddr, index: u32) -> io::Result<()> {
    let status = Command::new(NETSH)
        .args(["interface", "ipv4", "add", "dnsservers"])
        .arg(format!("name={alias}"))
        .arg(ip.to_string())
        .arg(format!("index={index}"))
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!("netsh add dnsservers failed: {status}")));
    }
    Ok(())
}

fn set_dns_ipv6(alias: &str, ip: Option<IpAddr>) -> io::Result<()> {
    let mut cmd = Command::new(NETSH);
    cmd.args(["interface", "ipv6", "set", "dnsservers"])
        .arg(format!("name={alias}"));
    match ip {
        Some(ip) => {
            cmd.arg("static").arg(ip.to_string()).arg("primary");
        }
        None => {
            cmd.arg("static").arg("none");
        }
    }
    let status = cmd.status()?;
    if !status.success() {
        return Err(io::Error::other(format!("netsh set dnsservers v6 failed: {status}")));
    }
    Ok(())
}

fn set_dhcp_ipv6(alias: &str) -> io::Result<()> {
    let status = Command::new(NETSH)
        .args(["interface", "ipv6", "set", "dnsservers"])
        .arg(format!("name={alias}"))
        .arg("dhcp")
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "netsh set dnsservers v6 dhcp failed: {status}"
        )));
    }
    Ok(())
}

fn add_dns_ipv6(alias: &str, ip: IpAddr, index: u32) -> io::Result<()> {
    let status = Command::new(NETSH)
        .args(["interface", "ipv6", "add", "dnsservers"])
        .arg(format!("name={alias}"))
        .arg(ip.to_string())
        .arg(format!("index={index}"))
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!("netsh add dnsservers v6 failed: {status}")));
    }
    Ok(())
}

// Restore =============================================================================================================

fn restore_v4(alias: &str, prior: &DnsPrior) -> io::Result<()> {
    match prior {
        DnsPrior::None => set_dns_ipv4(alias, None),
        DnsPrior::Dhcp => set_dhcp_ipv4(alias),
        DnsPrior::Static { servers } => {
            let mut iter = servers.iter();
            if let Some(first) = iter.next() {
                set_dns_ipv4(alias, Some(*first))?;
                for (i, s) in iter.enumerate() {
                    add_dns_ipv4(alias, *s, (i + 2) as u32)?;
                }
                Ok(())
            } else {
                set_dns_ipv4(alias, None)
            }
        }
    }
}

fn restore_v6(alias: &str, prior: &DnsPrior) -> io::Result<()> {
    match prior {
        DnsPrior::None => set_dns_ipv6(alias, None),
        DnsPrior::Dhcp => set_dhcp_ipv6(alias),
        DnsPrior::Static { servers } => {
            let mut iter = servers.iter();
            if let Some(first) = iter.next() {
                set_dns_ipv6(alias, Some(*first))?;
                for (i, s) in iter.enumerate() {
                    add_dns_ipv6(alias, *s, (i + 2) as u32)?;
                }
                Ok(())
            } else {
                set_dns_ipv6(alias, None)
            }
        }
    }
}
