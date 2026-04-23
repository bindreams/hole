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
use std::time::Instant;

use super::AppliedAdapter;
use crate::dns_state::{AdapterId, DnsPrior, DnsPriorAdapter};

const NETSH: &str = "netsh";

// Public API ==========================================================================================================

/// Capture the v4+v6 DNS state of every adapter in `aliases`. Adapters
/// that don't exist (e.g. the TUN alias hasn't been created yet) are
/// silently skipped.
pub fn capture_adapters(aliases: &[String]) -> io::Result<Vec<DnsPriorAdapter>> {
    let started = Instant::now();
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
    tracing::debug!(
        aliases = aliases.len(),
        captured = out.len(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "capture_adapters"
    );
    Ok(out)
}

/// Apply `loopback_ip` as the DNS server on each adapter in `aliases`.
/// Returns one [`AppliedAdapter`] per adapter that was successfully set.
/// Callers flush the DNS cache separately (via [`flush_dns_cache`]) once
/// the full adapter list is applied.
pub fn apply_loopback(aliases: &[String], loopback_ip: IpAddr) -> io::Result<Vec<AppliedAdapter>> {
    let started = Instant::now();
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
    tracing::debug!(
        aliases = aliases.len(),
        applied = applied.len(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "apply_loopback"
    );
    Ok(applied)
}

/// Run `ipconfig /flushdns` as a **fire-and-forget** background
/// operation. Returns immediately; callers never block on the flush.
///
/// Why detached (Phase 4 #247): `ipconfig /flushdns` is notoriously slow
/// on Windows — often 1-5 seconds, and was a significant chunk of the
/// 11.3s apply stall observed in #247. Nothing downstream actually
/// depends on the flush having completed: the preceding `netsh set
/// dnsservers` has already invalidated the per-adapter cache for the
/// aliases we just changed. The OS-wide DNS client cache staleness
/// tradeoff is documented in the PR body.
///
/// Symmetry note: this is fire-and-forget on both setup (the
/// `apply_loopback` call path) and teardown (`RunningDns::drop` →
/// `super::restore_all`) sides. If one side blocked and the other
/// didn't, start would be fast while stop would be slow — inconsistent
/// from a UX perspective.
///
/// Uses `std::thread::spawn` rather than `tokio::task::spawn_blocking`
/// so callers need no runtime handle — `RunningDns::drop` is sync and
/// cannot reach a tokio runtime. The thread calls `Command::output()`,
/// which reaps the spawned `Child` on its own `Drop`, so no process
/// leak if the bridge exits before the flush returns.
///
/// The DEBUG `elapsed_ms` log is emitted from inside the spawned thread
/// so Phase 2 can still observe `ipconfig` wall-clock latency even
/// though the caller isn't blocked by it.
pub fn flush_dns_cache() {
    std::thread::spawn(|| {
        let started = Instant::now();
        let res = Command::new("ipconfig").arg("/flushdns").output();
        let elapsed_ms = started.elapsed().as_millis() as u64;
        match res {
            Ok(_) => tracing::debug!(elapsed_ms, "flush_dns_cache"),
            Err(e) => tracing::warn!(error = %e, elapsed_ms, "ipconfig /flushdns failed"),
        }
    });
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
    let started = Instant::now();
    let v4 = match show_dnsservers("ipv4", alias)? {
        Some(out) => parse_netsh_dnsservers(&out),
        None => {
            tracing::debug!(
                %alias,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "capture_one: adapter not found"
            );
            return Ok(None);
        }
    };
    let v6 = show_dnsservers("ipv6", alias)?.map(|o| parse_netsh_dnsservers(&o));
    tracing::debug!(
        %alias,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "capture_one"
    );
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
    let started = Instant::now();
    let output = Command::new(NETSH)
        .args(["interface", family, "show", "dnsservers"])
        .arg(format!("name={alias}"))
        .output()?;
    tracing::debug!(
        %alias,
        %family,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "show_dnsservers"
    );
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
    let started = Instant::now();
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
    tracing::debug!(
        %alias,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "set_dns_ipv4"
    );
    if !status.success() {
        return Err(io::Error::other(format!("netsh set dnsservers failed: {status}")));
    }
    Ok(())
}

fn set_dhcp_ipv4(alias: &str) -> io::Result<()> {
    let started = Instant::now();
    let status = Command::new(NETSH)
        .args(["interface", "ipv4", "set", "dnsservers"])
        .arg(format!("name={alias}"))
        .arg("dhcp")
        .status()?;
    tracing::debug!(
        %alias,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "set_dhcp_ipv4"
    );
    if !status.success() {
        return Err(io::Error::other(format!("netsh set dnsservers dhcp failed: {status}")));
    }
    Ok(())
}

fn add_dns_ipv4(alias: &str, ip: IpAddr, index: u32) -> io::Result<()> {
    let started = Instant::now();
    let status = Command::new(NETSH)
        .args(["interface", "ipv4", "add", "dnsservers"])
        .arg(format!("name={alias}"))
        .arg(ip.to_string())
        .arg(format!("index={index}"))
        .status()?;
    tracing::debug!(
        %alias,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "add_dns_ipv4"
    );
    if !status.success() {
        return Err(io::Error::other(format!("netsh add dnsservers failed: {status}")));
    }
    Ok(())
}

fn set_dns_ipv6(alias: &str, ip: Option<IpAddr>) -> io::Result<()> {
    let started = Instant::now();
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
    tracing::debug!(
        %alias,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "set_dns_ipv6"
    );
    if !status.success() {
        return Err(io::Error::other(format!("netsh set dnsservers v6 failed: {status}")));
    }
    Ok(())
}

fn set_dhcp_ipv6(alias: &str) -> io::Result<()> {
    let started = Instant::now();
    let status = Command::new(NETSH)
        .args(["interface", "ipv6", "set", "dnsservers"])
        .arg(format!("name={alias}"))
        .arg("dhcp")
        .status()?;
    tracing::debug!(
        %alias,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "set_dhcp_ipv6"
    );
    if !status.success() {
        return Err(io::Error::other(format!(
            "netsh set dnsservers v6 dhcp failed: {status}"
        )));
    }
    Ok(())
}

fn add_dns_ipv6(alias: &str, ip: IpAddr, index: u32) -> io::Result<()> {
    let started = Instant::now();
    let status = Command::new(NETSH)
        .args(["interface", "ipv6", "add", "dnsservers"])
        .arg(format!("name={alias}"))
        .arg(ip.to_string())
        .arg(format!("index={index}"))
        .status()?;
    tracing::debug!(
        %alias,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "add_dns_ipv6"
    );
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
