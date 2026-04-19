//! macOS `networksetup`-based system DNS capture / apply / restore.
//!
//! Identifier is the *network service* name (e.g. "Wi-Fi") as reported by
//! `networksetup -listallnetworkservices`. This is what the set/get DNS
//! subcommands accept directly, avoiding a separate name-to-GUID lookup
//! via `scutil`.

use std::io;
use std::net::IpAddr;
use std::process::Command;

use super::AppliedAdapter;
use crate::dns_state::{AdapterId, DnsPrior, DnsPriorAdapter};

const NETWORKSETUP: &str = "networksetup";

pub fn capture_adapters(services: &[String]) -> io::Result<Vec<DnsPriorAdapter>> {
    let mut out = Vec::with_capacity(services.len());
    for svc in services {
        match capture_one(svc) {
            Ok(Some(p)) => out.push(p),
            Ok(None) => {
                tracing::debug!(service = %svc, "DNS capture: service not found; skipping");
            }
            Err(e) => {
                tracing::warn!(service = %svc, error = %e, "DNS capture failed for service");
            }
        }
    }
    Ok(out)
}

pub fn apply_loopback(services: &[String], loopback_ip: IpAddr) -> io::Result<Vec<AppliedAdapter>> {
    let mut applied = Vec::with_capacity(services.len());
    for svc in services {
        if let Err(e) = set_dnsservers(svc, &[loopback_ip]) {
            tracing::warn!(service = %svc, error = %e, "DNS apply failed; continuing");
            continue;
        }
        applied.push(AppliedAdapter {
            id: AdapterId::MacosServiceName { value: svc.clone() },
            name_at_capture: svc.clone(),
        });
    }
    flush_dns_cache();
    Ok(applied)
}

/// Flush the macOS DNS cache (dscacheutil + mDNSResponder signal).
pub fn flush_dns_cache() {
    let _ = Command::new("dscacheutil").arg("-flushcache").status();
    let _ = Command::new("killall").args(["-HUP", "mDNSResponder"]).status();
}

pub fn platform_restore_adapter(adapter: &DnsPriorAdapter) -> io::Result<()> {
    let AdapterId::MacosServiceName { value: svc } = &adapter.id else {
        return Err(io::Error::other(format!(
            "expected MacosServiceName in DnsPriorAdapter.id, got {:?}",
            adapter.id
        )));
    };
    // macOS restores v4 and v6 via the same `setdnsservers` invocation —
    // it takes a mixed list. The captured v4/v6 priors must be merged
    // into a single list.
    let mut combined: Vec<IpAddr> = Vec::new();
    let mut saw_static = false;
    for p in [&adapter.v4, &adapter.v6] {
        if let DnsPrior::Static { servers } = p {
            saw_static = true;
            combined.extend_from_slice(servers);
        }
    }
    if saw_static {
        set_dnsservers(svc, &combined)
    } else {
        // Both v4 and v6 were DHCP or None — macOS collapses these to
        // `Empty`, which means "clear all DNS for this service, rely on
        // DHCP".
        clear_dnsservers(svc)
    }
}

fn capture_one(svc: &str) -> io::Result<Option<DnsPriorAdapter>> {
    let output = Command::new(NETWORKSETUP).args(["-getdnsservers", svc]).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("not a recognized network service") {
            return Ok(None);
        }
        return Err(io::Error::other(format!(
            "networksetup -getdnsservers failed: {} (stderr={})",
            output.status, stderr
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let (v4, v6) = split_v4_v6(parse_networksetup_output(&stdout));
    Ok(Some(DnsPriorAdapter {
        id: AdapterId::MacosServiceName { value: svc.to_string() },
        name_at_capture: svc.to_string(),
        v4,
        v6,
    }))
}

/// Parse the stdout of `networksetup -getdnsservers <svc>` into a
/// [`DnsPrior`]. Shapes:
///
/// ```text
/// There aren't any DNS Servers set on Wi-Fi.
/// ```
/// →  [`DnsPrior::Dhcp`] (macOS uses this exact phrasing for both
///     DHCP-assigned and unset; we cannot distinguish, so bias to Dhcp).
///
/// ```text
/// 1.1.1.1
/// 2606:4700:4700::1111
/// ```
/// → [`DnsPrior::Static`] with both IPs.
pub(super) fn parse_networksetup_output(stdout: &str) -> DnsPrior {
    let trimmed = stdout.trim();
    if trimmed.is_empty() || trimmed.to_ascii_lowercase().contains("aren't any dns servers") {
        return DnsPrior::Dhcp;
    }
    let mut servers: Vec<IpAddr> = Vec::new();
    for line in trimmed.lines() {
        if let Ok(ip) = line.trim().parse::<IpAddr>() {
            servers.push(ip);
        }
    }
    if servers.is_empty() {
        DnsPrior::Dhcp
    } else {
        DnsPrior::Static { servers }
    }
}

/// Split a combined IP list (as `networksetup` returns) into v4 and v6
/// [`DnsPrior`] records. DHCP/None collapses into both families.
fn split_v4_v6(combined: DnsPrior) -> (DnsPrior, DnsPrior) {
    match combined {
        DnsPrior::None => (DnsPrior::None, DnsPrior::None),
        DnsPrior::Dhcp => (DnsPrior::Dhcp, DnsPrior::Dhcp),
        DnsPrior::Static { servers } => {
            let (v4, v6): (Vec<_>, Vec<_>) = servers.into_iter().partition(|ip| ip.is_ipv4());
            let v4p = if v4.is_empty() {
                DnsPrior::None
            } else {
                DnsPrior::Static { servers: v4 }
            };
            let v6p = if v6.is_empty() {
                DnsPrior::None
            } else {
                DnsPrior::Static { servers: v6 }
            };
            (v4p, v6p)
        }
    }
}

fn set_dnsservers(svc: &str, ips: &[IpAddr]) -> io::Result<()> {
    let mut cmd = Command::new(NETWORKSETUP);
    cmd.arg("-setdnsservers").arg(svc);
    if ips.is_empty() {
        cmd.arg("Empty");
    } else {
        for ip in ips {
            cmd.arg(ip.to_string());
        }
    }
    let status = cmd.status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "networksetup -setdnsservers failed: {status}"
        )));
    }
    Ok(())
}

fn clear_dnsservers(svc: &str) -> io::Result<()> {
    set_dnsservers(svc, &[])
}
