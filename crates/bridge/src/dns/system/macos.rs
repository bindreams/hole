//! macOS `networksetup`-based system DNS apply / restore.
//!
//! Identifier is the *network service* name (e.g. "Wi-Fi") as reported by
//! `networksetup -listallnetworkservices`. This is what the set/get DNS
//! subcommands accept directly, avoiding a separate name-to-GUID lookup
//! via `scutil`.
//!
//! [`MacDnsBackend`] — the **inner test seam**, mirroring
//! [`super::windows::WinDnsBackend`] and the `Routing` precedent from
//! [bindreams/hole#165](https://github.com/bindreams/hole/issues/165).
//! Production goes through [`Networksetup`]; unit tests substitute
//! `MockMacBackend` via [`crate::dns::system::SystemDns::new_with_mac_backend`].
//! `get_settings` / `set_servers` / `restore` / `restore_family` are used
//! ONLY by `crate::dns::recovery`'s upgrade sweep now — `apply_macos` no
//! longer calls `set_servers` (refs #868; see
//! [`crate::dns::system`]'s module doc), because that identifier type is a
//! *service* name, and `apply_macos` was handing it `hole-tun`, an
//! *interface* name: a guaranteed no-op. It now steers DNS via
//! [`MacDnsSteerer`] instead.
//!
//! [`MacDnsSteerer`] / [`SteeringHandle`] — the apply-path seam, mirroring
//! [`super::windows::DnsConfiner`]'s shape but not its `Box<dyn Any + Send>`
//! erasure: `DnsApplied::shutdown` needs to *call* `withdraw`
//! (confirmable, not `Drop`-only — Decided-without-asking #6), not merely
//! hold and drop the guard. Production goes through [`RealMacDnsSteerer`],
//! backed by `tun_engine::dns_steer::engage`; unit tests substitute a mock
//! via [`crate::dns::system::SystemDns::new_with_mac_backend`].

use std::io;
use std::net::IpAddr;
use std::process::Command;

use crate::dns_state::{AdapterId, DnsPrior, DnsPriorAdapter};

const NETWORKSETUP: &str = "networksetup";

// MacDnsBackend trait =================================================================================================

/// The bridge-side macOS DNS backend.
///
/// Production [`Networksetup`] shells out to `networksetup`. Tests
/// substitute `MockMacBackend` via
/// [`crate::dns::system::SystemDns::new_with_mac_backend`].
///
/// **Send + Sync + 'static** so an `Arc<dyn MacDnsBackend>` can cross a
/// `tokio::task::spawn_blocking(move || …)` closure unchanged.
///
/// All methods are sync; the async apply loop in
/// [`crate::dns::system::SystemDns`] dispatches each call onto the
/// blocking pool so the subprocess never stalls a runtime worker.
pub trait MacDnsBackend: Send + Sync + 'static {
    /// Capture the v4 + v6 DNS state of `service`. Returns `Ok(None)`
    /// when the service does not exist; returns `Err` only on unexpected
    /// `networksetup` failures. Used only by the upgrade sweep now.
    fn get_settings(&self, service: &str) -> io::Result<Option<DnsPriorAdapter>>;

    /// Set the DNS resolvers on `service` to `servers`. `networksetup`
    /// accepts mixed v4/v6 lists in one call.
    fn set_servers(&self, service: &str, servers: &[IpAddr]) -> io::Result<()>;

    /// Restore BOTH families of the captured prior DNS state for
    /// `adapter` in a single `networksetup -setdnsservers` invocation.
    /// Used only by the upgrade sweep now, and only when both families'
    /// evidence supports a restore.
    fn restore(&self, adapter: &DnsPriorAdapter) -> io::Result<()>;

    /// Restore ONE family, preserving whatever is CURRENTLY live for the
    /// other. `networksetup` has no per-family API — both families share
    /// one combined list — so this reads the adapter's current settings
    /// first and merges. Used by the upgrade sweep's per-family evidence
    /// gate.
    fn restore_family(&self, service: &str, ipv6: bool, prior: &DnsPrior) -> io::Result<()>;

    /// Flush the macOS DNS cache (`dscacheutil -flushcache` +
    /// `killall -HUP mDNSResponder`). Best-effort; failures are logged
    /// but not returned.
    fn flush(&self) -> io::Result<()>;
}

// Networksetup ========================================================================================================

/// Production [`MacDnsBackend`] implementation. Stateless; methods
/// shell out to `networksetup`.
#[derive(Default, Debug, Clone, Copy)]
pub struct Networksetup;

impl MacDnsBackend for Networksetup {
    fn get_settings(&self, service: &str) -> io::Result<Option<DnsPriorAdapter>> {
        let output = Command::new(NETWORKSETUP).args(["-getdnsservers", service]).output()?;
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
            id: AdapterId::MacosServiceName {
                value: service.to_string(),
            },
            name_at_capture: service.to_string(),
            v4,
            v6,
        }))
    }

    fn set_servers(&self, service: &str, servers: &[IpAddr]) -> io::Result<()> {
        set_dnsservers(service, servers)
    }

    fn restore(&self, adapter: &DnsPriorAdapter) -> io::Result<()> {
        let AdapterId::MacosServiceName { value: svc } = &adapter.id else {
            return Err(io::Error::other(format!(
                "Networksetup::restore: expected MacosServiceName, got {:?}",
                adapter.id
            )));
        };
        // macOS restores v4 and v6 via the same `setdnsservers`
        // invocation — it takes a mixed list. The captured v4/v6 priors
        // must be merged.
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
            // Both v4 and v6 were DHCP or None — macOS collapses these
            // to `Empty`, which means "clear all DNS for this service,
            // rely on DHCP".
            clear_dnsservers(svc)
        }
    }

    fn restore_family(&self, service: &str, ipv6: bool, prior: &DnsPrior) -> io::Result<()> {
        // No per-family API on this platform: read the current combined
        // list, keep the OTHER family's CURRENT value untouched, and
        // replace only the family being restored.
        let current = self.get_settings(service)?;
        let (mut v4, mut v6) = match current {
            Some(adapter) => (adapter.v4, adapter.v6),
            None => (DnsPrior::None, DnsPrior::None),
        };
        if ipv6 {
            v6 = prior.clone();
        } else {
            v4 = prior.clone();
        }
        let mut combined: Vec<IpAddr> = Vec::new();
        let mut saw_static = false;
        for p in [&v4, &v6] {
            if let DnsPrior::Static { servers } = p {
                saw_static = true;
                combined.extend_from_slice(servers);
            }
        }
        if saw_static {
            set_dnsservers(service, &combined)
        } else {
            clear_dnsservers(service)
        }
    }

    fn flush(&self) -> io::Result<()> {
        // Fire-and-forget the cache flush. `dscacheutil` is fast; the
        // SIGHUP to mDNSResponder is a courtesy notification.
        let _ = Command::new("dscacheutil").arg("-flushcache").status();
        let _ = Command::new("killall").args(["-HUP", "mDNSResponder"]).status();
        Ok(())
    }
}

// Helpers =============================================================================================================

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

// MacDnsSteerer / SteeringHandle ======================================================================================

/// The bridge-side seam over `tun_engine::dns_steer::engage`. Production
/// [`RealMacDnsSteerer`] calls it directly; unit tests substitute a mock so
/// `SystemDns::apply`'s cancel / routed-family / error handling is
/// testable without a real `SCDynamicStore` session. See the module doc.
pub trait MacDnsSteerer: Send + Sync + 'static {
    /// Publish the supplemental resolver key for `servers` — see
    /// `tun_engine::dns_steer::engage`.
    fn engage(&self, servers: &[IpAddr]) -> io::Result<Box<dyn SteeringHandle>>;
}

/// Guard for the engaged DNS steering. `withdraw` is confirmable — it
/// consumes the box, so it can only be called once. `Drop` on the
/// concrete production type is the crash/unwind fallback — see
/// `tun_engine::dns_steer::Steering`'s own doc.
pub trait SteeringHandle: Send {
    fn withdraw(self: Box<Self>) -> io::Result<()>;
}

/// Production [`MacDnsSteerer`]. Stateless; calls
/// `tun_engine::dns_steer::engage` directly.
#[derive(Default, Debug, Clone, Copy)]
pub struct RealMacDnsSteerer;

impl MacDnsSteerer for RealMacDnsSteerer {
    fn engage(&self, servers: &[IpAddr]) -> io::Result<Box<dyn SteeringHandle>> {
        tun_engine::dns_steer::engage(servers)
            .map(|s| Box::new(s) as Box<dyn SteeringHandle>)
            .map_err(io::Error::other)
    }
}

impl SteeringHandle for tun_engine::dns_steer::Steering {
    fn withdraw(self: Box<Self>) -> io::Result<()> {
        // Move the guard out of the box so its by-value inherent
        // `withdraw` (not this trait method — inherent methods win method
        // resolution) can run.
        let inner = *self;
        let key = inner.key().to_string();
        inner.withdraw().map_err(|e| {
            tracing::warn!(key = %key, error = %e, "dns_steer: withdraw failed");
            io::Error::other(e)
        })
    }
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;
