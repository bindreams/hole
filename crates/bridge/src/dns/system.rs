//! System DNS capture/apply/restore.
//!
//! The bridge re-points OS DNS clients at the `LocalDnsServer` loopback IP
//! while a proxy is running, then restores the prior per-adapter / per-
//! address-family DNS configuration on clean shutdown or crash recovery.
//!
//! ## Per-adapter, per-family, three prior kinds
//!
//! Each adapter carries two independent DNS lists (v4, v6); each list is
//! in one of three states — static, DHCP-assigned, or unset. The restore
//! path dispatches on the captured [`DnsPrior`] variant so a prior that
//! was DHCP-assigned doesn't get reapplied as a static list (which would
//! freeze DHCP renewal).
//!
//! ## Which adapters?
//!
//! Capture targets two adapters: the TUN adapter (we want the best-route
//! resolver lookup to land here so the OS picks *our* DNS) and the
//! upstream physical adapter (defense in depth against multi-homed
//! resolvers). Apply sets the same loopback on both. Restore replays the
//! captured state per adapter.
//!
//! ## Platform implementations
//!
//! - **Windows** — `netsh interface {ipv4,ipv6} {show,set} dnsservers`.
//!   Adapter identity is the LUID (stable for physical adapters across
//!   reboots; the TUN adapter is recreated per-connect so its LUID is
//!   fresh each time).
//! - **macOS** — `networksetup -{getdnsservers,setdnsservers}`. Adapter
//!   identity is the service name (e.g. "Wi-Fi"). Service names are
//!   reasonably stable across short periods; a user who renames a
//!   service mid-session will see that service skipped on restore.

use std::io;

use crate::dns_state::{AdapterId, DnsPriorAdapter};

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

/// One applied DNS change, returned so a rollback on partial failure can
/// restore exactly what was touched. Production code persists
/// `Vec<DnsPriorAdapter>` to `bridge-dns.json` and feeds it to
/// [`restore_all`] on shutdown.
#[derive(Debug, Clone)]
pub struct AppliedAdapter {
    pub id: AdapterId,
    pub name_at_capture: String,
}

/// Restore all adapters listed in `prior`. Each adapter is restored
/// independently — one failure is logged and the rest proceed. This
/// matches the crash-recovery contract (best-effort).
pub fn restore_all(prior: &[DnsPriorAdapter]) -> Vec<(AdapterId, io::Error)> {
    let mut errors = Vec::new();
    for adapter in prior {
        if let Err(e) = restore_adapter(adapter) {
            tracing::warn!(
                id = ?adapter.id,
                name = %adapter.name_at_capture,
                error = %e,
                "DNS restore failed for adapter; continuing"
            );
            errors.push((adapter.id.clone(), e));
        }
    }
    errors
}

/// Summary of the DNS state that was in effect before `apply` ran. The
/// caller persists this (via `dns_state::save`) and feeds it to
/// [`restore_all`] on shutdown or crash recovery.
#[derive(Debug, Clone)]
pub struct PriorSnapshot {
    pub adapters: Vec<DnsPriorAdapter>,
}

impl PriorSnapshot {
    pub fn empty() -> Self {
        Self { adapters: Vec::new() }
    }
}

/// Dispatch a single adapter's restore to the platform implementation.
/// The concrete function lives in `windows.rs` / `macos.rs`; this wrapper
/// keeps the error type uniform across platforms and is usable from
/// non-platform-gated callers.
fn restore_adapter(adapter: &DnsPriorAdapter) -> io::Result<()> {
    platform_restore_adapter(adapter)
}

// Placeholder when building on an unsupported platform — keeps the
// module's surface area compilable for test-only targets like `cargo
// check` on Linux in CI. The bridge is only shipped for Windows and
// macOS so this branch never runs in production.
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn platform_restore_adapter(_adapter: &DnsPriorAdapter) -> io::Result<()> {
    Err(io::Error::other("system DNS restore not implemented on this target OS"))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn capture_adapters(_aliases: &[String]) -> io::Result<Vec<DnsPriorAdapter>> {
    Err(io::Error::other("system DNS capture not implemented on this target OS"))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn apply_loopback(_aliases: &[String], _loopback_ip: std::net::IpAddr) -> io::Result<Vec<AppliedAdapter>> {
    Err(io::Error::other("system DNS apply not implemented on this target OS"))
}

// Re-export DnsPrior helpers so callers don't need a separate import just
// for the "construct from raw netsh lines" side.
pub use crate::dns_state::DnsPrior as Prior;
pub use crate::dns_state::DnsPriorAdapter as PriorAdapter;

#[cfg(test)]
#[path = "system_tests.rs"]
mod system_tests;
