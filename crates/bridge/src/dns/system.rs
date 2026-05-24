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
use std::path::PathBuf;

use tokio_util::sync::CancellationToken;

use crate::dns_state::{AdapterId, DnsPriorAdapter};

// Dns trait surface ===================================================================================================

/// Bridge-side system-DNS facade.
///
/// `Dns` and [`DnsApplied`] are the test-isolation seam for system-DNS
/// I/O, mirroring [`crate::proxy::Proxy`] and [`tun_engine::routing::Routing`].
/// Production goes through `SystemDns` (platform-specific); tests
/// substitute `MockDns` via [`crate::proxy_manager::ProxyManager::new_with_dns`].
///
/// **Why a trait, not free functions.** Direct callers of the
/// platform-free-function surface (`apply_loopback`, `capture_adapters`,
/// `restore_all`) outside the `SystemDns` impl are rejected by workspace
/// `clippy.toml` `disallowed_methods`, mirroring the
/// `setup_routes` / `teardown_routes` enforcement at
/// [tun_engine::routing](../../../tun_engine/routing.rs). The motivation is
/// identical to #165: a helper that bypasses the trait cannot be
/// intercepted by the mock and will exercise real production code from
/// unit tests, with catastrophic consequences for test reliability and
/// CI health. See bindreams/hole#397.
pub trait Dns: Send + Sync + 'static {
    /// RAII guard returned by [`apply`](Self::apply). Owns the
    /// `LocalDnsServer`, the captured `DnsPriorAdapter`s, and any
    /// platform-specific state needed for restore.
    ///
    /// **Two teardown paths**:
    ///
    /// - Preferred: call [`DnsApplied::shutdown`] (async) before drop.
    ///   This is what [`crate::proxy_manager::ProxyManager::stop`] does.
    /// - Fallback: Drop. Synchronous, used only on crash / panic
    ///   unwind. Production implementations may use
    ///   `tokio::task::block_in_place` if a runtime is current.
    type Applied: DnsApplied;

    /// Capture the prior DNS state of `capture_aliases`, persist it to
    /// `bridge-dns.json` (if `state_dir` is set), then point the OS at
    /// `local_dns_server.addr().ip()` on each adapter in `apply_aliases`.
    ///
    /// **Cancellation.** The implementation MUST check `cancel.cancelled()`
    /// between per-adapter I/O operations and inline-restore any
    /// partially-applied adapters before returning
    /// [`DnsError::Cancelled`]. Cancel-check granularity is between calls,
    /// not mid-call — see the plan for #397 for rationale.
    fn apply(
        &self,
        local_dns_server: crate::dns::server::LocalDnsServer,
        capture_aliases: Vec<String>,
        apply_aliases: Vec<String>,
        state_dir: Option<PathBuf>,
        cancel: CancellationToken,
    ) -> impl std::future::Future<Output = Result<Self::Applied, DnsError>> + Send;
}

/// RAII guard returned by [`Dns::apply`]. See [`Dns::Applied`] for the
/// shutdown contract.
pub trait DnsApplied: Send + 'static {
    /// Restore the captured prior DNS state and release the
    /// `LocalDnsServer`. Async so the platform I/O can use
    /// `tokio::task::spawn_blocking` and never stall the runtime worker.
    /// Idempotent: calling twice is a no-op the second time.
    fn shutdown(&mut self) -> impl std::future::Future<Output = ()> + Send + '_;
}

/// Errors returned from [`Dns::apply`].
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    /// The cancel token fired between netsh / Win32 calls during apply.
    /// Any partially-applied adapters have been inline-restored before
    /// this variant is returned.
    #[error("DNS apply cancelled")]
    Cancelled,

    /// Capture or apply failed at the platform level. The bridge logs a
    /// warning and continues with a degraded `RunningState.dns = None`
    /// (preserves the pre-#397 behavior: forwarder is up but OS
    /// resolvers haven't been redirected). Non-cancel failures are NOT
    /// fatal to proxy start.
    #[error("DNS apply failed: {0}")]
    Io(#[from] io::Error),
}

// SystemDns ===========================================================================================================
//
// Production `Dns` implementation. This is the stub-stage wiring — `apply`
// shells out to the existing free-function surface on a blocking-pool
// worker so the bridge keeps the pre-#397 behavior. The real Win32 FFI
// rewrite + cancel plumbing land in subsequent commits on this branch.
// See bindreams/hole#397.

/// Production [`Dns`] implementation. Default constructor; carries no
/// state on its own — platform behavior comes from the free-function
/// surface in `dns/system/{windows,macos}.rs` (transitively).
#[derive(Default, Clone)]
pub struct SystemDns;

impl SystemDns {
    pub fn new() -> Self {
        Self
    }
}

impl Dns for SystemDns {
    type Applied = SystemDnsApplied;

    async fn apply(
        &self,
        local_dns_server: crate::dns::server::LocalDnsServer,
        capture_aliases: Vec<String>,
        apply_aliases: Vec<String>,
        state_dir: Option<PathBuf>,
        cancel: CancellationToken,
    ) -> Result<Self::Applied, DnsError> {
        // STAGE 1 stub (#397): delegate to the existing free-function surface.
        // Cancel-naive at this layer — the cancel-aware loop lands when the
        // Win32 backend replaces netsh. Layer 2 tests guard the contract.
        let _ = cancel;
        let started = std::time::Instant::now();
        let chosen_loopback = local_dns_server.addr();
        let loopback_ip = chosen_loopback.ip();

        #[cfg(any(target_os = "windows", target_os = "macos"))]
        let captured = {
            let capture_aliases = capture_aliases.clone();
            let apply_aliases = apply_aliases.clone();
            let state_dir_for_blocking = state_dir.clone();
            tokio::task::spawn_blocking(move || -> Result<Vec<DnsPriorAdapter>, io::Error> {
                let prior = capture_adapters(&capture_aliases)?;
                if let Some(dir) = state_dir_for_blocking.as_deref() {
                    let state = crate::dns_state::DnsState {
                        version: crate::dns_state::SCHEMA_VERSION,
                        chosen_loopback,
                        adapters: prior.clone(),
                    };
                    if let Err(e) = crate::dns_state::save(dir, &state) {
                        tracing::warn!(error = %e, "dns_state::save failed; continuing without crash-recovery file");
                    }
                }
                apply_loopback(&apply_aliases, loopback_ip)?;
                Ok(prior)
            })
            .await
            .map_err(|join_err| io::Error::other(format!("dns apply join error: {join_err}")))??
        };

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        let captured: Vec<DnsPriorAdapter> = {
            let _ = (capture_aliases, apply_aliases);
            Vec::new()
        };

        tracing::info!(
            elapsed_ms = started.elapsed().as_millis() as u64,
            "apply_dns_settings done"
        );

        Ok(SystemDnsApplied {
            applied_prior: captured,
            state_dir,
            local_dns_server: Some(local_dns_server),
            shutdown_called: false,
        })
    }
}

/// RAII guard returned by [`SystemDns::apply`]. Drop restores system DNS
/// (sync fallback for crash / panic unwind) and releases the
/// [`LocalDnsServer`]. The preferred teardown path is
/// [`DnsApplied::shutdown`] (async), called by `ProxyManager::stop`.
pub struct SystemDnsApplied {
    applied_prior: Vec<DnsPriorAdapter>,
    state_dir: Option<PathBuf>,
    /// Held to keep the loopback `<ip>:53` bound and to keep the
    /// forwarder tasks running. Released AFTER system DNS is restored.
    local_dns_server: Option<crate::dns::server::LocalDnsServer>,
    shutdown_called: bool,
}

impl DnsApplied for SystemDnsApplied {
    async fn shutdown(&mut self) {
        if self.shutdown_called {
            return;
        }
        self.shutdown_called = true;
        let prior = std::mem::take(&mut self.applied_prior);
        let state_dir = self.state_dir.clone();
        // Run sync restore on the blocking pool so we never stall the
        // runtime worker.
        let _ = tokio::task::spawn_blocking(move || {
            let errors = restore_all(&prior);
            if !errors.is_empty() {
                tracing::warn!(
                    count = errors.len(),
                    "SystemDnsApplied::shutdown: some adapters failed to restore"
                );
            }
            if let Some(dir) = state_dir {
                if let Err(e) = crate::dns_state::clear(&dir) {
                    tracing::warn!(
                        error = %e,
                        "SystemDnsApplied::shutdown: failed to clear bridge-dns.json"
                    );
                }
            }
        })
        .await;
        // Drop the LocalDnsServer AFTER restore so the OS still has the
        // loopback resolver bound during the window between restore
        // start and finish.
        let _ = self.local_dns_server.take();
    }
}

impl Drop for SystemDnsApplied {
    /// Sync fallback for crash / panic unwind. The async `shutdown` path
    /// is the preferred teardown; production code calls it explicitly
    /// before drop.
    fn drop(&mut self) {
        if self.shutdown_called {
            return;
        }
        let errors = restore_all(&self.applied_prior);
        if !errors.is_empty() {
            tracing::warn!(
                count = errors.len(),
                "SystemDnsApplied::drop: some adapters failed to restore (sync fallback path)"
            );
        }
        if let Some(dir) = &self.state_dir {
            if let Err(e) = crate::dns_state::clear(dir) {
                tracing::warn!(
                    error = %e,
                    "SystemDnsApplied::drop: failed to clear bridge-dns.json"
                );
            }
        }
        // LocalDnsServer drops via the field's own Drop on this struct's drop.
    }
}

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
