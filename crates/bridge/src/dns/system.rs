//! System DNS capture/apply/restore.
//!
//! The bridge re-points OS DNS clients at the configured upstream resolver
//! IPs while a proxy is running, then restores the prior per-adapter / per-
//! address-family DNS configuration on clean shutdown or crash recovery.
//! OS DNS to those resolver IPs routes into `hole-tun` and is intercepted by
//! the in-TUN `LocalDnsEndpoint` (there is no loopback `:53` server).
//!
//! ## Per-adapter, per-family, three prior kinds
//!
//! Each adapter carries two independent DNS lists (v4, v6); each list is
//! in one of three states — static, DHCP-assigned, or unset. The restore
//! path dispatches on the captured [`crate::dns_state::DnsPrior`] variant
//! so a prior that was DHCP-assigned doesn't get reapplied as a static
//! list (which would freeze DHCP renewal).
//!
//! ## Which adapters?
//!
//! Capture targets one adapter: the upstream physical adapter. Apply sets
//! the resolver IPs on both the TUN adapter (which we want the best-route
//! resolver lookup to land on) and the upstream. The TUN is recreated per
//! connect so its prior state is "defaults"; nothing to capture.
//! Restore replays the captured state per adapter.
//!
//! ## Platform implementations
//!
//! - **Windows** — Direct Win32 calls via [`windows::WinDnsBackend`] +
//!   [`windows::Win32Real`]. Adapter identity is the friendly alias
//!   ("Wi-Fi", "wintun") which resolves to a LUID-then-GUID inside
//!   `Win32Real`.
//! - **macOS** — `networksetup -{getdnsservers,setdnsservers}`. Adapter
//!   identity is the service name (e.g. "Wi-Fi"). Reasonably stable
//!   across short periods; a user who renames a service mid-session
//!   will see that service skipped on restore.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::dns_state::{AdapterId, DnsPriorAdapter};

// Dns trait surface ===================================================================================================

/// Bridge-side system-DNS facade.
///
/// `Dns` and [`DnsApplied`] are the test-isolation seam for system-DNS
/// I/O, mirroring [`crate::proxy::Proxy`] and [`tun_engine::routing::Routing`].
/// Production goes through [`SystemDns`] (platform-specific); tests
/// substitute a mock via [`crate::proxy_manager::ProxyManager::new_with_dns`].
///
/// **Why a trait, not free functions.** Direct callers of the
/// platform-free-function surface (`capture_adapters`, `restore_all`)
/// outside the `SystemDns` impl are rejected by workspace
/// `clippy.toml` `disallowed_methods`, mirroring the `setup_routes` /
/// `teardown_routes` enforcement at
/// [tun_engine::routing](../../../tun_engine/routing.rs). The motivation
/// is identical to #165: a helper that bypasses the trait cannot be
/// intercepted by the mock and will exercise real production code from
/// unit tests, with catastrophic consequences for test reliability and
/// CI health. See bindreams/hole#397.
pub trait Dns: Send + Sync + 'static {
    /// RAII guard returned by [`apply`](Self::apply). Owns the captured
    /// `DnsPriorAdapter`s and any platform-specific state needed for restore.
    ///
    /// **Two teardown paths**:
    ///
    /// - Preferred: call [`DnsApplied::shutdown`] (async) before drop.
    ///   This is what `ProxyManager::stop` does.
    /// - Fallback: Drop. Synchronous, used only on crash / panic
    ///   unwind. The `DebugDropBomb` safeguard inside the production
    ///   guard panics in debug builds if shutdown wasn't awaited, so
    ///   missed-shutdown bugs are caught at first test run.
    type Applied: DnsApplied;

    /// Capture the prior DNS state of `capture_aliases`, persist it to
    /// `bridge-dns.json` (if `state_dir` is set), then point the OS at
    /// `advertise_ips` (the configured upstream resolver IPs) on each
    /// adapter in `apply_aliases`.
    ///
    /// On Windows, `set_servers` splits `advertise_ips` per address family
    /// and sets the v4 and v6 families separately; a family with no entries
    /// is left untouched, never cleared. macOS sets the mixed list in one
    /// call. OS UDP/53 to these IPs routes into `hole-tun` and is intercepted
    /// by the in-TUN `LocalDnsEndpoint`; OS TCP/53 falls through the proxy
    /// cascade to the real resolver over the tunnel.
    ///
    /// **Cancellation.** The implementation MUST check `cancel.cancelled()`
    /// between per-adapter I/O operations and inline-restore any
    /// partially-applied adapters before returning
    /// [`DnsError::Cancelled`]. Cancel-check granularity is between calls,
    /// not mid-call (an in-flight FFI write cannot be safely interrupted).
    fn apply(
        &self,
        advertise_ips: Vec<std::net::IpAddr>,
        capture_aliases: Vec<String>,
        apply_aliases: Vec<String>,
        state_dir: Option<PathBuf>,
        owner: Option<(u32, u32)>,
        cancel: CancellationToken,
    ) -> impl std::future::Future<Output = Result<Self::Applied, DnsError>> + Send;
}

/// RAII guard returned by [`Dns::apply`]. See [`Dns::Applied`] for the
/// shutdown contract.
pub trait DnsApplied: Send + 'static {
    /// Restore the captured prior DNS state. Async so the platform I/O can
    /// use `tokio::task::spawn_blocking` and never stall the runtime worker.
    /// Idempotent: calling twice is a no-op the second time.
    fn shutdown(&mut self) -> impl std::future::Future<Output = ()> + Send + '_;
}

/// Errors returned from [`Dns::apply`].
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    /// The cancel token fired between FFI / netsh calls during apply.
    /// Any partially-applied adapters have been inline-restored before
    /// this variant is returned.
    #[error("DNS apply cancelled")]
    Cancelled,

    /// Capture or apply failed at the platform level. The bridge logs a
    /// warning and continues with a degraded `RunningState.dns = None`
    /// (forwarder up, OS resolvers not redirected). Non-cancel failures
    /// are NOT fatal to proxy start.
    #[error("DNS apply failed: {0}")]
    Io(#[from] io::Error),
}

// SystemDns ===========================================================================================================
//
// `SystemDns` carries a platform-specific backend trait object so tests
// can substitute a mock without touching the OS resolver. Mirrors
// [`tun_engine::routing::SystemRouting`].
//
// - Windows: `Arc<dyn WinDnsBackend>`. Production: `Win32Real`
//   (`SetInterfaceDnsSettings` / `GetInterfaceDnsSettings` /
//   `DnsFlushResolverCache`, ~ms-scale FFI).
// - macOS: `Arc<dyn MacDnsBackend>`. Production: `Networksetup`
//   (`networksetup -getdnsservers` / `-setdnsservers` subprocess).

/// Production [`Dns`] implementation.
#[derive(Clone)]
pub struct SystemDns {
    /// Win32 DNS backend. Production: [`windows::Win32Real`]; tests:
    /// substitute via [`Self::new_with_backend`].
    #[cfg(target_os = "windows")]
    backend: Arc<dyn windows::WinDnsBackend>,
    /// macOS `networksetup` backend. Production:
    /// [`macos::Networksetup`]; tests: substitute via
    /// [`Self::new_with_mac_backend`].
    #[cfg(target_os = "macos")]
    backend: Arc<dyn macos::MacDnsBackend>,
}

impl Default for SystemDns {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemDns {
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "windows")]
            backend: Arc::new(windows::Win32Real),
            #[cfg(target_os = "macos")]
            backend: Arc::new(macos::Networksetup),
        }
    }

    /// Construct a [`SystemDns`] with a specific [`windows::WinDnsBackend`]
    /// implementation. Used by `windows_tests.rs` to substitute a mock;
    /// production uses [`Self::new`].
    #[cfg(target_os = "windows")]
    pub fn new_with_backend(backend: Arc<dyn windows::WinDnsBackend>) -> Self {
        Self { backend }
    }

    /// Construct a [`SystemDns`] with a specific [`macos::MacDnsBackend`]
    /// implementation. Used by Layer-2 unit tests to substitute a mock.
    /// Production code uses [`Self::new`].
    #[cfg(target_os = "macos")]
    pub fn new_with_mac_backend(backend: Arc<dyn macos::MacDnsBackend>) -> Self {
        Self { backend }
    }
}

impl Dns for SystemDns {
    type Applied = SystemDnsApplied;

    #[cfg(target_os = "windows")]
    async fn apply(
        &self,
        advertise_ips: Vec<std::net::IpAddr>,
        capture_aliases: Vec<String>,
        apply_aliases: Vec<String>,
        state_dir: Option<PathBuf>,
        owner: Option<(u32, u32)>,
        cancel: CancellationToken,
    ) -> Result<Self::Applied, DnsError> {
        apply_windows(
            &self.backend,
            advertise_ips,
            capture_aliases,
            apply_aliases,
            state_dir,
            owner,
            cancel,
        )
        .await
    }

    #[cfg(target_os = "macos")]
    async fn apply(
        &self,
        advertise_ips: Vec<std::net::IpAddr>,
        capture_aliases: Vec<String>,
        apply_aliases: Vec<String>,
        state_dir: Option<PathBuf>,
        owner: Option<(u32, u32)>,
        cancel: CancellationToken,
    ) -> Result<Self::Applied, DnsError> {
        apply_macos(
            &self.backend,
            advertise_ips,
            capture_aliases,
            apply_aliases,
            state_dir,
            owner,
            cancel,
        )
        .await
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    async fn apply(
        &self,
        _advertise_ips: Vec<std::net::IpAddr>,
        _capture_aliases: Vec<String>,
        _apply_aliases: Vec<String>,
        state_dir: Option<PathBuf>,
        _owner: Option<(u32, u32)>,
        _cancel: CancellationToken,
    ) -> Result<Self::Applied, DnsError> {
        Ok(SystemDnsApplied {
            applied_prior: Vec::new(),
            state_dir,
            bomb: drop_bomb::DebugDropBomb::new(BOMB_MSG),
            shutdown_completed: false,
        })
    }
}

/// Message stored in the `DebugDropBomb`. The `#[should_panic(expected =
/// ...)]` in [`crate::dns::system::windows::windows_tests`] matches this
/// exact string.
const BOMB_MSG: &str = "SystemDnsApplied dropped without awaiting shutdown()";

// Windows apply loop ==================================================================================================

#[cfg(target_os = "windows")]
async fn apply_windows(
    backend: &Arc<dyn windows::WinDnsBackend>,
    advertise_ips: Vec<std::net::IpAddr>,
    capture_aliases: Vec<String>,
    apply_aliases: Vec<String>,
    state_dir: Option<PathBuf>,
    owner: Option<(u32, u32)>,
    cancel: CancellationToken,
) -> Result<SystemDnsApplied, DnsError> {
    let started = std::time::Instant::now();
    // `set_servers` advertises both families, splitting `advertise_ips` per
    // family internally and leaving a family with no configured resolver
    // untouched. Pass the full list through unchanged.
    let mut captured: Vec<DnsPriorAdapter> = Vec::new();

    // Capture phase. Cancel checked between FFIs; capture is read-only,
    // so an early Err here mutates no state.
    for alias in &capture_aliases {
        if cancel.is_cancelled() {
            return Err(DnsError::Cancelled);
        }
        let b = Arc::clone(backend);
        let alias_owned = alias.clone();
        let res = tokio::task::spawn_blocking(move || b.get_settings(&alias_owned))
            .await
            .map_err(|e| DnsError::Io(io::Error::other(e)))?;
        match res {
            Ok(Some(prior)) => captured.push(prior),
            Ok(None) => tracing::debug!(%alias, "DNS capture: adapter not found; skipping"),
            Err(e) => tracing::warn!(%alias, error = %e, "DNS capture failed for adapter"),
        }
    }

    // Cancel-check after capture, before mutating side: capture is pure
    // read, persist + apply mutate state. Skipping the check here would
    // let a cancel arriving between the last capture and the first
    // persist proceed to write `bridge-dns.json` and start mutating DNS.
    if cancel.is_cancelled() {
        return Err(DnsError::Cancelled);
    }

    // Persist BEFORE apply so a mid-apply crash leaves a recoverable
    // file (matches `tun_engine::routing::SystemRouting::install`).
    if let Some(dir) = state_dir.as_deref() {
        let state = crate::dns_state::DnsState {
            version: crate::dns_state::SCHEMA_VERSION,
            advertised: advertise_ips.clone(),
            adapters: captured.clone(),
        };
        if let Err(e) = crate::dns_state::save(dir, &state, owner) {
            tracing::warn!(error = %e, "dns_state::save failed; continuing without crash-recovery file");
        }
    }

    // Apply phase. Cancel between FFIs — we do NOT race cancel against
    // an in-flight `spawn_blocking` because abandoning the join handle
    // leaves the FFI running on the blocking pool and creates a TOCTOU
    // race against the inline-restore that runs next (both could be
    // mutating the same adapter from different threads). Each FFI is
    // ~10 ms; the cancel-response delay is bounded by ≤1 FFI duration.
    for alias in &apply_aliases {
        if cancel.is_cancelled() {
            // Cooperative inline-restore — runs serially through the
            // same backend (cancel-disregarded inside restore). FFI
            // budget for restore: 2 adapters × 2 families = ~40 ms.
            // Also clears `bridge-dns.json` so the next start's
            // `recover_dns_config` doesn't replay an already-restored
            // prior over any user-side DNS changes made between this
            // cancel and that next start.
            inline_restore(backend, &captured, state_dir.as_deref()).await;
            return Err(DnsError::Cancelled);
        }
        let b = Arc::clone(backend);
        let alias_owned = alias.clone();
        let ips = advertise_ips.clone();
        let res = tokio::task::spawn_blocking(move || b.set_servers(&alias_owned, &ips))
            .await
            .map_err(|e| DnsError::Io(io::Error::other(e)))?;
        if let Err(e) = res {
            tracing::warn!(%alias, error = %e, "DNS apply failed; continuing");
        }
    }

    // Flush. Best-effort — through the backend so MockBackend can count
    // it for the perf-regression test.
    let b = Arc::clone(backend);
    let _ = tokio::task::spawn_blocking(move || b.flush()).await;

    tracing::info!(
        elapsed_ms = started.elapsed().as_millis() as u64,
        "apply_dns_settings done"
    );

    Ok(SystemDnsApplied {
        backend: Arc::clone(backend),
        applied_prior: captured,
        state_dir,
        bomb: drop_bomb::DebugDropBomb::new(BOMB_MSG),
        shutdown_completed: false,
    })
}

#[cfg(target_os = "windows")]
async fn inline_restore(
    backend: &Arc<dyn windows::WinDnsBackend>,
    prior: &[DnsPriorAdapter],
    state_dir: Option<&std::path::Path>,
) {
    let backend = Arc::clone(backend);
    let prior = prior.to_vec();
    let state_dir = state_dir.map(std::path::Path::to_path_buf);
    let _ = tokio::task::spawn_blocking(move || {
        for adapter in &prior {
            if let Err(e) = backend.restore(adapter) {
                tracing::warn!(
                    id = ?adapter.id,
                    error = %e,
                    "inline-restore: adapter failed; continuing"
                );
            }
        }
        let _ = backend.flush();
        if let Some(dir) = state_dir {
            if let Err(e) = crate::dns_state::clear(&dir) {
                tracing::warn!(
                    error = %e,
                    "inline-restore: failed to clear bridge-dns.json"
                );
            }
        }
    })
    .await;
}

// macOS apply loop ====================================================================================================

#[cfg(target_os = "macos")]
async fn apply_macos(
    backend: &Arc<dyn macos::MacDnsBackend>,
    advertise_ips: Vec<std::net::IpAddr>,
    capture_aliases: Vec<String>,
    apply_aliases: Vec<String>,
    state_dir: Option<PathBuf>,
    owner: Option<(u32, u32)>,
    cancel: CancellationToken,
) -> Result<SystemDnsApplied, DnsError> {
    let started = std::time::Instant::now();
    let mut captured: Vec<DnsPriorAdapter> = Vec::new();

    // Capture phase. Cancel checked between subprocesses; capture is
    // read-only, so an early Err here mutates no state.
    for service in &capture_aliases {
        if cancel.is_cancelled() {
            return Err(DnsError::Cancelled);
        }
        let b = Arc::clone(backend);
        let svc_owned = service.clone();
        let res = tokio::task::spawn_blocking(move || b.get_settings(&svc_owned))
            .await
            .map_err(|e| DnsError::Io(io::Error::other(e)))?;
        match res {
            Ok(Some(prior)) => captured.push(prior),
            Ok(None) => tracing::debug!(%service, "DNS capture: service not found; skipping"),
            Err(e) => tracing::warn!(%service, error = %e, "DNS capture failed for service"),
        }
    }

    if cancel.is_cancelled() {
        return Err(DnsError::Cancelled);
    }

    // Persist BEFORE apply so a mid-apply crash leaves a recoverable
    // file (matches `tun_engine::routing::SystemRouting::install`).
    if let Some(dir) = state_dir.as_deref() {
        let state = crate::dns_state::DnsState {
            version: crate::dns_state::SCHEMA_VERSION,
            advertised: advertise_ips.clone(),
            adapters: captured.clone(),
        };
        if let Err(e) = crate::dns_state::save(dir, &state, owner) {
            tracing::warn!(error = %e, "dns_state::save failed; continuing without crash-recovery file");
        }
    }

    // Apply phase. Cancel between subprocesses, mirroring the Windows
    // path's TOCTOU rationale: abandoning an in-flight `spawn_blocking`
    // leaves `networksetup` running on the blocking pool and would race
    // the subsequent inline-restore.
    for service in &apply_aliases {
        if cancel.is_cancelled() {
            // Clears `bridge-dns.json` alongside the per-adapter restore —
            // same rationale as the Windows path above.
            inline_restore_macos(backend, &captured, state_dir.as_deref()).await;
            return Err(DnsError::Cancelled);
        }
        let b = Arc::clone(backend);
        let svc_owned = service.clone();
        let ips = advertise_ips.clone();
        let res = tokio::task::spawn_blocking(move || b.set_servers(&svc_owned, &ips))
            .await
            .map_err(|e| DnsError::Io(io::Error::other(e)))?;
        if let Err(e) = res {
            tracing::warn!(%service, error = %e, "DNS apply failed; continuing");
        }
    }

    // Flush. Best-effort — through the backend so mock backends can
    // count it for the perf-regression test.
    let b = Arc::clone(backend);
    let _ = tokio::task::spawn_blocking(move || b.flush()).await;

    tracing::info!(
        elapsed_ms = started.elapsed().as_millis() as u64,
        "apply_dns_settings done"
    );

    Ok(SystemDnsApplied {
        backend: Arc::clone(backend),
        applied_prior: captured,
        state_dir,
        bomb: drop_bomb::DebugDropBomb::new(BOMB_MSG),
        shutdown_completed: false,
    })
}

#[cfg(target_os = "macos")]
async fn inline_restore_macos(
    backend: &Arc<dyn macos::MacDnsBackend>,
    prior: &[DnsPriorAdapter],
    state_dir: Option<&std::path::Path>,
) {
    let backend = Arc::clone(backend);
    let prior = prior.to_vec();
    let state_dir = state_dir.map(std::path::Path::to_path_buf);
    let _ = tokio::task::spawn_blocking(move || {
        for adapter in &prior {
            if let Err(e) = backend.restore(adapter) {
                tracing::warn!(
                    id = ?adapter.id,
                    error = %e,
                    "inline-restore: adapter failed; continuing"
                );
            }
        }
        let _ = backend.flush();
        if let Some(dir) = state_dir {
            if let Err(e) = crate::dns_state::clear(&dir) {
                tracing::warn!(
                    error = %e,
                    "inline-restore: failed to clear bridge-dns.json"
                );
            }
        }
    })
    .await;
}

// SystemDnsApplied ====================================================================================================

/// RAII guard returned by [`SystemDns::apply`]. The preferred teardown
/// path is [`DnsApplied::shutdown`] (async) called by
/// `ProxyManager::stop`; the `DebugDropBomb` panics in debug builds if
/// shutdown wasn't awaited, catching missed-shutdown bugs at the first
/// test run. Release builds fall through to a best-effort sync restore.
#[must_use = "SystemDnsApplied owns async cleanup; call .shutdown().await before drop"]
pub struct SystemDnsApplied {
    /// Win32 backend used for restore on Windows. Mirrors the macOS
    /// `backend` field below; both go through `Arc<dyn …Backend>` so
    /// `SystemDnsApplied` is platform-agnostic.
    #[cfg(target_os = "windows")]
    backend: Arc<dyn windows::WinDnsBackend>,
    /// `networksetup` backend used for restore on macOS.
    #[cfg(target_os = "macos")]
    backend: Arc<dyn macos::MacDnsBackend>,
    applied_prior: Vec<DnsPriorAdapter>,
    state_dir: Option<PathBuf>,
    /// Runtime safeguard: panics in debug builds on drop if `shutdown`
    /// wasn't awaited. No-op in release.
    ///
    /// **DO NOT** gate the sync-fallback `Drop` path on `bomb.is_defused()`:
    /// `drop_bomb::DebugDropBomb::is_defused()` returns `true`
    /// unconditionally in release builds (`FakeBomb`), which would make
    /// the fallback dead code in release. The `shutdown_completed` flag
    /// below is the load-bearing release-mode signal.
    bomb: drop_bomb::DebugDropBomb,
    /// `true` after `DnsApplied::shutdown` has completed its restore +
    /// cleanup. Set in `shutdown` regardless of build profile. `Drop`
    /// checks this (not `bomb.is_defused()`) to decide whether to run
    /// the sync-fallback restore. See bindreams/hole#397.
    shutdown_completed: bool,
}

impl DnsApplied for SystemDnsApplied {
    async fn shutdown(&mut self) {
        self.bomb.defuse();
        self.shutdown_completed = true;
        let prior = std::mem::take(&mut self.applied_prior);
        let state_dir = self.state_dir.clone();
        #[cfg(any(target_os = "windows", target_os = "macos"))]
        let backend = Arc::clone(&self.backend);

        let _ = tokio::task::spawn_blocking(move || {
            #[cfg(any(target_os = "windows", target_os = "macos"))]
            {
                for adapter in &prior {
                    if let Err(e) = backend.restore(adapter) {
                        tracing::warn!(
                            id = ?adapter.id,
                            error = %e,
                            "SystemDnsApplied::shutdown: restore failed for adapter"
                        );
                    }
                }
                let _ = backend.flush();
            }
            #[cfg(not(any(target_os = "windows", target_os = "macos")))]
            {
                let _ = prior;
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
    }
}

impl Drop for SystemDnsApplied {
    /// Sync fallback for crash / panic unwind. `DebugDropBomb`'s own
    /// Drop panics in debug builds if not defused (catching
    /// missed-shutdown bugs); release builds suppress the panic and we
    /// run the best-effort sync restore below.
    ///
    /// The release signal is `shutdown_completed`, not `bomb.is_defused()`
    /// — see the `shutdown_completed` field doc.
    fn drop(&mut self) {
        if self.shutdown_completed {
            return;
        }
        // Released paths: missed-shutdown bug in release. Log and run
        // best-effort sync restore so the user's DNS isn't left
        // hijacked.
        tracing::warn!("SystemDnsApplied dropped without shutdown() — sync fallback");
        #[cfg(any(target_os = "windows", target_os = "macos"))]
        {
            for adapter in &self.applied_prior {
                if let Err(e) = self.backend.restore(adapter) {
                    tracing::warn!(
                        id = ?adapter.id,
                        error = %e,
                        "SystemDnsApplied::drop: restore failed (sync fallback)"
                    );
                }
            }
            let _ = self.backend.flush();
        }
        if let Some(dir) = &self.state_dir {
            if let Err(e) = crate::dns_state::clear(dir) {
                tracing::warn!(
                    error = %e,
                    "SystemDnsApplied::drop: failed to clear bridge-dns.json"
                );
            }
        }
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

// Re-export DnsPrior helpers so callers don't need a separate import just
// for the "construct from raw lines" side.
pub use crate::dns_state::DnsPrior as Prior;
pub use crate::dns_state::DnsPriorAdapter as PriorAdapter;

#[cfg(test)]
#[path = "system_tests.rs"]
mod system_tests;
