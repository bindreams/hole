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
//! path dispatches on the captured [`crate::dns_state::DnsPrior`] variant
//! so a prior that was DHCP-assigned doesn't get reapplied as a static
//! list (which would freeze DHCP renewal).
//!
//! ## Which adapters?
//!
//! Capture targets one adapter: the upstream physical adapter. Apply sets
//! the loopback on both the TUN adapter (which we want the best-route
//! resolver lookup to land on) and the upstream. The TUN is recreated per
//! connect so its prior state is "defaults"; nothing to capture.
//! Restore replays the captured state per adapter.
//!
//! ## Platform implementations
//!
//! - **Windows** — Direct Win32 calls via [`windows::WinDnsBackend`] +
//!   [`windows::Win32Real`]. Pre-#397 this layer shelled out to `netsh`.
//!   Adapter identity is the friendly alias ("Wi-Fi", "wintun") which
//!   resolves to a LUID-then-GUID inside `Win32Real`.
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
/// substitute `MockDns` via `ProxyManager::new_with_dns` (chunk 3).
///
/// **Why a trait, not free functions.** Direct callers of the
/// platform-free-function surface (`apply_loopback`, `capture_adapters`,
/// `restore_all`) outside the `SystemDns` impl are rejected by workspace
/// `clippy.toml` `disallowed_methods` (added in chunk 3), mirroring the
/// `setup_routes` / `teardown_routes` enforcement at
/// [tun_engine::routing](../../../tun_engine/routing.rs). The motivation
/// is identical to #165: a helper that bypasses the trait cannot be
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
    ///   This is what `ProxyManager::stop` does (chunk 3).
    /// - Fallback: Drop. Synchronous, used only on crash / panic
    ///   unwind. The `DebugDropBomb` safeguard inside the production
    ///   guard panics in debug builds if shutdown wasn't awaited, so
    ///   missed-shutdown bugs are caught at first test run.
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
    /// The cancel token fired between FFI / netsh calls during apply.
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
// On Windows, `SystemDns` carries an `Arc<dyn WinDnsBackend>` so tests can
// substitute `MockBackend`. The default constructor uses `Win32Real` which
// calls `SetInterfaceDnsSettings` / `GetInterfaceDnsSettings` /
// `DnsFlushResolverCache` directly (~ms-scale FFI).
//
// On macOS, `SystemDns` is currently stateless and delegates to the
// `networksetup`-based free-function surface; the parity `MacDnsBackend`
// refactor lands in chunk 3.

/// Production [`Dns`] implementation.
#[derive(Clone)]
pub struct SystemDns {
    /// Win32 DNS backend. Production: [`windows::Win32Real`]; tests:
    /// substitute via [`Self::new_with_backend`].
    #[cfg(target_os = "windows")]
    backend: Arc<dyn windows::WinDnsBackend>,
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
        }
    }

    /// Construct a [`SystemDns`] with a specific [`windows::WinDnsBackend`]
    /// implementation. Used by Layer-2 unit tests (`windows_tests.rs`) to
    /// substitute a mock. Production code uses [`Self::new`].
    #[cfg(target_os = "windows")]
    pub fn new_with_backend(backend: Arc<dyn windows::WinDnsBackend>) -> Self {
        Self { backend }
    }
}

impl Dns for SystemDns {
    type Applied = SystemDnsApplied;

    #[cfg(target_os = "windows")]
    async fn apply(
        &self,
        local_dns_server: crate::dns::server::LocalDnsServer,
        capture_aliases: Vec<String>,
        apply_aliases: Vec<String>,
        state_dir: Option<PathBuf>,
        cancel: CancellationToken,
    ) -> Result<Self::Applied, DnsError> {
        apply_windows(
            &self.backend,
            local_dns_server,
            capture_aliases,
            apply_aliases,
            state_dir,
            cancel,
        )
        .await
    }

    #[cfg(target_os = "macos")]
    async fn apply(
        &self,
        local_dns_server: crate::dns::server::LocalDnsServer,
        capture_aliases: Vec<String>,
        apply_aliases: Vec<String>,
        state_dir: Option<PathBuf>,
        cancel: CancellationToken,
    ) -> Result<Self::Applied, DnsError> {
        // macOS path keeps the chunk-1 stub-delegation. The cancel-aware
        // `MacDnsBackend` refactor lands in chunk 3.
        let _ = cancel;
        let started = std::time::Instant::now();
        let chosen_loopback = local_dns_server.addr();
        let loopback_ip = chosen_loopback.ip();

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

        tracing::info!(
            elapsed_ms = started.elapsed().as_millis() as u64,
            "apply_dns_settings done"
        );

        Ok(SystemDnsApplied {
            applied_prior: captured,
            state_dir,
            local_dns_server: Some(local_dns_server),
            bomb: drop_bomb::DebugDropBomb::new(BOMB_MSG),
        })
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    async fn apply(
        &self,
        local_dns_server: crate::dns::server::LocalDnsServer,
        _capture_aliases: Vec<String>,
        _apply_aliases: Vec<String>,
        state_dir: Option<PathBuf>,
        _cancel: CancellationToken,
    ) -> Result<Self::Applied, DnsError> {
        Ok(SystemDnsApplied {
            applied_prior: Vec::new(),
            state_dir,
            local_dns_server: Some(local_dns_server),
            bomb: drop_bomb::DebugDropBomb::new(BOMB_MSG),
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
    local_dns_server: crate::dns::server::LocalDnsServer,
    capture_aliases: Vec<String>,
    apply_aliases: Vec<String>,
    state_dir: Option<PathBuf>,
    cancel: CancellationToken,
) -> Result<SystemDnsApplied, DnsError> {
    let started = std::time::Instant::now();
    let chosen_loopback = local_dns_server.addr();
    let loopback_ip = chosen_loopback.ip();
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
            chosen_loopback,
            adapters: captured.clone(),
        };
        if let Err(e) = crate::dns_state::save(dir, &state) {
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
            inline_restore(backend, &captured).await;
            return Err(DnsError::Cancelled);
        }
        let b = Arc::clone(backend);
        let alias_owned = alias.clone();
        let res = tokio::task::spawn_blocking(move || b.set_loopback(&alias_owned, loopback_ip))
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
        local_dns_server: Some(local_dns_server),
        bomb: drop_bomb::DebugDropBomb::new(BOMB_MSG),
    })
}

#[cfg(target_os = "windows")]
async fn inline_restore(backend: &Arc<dyn windows::WinDnsBackend>, prior: &[DnsPriorAdapter]) {
    let backend = Arc::clone(backend);
    let prior = prior.to_vec();
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
    /// Win32 backend used for restore. None on macOS / unsupported
    /// targets — those use the free-function path (chunk 3 unifies).
    #[cfg(target_os = "windows")]
    backend: Arc<dyn windows::WinDnsBackend>,
    applied_prior: Vec<DnsPriorAdapter>,
    state_dir: Option<PathBuf>,
    /// Held to keep the loopback `<ip>:53` bound and to keep the
    /// forwarder tasks running. Released AFTER system DNS is restored.
    local_dns_server: Option<crate::dns::server::LocalDnsServer>,
    /// Runtime safeguard: panics in debug builds on drop if `shutdown`
    /// wasn't awaited. No-op in release; the sync-fallback `Drop` impl
    /// below covers the release-build crash-unwind path.
    bomb: drop_bomb::DebugDropBomb,
}

impl DnsApplied for SystemDnsApplied {
    async fn shutdown(&mut self) {
        self.bomb.defuse();
        let prior = std::mem::take(&mut self.applied_prior);
        let state_dir = self.state_dir.clone();
        #[cfg(target_os = "windows")]
        let backend = Arc::clone(&self.backend);

        let _ = tokio::task::spawn_blocking(move || {
            #[cfg(target_os = "windows")]
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
            #[cfg(not(target_os = "windows"))]
            {
                let errors = restore_all(&prior);
                if !errors.is_empty() {
                    tracing::warn!(
                        count = errors.len(),
                        "SystemDnsApplied::shutdown: some adapters failed to restore"
                    );
                }
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
    /// Sync fallback for crash / panic unwind. `DebugDropBomb`'s own
    /// Drop panics in debug builds if not defused (catching
    /// missed-shutdown bugs); release builds suppress the panic and we
    /// run the best-effort sync restore below.
    fn drop(&mut self) {
        if self.bomb.is_defused() {
            return;
        }
        // Released paths: missed-shutdown bug in release. Log and run
        // best-effort sync restore so the user's DNS isn't left
        // hijacked.
        tracing::warn!("SystemDnsApplied dropped without shutdown() — sync fallback");
        #[cfg(target_os = "windows")]
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
        #[cfg(not(target_os = "windows"))]
        {
            let errors = restore_all(&self.applied_prior);
            if !errors.is_empty() {
                tracing::warn!(
                    count = errors.len(),
                    "SystemDnsApplied::drop: some adapters failed to restore (sync fallback)"
                );
            }
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
// for the "construct from raw lines" side.
pub use crate::dns_state::DnsPrior as Prior;
pub use crate::dns_state::DnsPriorAdapter as PriorAdapter;

#[cfg(test)]
#[path = "system_tests.rs"]
mod system_tests;
