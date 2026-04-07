//! Wintun.dll resolution and pre-loading.
//!
//! shadowsocks-service does not expose a way to customize the wintun.dll
//! path that the `tun` crate uses (its `TunConfiguration` is private and
//! defaults to the bare relative name "wintun.dll"). We work around this
//! by resolving wintun.dll ourselves, loading it explicitly via
//! `wintun_bindings::load_from_path`, and then relying on Windows' loaded-
//! module table behavior: a subsequent `LoadLibraryExW("wintun.dll")` from
//! inside shadowsocks-service finds the already-loaded module by base name
//! and returns its handle without re-walking the DLL search order.
//!
//! This gives us:
//!
//! 1. A descriptive error message when wintun.dll is missing (we know
//!    exactly which paths we tried).
//! 2. Independence from the Windows DLL search order — wintun no longer
//!    has to live in the executable directory if our resolution finds it
//!    somewhere else.
//! 3. Defense in depth: the staging done by dev.py / msi-installer (and
//!    future xtask) is still the primary mechanism that puts wintun.dll
//!    where it can be found, but if that ever drifts the user gets a
//!    clear error instead of the cryptic "LoadLibraryExW failed".
//!
//! The LDR-table base-name dedup behavior was empirically verified before
//! adopting this approach (see issue #141 discussion).

use crate::proxy::ProxyError;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tracing::info;

/// Cached successful load. Holds the wintun handle for the process lifetime so
/// the OS doesn't unload the DLL after our `Wintun` (Arc) goes out of scope.
///
/// We deliberately do **not** cache the failure case: if `ensure_loaded` fails
/// once, the user might fix the problem (e.g. install wintun, re-run staging)
/// and retry. A cached error would prevent retry forever within the same
/// process. Caching only success means a successful pre-load is paid once;
/// failure paths are retried on every call (cheap — just a few path probes).
static WINTUN: OnceLock<wintun_bindings::Wintun> = OnceLock::new();

/// Pre-load wintun.dll. Idempotent (safe to call from multiple proxy starts).
/// Returns immediately on cached success; retries from scratch on failure.
pub fn ensure_loaded() -> Result<(), ProxyError> {
    if WINTUN.get().is_some() {
        return Ok(());
    }
    let path = resolve_wintun_path()?;
    info!(path = %path.display(), "pre-loading wintun.dll");
    // SAFETY: `wintun_bindings::load_from_path` is `unsafe` because
    // `libloading::Library::new` calls `LoadLibraryExW`, which executes the
    // DLL's `DllMain` (arbitrary code from the DLL). wintun.dll is the
    // WireGuard LLC userspace TUN driver, downloaded by `crates/gui/build.rs`
    // (and a future xtask subcommand) from www.wintun.net with SHA-256
    // verification against a hash pinned at compile time. The same DLL is
    // unconditionally loaded by `shadowsocks-service` later in the proxy
    // startup path; we are simply moving that load earlier and giving it an
    // explicit absolute path so we can produce a descriptive error.
    let dll = unsafe { wintun_bindings::load_from_path(&path) }.map_err(|e| ProxyError::WintunLoad {
        path: path.clone(),
        message: e.to_string(),
    })?;
    // OnceLock::set returns Err if already set by a concurrent caller — either
    // way, the DLL is now loaded into the process and visible to the later
    // bare-name `LoadLibraryExW("wintun.dll")` call inside shadowsocks-service.
    let _ = WINTUN.set(dll);
    Ok(())
}

/// Resolve a path to wintun.dll by checking, in order:
///
///   1. The directory of the current executable (production / staged BINDIR)
///   2. The repo's `.cache/wintun/wintun.dll` (xtask deps output)
///
/// Returns the list of paths tried in the `WintunMissing` variant so the
/// failure mode is fully diagnosable in logs.
fn resolve_wintun_path() -> Result<PathBuf, ProxyError> {
    resolve_wintun_path_inner(std::env::current_exe().ok())
}

/// Inner implementation that accepts an explicit `current_exe` path for
/// testability. Mirrors the pattern in [`crate::proxy::resolve_plugin_path_inner`].
fn resolve_wintun_path_inner(current_exe: Option<PathBuf>) -> Result<PathBuf, ProxyError> {
    let mut tried = Vec::new();

    // 1. Next to the executable. Production (MSI install) and the dev BINDIR
    //    staged by dev.py both put wintun.dll here.
    if let Some(exe) = current_exe {
        let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("wintun.dll");
            if candidate.is_file() {
                return Ok(candidate);
            }
            tried.push(candidate);

            // 2. Repo cache fallback — useful when running `cargo run -p hole-gui`
            // directly without staging the BINDIR. Walks up looking for
            // `.cache/wintun/wintun.dll` (the `cargo xtask wintun` output).
            if let Some(p) = walk_up_for(dir, Path::new(".cache/wintun/wintun.dll")) {
                if p.is_file() {
                    return Ok(p);
                }
                tried.push(p);
            }
        }
    }

    Err(ProxyError::WintunMissing { tried })
}

/// Walk up from `start` up to 8 levels looking for `<dir>/<rel>`. Returns the
/// first matching candidate path (file existence is checked by the caller).
/// 8 levels covers `cargo target/{debug,release}/hole.exe` (2 levels) and
/// worktree layouts like `.tmp/claude/worktrees/<branch>/target/debug/hole.exe`
/// (5 levels), with margin.
fn walk_up_for(start: &Path, rel: &Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    for _ in 0..8 {
        let candidate = dir.join(rel);
        if candidate.exists() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
    None
}

#[cfg(test)]
#[path = "wintun_tests.rs"]
mod wintun_tests;
