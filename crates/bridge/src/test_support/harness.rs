//! Per-test `ProxyManager` harness builders.
//!
//! These are plain functions, not skuld fixtures, because skuld's scope
//! rule forbids a `test`-scoped fixture from depending on a `variable`-
//! scoped one (the built-in `temp_dir` is `variable`-scoped). The functions
//! take the process-scoped fixture references they need as arguments and
//! return a fresh per-test harness.
//!
//! Each harness owns:
//! - A unique state directory (`tempfile::TempDir`) that the route-recovery
//!   state file is written into.
//! - A unique ephemeral SOCKS5 `local_port` allocated via
//!   [`crate::test_support::port_alloc::allocate_ephemeral_port_sync`].
//! - A `ProxyManager<B>` instance.
//! - A `ProxyConfig` ready to pass to `manager.start(...)`.

use crate::proxy_manager::{ProxyBackend, ProxyManager, RealBackend};
use crate::test_support::backends::SocksOnlyBackend;
use crate::test_support::port_alloc::allocate_ephemeral_port_sync;
use hole_common::config::ServerEntry;
use hole_common::protocol::ProxyConfig;
use std::net::SocketAddr;
use tempfile::TempDir;

/// A per-test bundle of everything a test needs to drive `ProxyManager`
/// against a real backend.
pub(crate) struct BridgeHarness<B: ProxyBackend> {
    pub manager: ProxyManager<B>,
    pub proxy_config: ProxyConfig,
    /// State-dir tempdir. Held alive for the test's duration so the
    /// route-recovery state file persists where the manager expects it,
    /// AND so test bodies can read paths inside it (e.g.
    /// `bridge-routes.json` in `lifecycle_state_file_cleared_on_clean_stop`).
    pub state_dir: TempDir,
}

impl<B: ProxyBackend> BridgeHarness<B> {
    /// Convenience: path to the `bridge-routes.json` state file inside
    /// `state_dir`. May or may not exist depending on backend +
    /// proxy lifecycle phase.
    pub fn state_file_path(&self) -> std::path::PathBuf {
        self.state_dir.path().join("bridge-routes.json")
    }
}

/// Build a `ServerEntry` from the loose pieces a test fixture provides.
fn build_entry(
    ss_addr: SocketAddr,
    method: &str,
    password: &str,
    plugin: Option<String>,
    plugin_opts: Option<String>,
) -> ServerEntry {
    ServerEntry {
        id: "test-entry".into(),
        name: "test".into(),
        server: ss_addr.ip().to_string(),
        server_port: ss_addr.port(),
        method: method.into(),
        password: password.into(),
        plugin,
        plugin_opts,
        validation: None,
    }
}

/// Build a SOCKS5-only test harness. Uses [`SocksOnlyBackend`] which strips
/// the TUN local from the shadowsocks `Config` and no-ops route setup, so
/// the test runs unelevated.
pub(crate) fn build_socks_harness(
    ss_addr: SocketAddr,
    method: &str,
    password: &str,
    plugin: Option<String>,
    plugin_opts: Option<String>,
) -> BridgeHarness<SocksOnlyBackend> {
    let entry = build_entry(ss_addr, method, password, plugin, plugin_opts);
    let proxy_config = ProxyConfig {
        server: entry,
        local_port: allocate_ephemeral_port_sync(),
    };
    let state_dir = tempfile::tempdir().expect("create harness state_dir");
    let manager = ProxyManager::new(SocksOnlyBackend::new(), state_dir.path().to_path_buf());
    BridgeHarness {
        manager,
        proxy_config,
        state_dir,
    }
}

/// Build a TUN-mode test harness. Uses the real backend and is therefore
/// admin/root-only. Test functions that call this **must** be guarded with
/// `#[cfg(target_os = "windows")]` (until macOS CI elevation is wired up
/// in a follow-up PR).
pub(crate) fn build_tun_harness(
    ss_addr: SocketAddr,
    method: &str,
    password: &str,
    plugin: Option<String>,
    plugin_opts: Option<String>,
) -> BridgeHarness<RealBackend> {
    let entry = build_entry(ss_addr, method, password, plugin, plugin_opts);
    let proxy_config = ProxyConfig {
        server: entry,
        local_port: allocate_ephemeral_port_sync(),
    };
    let state_dir = tempfile::tempdir().expect("create harness state_dir");
    let manager = ProxyManager::new(RealBackend, state_dir.path().to_path_buf());
    BridgeHarness {
        manager,
        proxy_config,
        state_dir,
    }
}
