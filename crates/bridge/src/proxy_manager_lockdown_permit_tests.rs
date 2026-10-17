//! The standing lockdown cover's App-ID permit, end to end through
//! `start_inner`: the file `install_lockdown` is asked to permit must be the
//! plugin binary that actually ran. Needs the staged dist directory (`DIST_BIN`)
//! for a real, spawnable `ex-ray`.

// `CancellationToken::new` is the test harness's root signal here, matching
// the sanctioned-test-file exception in `proxy_manager_tests.rs` (clippy.toml's
// "Bridge cancellation contract" carve-out).
#![allow(clippy::disallowed_methods)]

use super::proxy_manager_tests::{rt, test_config, MockProxy, MockRouting};
use super::*;
use crate::test_support::dist_fixture::*;
use crate::test_support::skuld_fixtures::*;
use std::path::Path;
use tun_engine::routing::failclosed::lockdown_state;

/// A Full-mode start with the kill switch on and a real `ex-ray` beside the
/// (staged) bridge exe hands `install_lockdown` that `ex-ray`, then the bridge's
/// own exe.
#[skuld::test(labels = [DIST_BIN])]
fn start_permits_the_plugin_binary_that_ran(#[fixture(dist_dir)] dist: &Path) {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        lockdown_state::set_enabled(dir.path(), true, None).unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let routing_state = routing.state();
        let mut pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());
        assert!(
            pm.standing_cover_expected(),
            "HARNESS: the lockdown intent set above must make install_lockdown reachable"
        );
        pm.set_bridge_exe_for_test(dist.join(if cfg!(windows) { "hole.exe" } else { "hole" }));

        let mut config = test_config();
        config.server.plugin = Some("ex-ray".into());
        pm.start(&config).await.unwrap();

        let ex_ray = dist
            .canonicalize()
            .unwrap()
            .join(if cfg!(windows) { "ex-ray.exe" } else { "ex-ray" });
        let app_ids = routing_state
            .last_lockdown_app_ids
            .lock()
            .unwrap()
            .clone()
            .expect("install_lockdown must have been called");
        assert_eq!(app_ids, vec![ex_ray, std::env::current_exe().unwrap()]);

        pm.stop().await.unwrap();
    });
}
