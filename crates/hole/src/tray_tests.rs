//! The tray handler glue (menu events, rebuilds, dialogs) requires a full
//! Tauri app context and has no automated coverage at any level; the
//! Start-at-Login toggle logic is unit-tested in autostart_tests.rs and the
//! install gate below.

use super::*;

#[skuld::test]
fn install_guard_blocks_reentry_until_dropped() {
    let first = try_begin_install().expect("first acquisition succeeds");
    assert!(try_begin_install().is_none(), "concurrent acquisition is blocked");
    drop(first);
    assert!(try_begin_install().is_some(), "released guard can be re-acquired");
}
