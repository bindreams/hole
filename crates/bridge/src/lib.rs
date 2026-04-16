pub mod diagnostics;
pub mod dispatcher;
pub mod filter;
pub mod foreground;
pub mod gateway;
pub mod group;
pub mod ipc;
pub mod logging;
pub mod platform;
pub mod plugin_recovery;
pub mod plugin_state;
pub mod proxy;
pub mod proxy_manager;
pub mod route_state;
pub mod routing;
pub mod server_test;
pub mod socket;
#[cfg(target_os = "windows")]
pub mod wintun;

// Cross-cutting test helpers. Deviates from the sibling `foo_tests.rs`
// convention used everywhere else in this crate because there is no
// business-logic counterpart: `test_support` is pure test infrastructure
// consumed by multiple `*_tests.rs` files.
#[cfg(test)]
mod test_support;

#[cfg(test)]
fn main() {
    // Test-binary escape hatch: when invoked with this env var set, act as a
    // file holder — open the target path and sleep. Used by
    // `diagnostics::file_locks` live-API tests to have a foreign process
    // holding a file that our enumerator should find. See #208.
    if let Ok(path) = std::env::var("HOLE_TEST_HOLD_FILE") {
        let _f = std::fs::File::open(&path).expect("test holder: open target file");
        std::thread::sleep(std::time::Duration::from_secs(60));
        return;
    }
    skuld::run_all();
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
#[skuld::test]
fn debug_assertions_enabled() {
    assert!(
        cfg!(debug_assertions),
        "tests must be compiled with debug assertions enabled"
    );
}
