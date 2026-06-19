pub mod cutover;
pub mod diagnostics;
pub mod dispatcher;
pub mod dns;
pub mod dns_state;
pub mod endpoint;
pub mod filter;
pub mod foreground;
pub mod group;
pub mod hole_router;
pub mod ipc;
pub mod logging;
pub mod platform;
pub mod plugin_recovery;
pub mod plugin_state;
pub mod proxy;
pub mod proxy_manager;
pub mod server_test;
pub mod socket;

// Cross-cutting test helpers. Deviates from the sibling `foo_tests.rs`
// convention used everywhere else in this crate because there is no
// business-logic counterpart: `test_support` is pure test infrastructure
// consumed by multiple `*_tests.rs` files.
#[cfg(test)]
mod test_support;

// The cross-implementation interop suite (ex-ray ↔ stock v2ray-plugin) was
// relocated to the `plugin-e2e` crate (#435) so it runs on a plugin-owned,
// Linux-inclusive matrix instead of Hole's Win+mac bridge CI.

// Install the workspace test subscriber + panic hook. The dev-dep
// is gated on cfg(test) because it isn't linked in non-test builds.
// See `crates/test-observability/` and bindreams/hole#301.
#[cfg(test)]
hole_test_observability::register!();

#[cfg(test)]
fn main() {
    // Subprocess re-exec for the DistHarness panic-hook regression
    // test. Dispatches into the child-side handler BEFORE skuld
    // initializes, so the deliberate panic and libtest's arg parsing are
    // bypassed for the child (unconditional dispatch on the env var).
    // See `test_support/dist_harness_panic_hook_tests.rs`.
    if std::env::var_os("HOLE_DIST_HARNESS_PANIC_TEST").is_some() {
        test_support::dist_harness_panic_hook_tests::run_child();
        std::process::exit(0);
    }
    foreground_child_hook::maybe_run();
    skuld::run_all();
}

/// Self-reinvoke hook for the CTRL_BREAK shutdown test: in child mode, call
/// shutdown_signal() (installs handlers eagerly), print a ready line, then
/// block on the future and exit 0 when the signal lands.
#[cfg(test)]
pub(crate) mod foreground_child_hook {
    pub const MODE_ENV: &str = "HOLE_BRIDGE_TEST_SHUTDOWN_CHILD";
    pub fn maybe_run() {
        if std::env::var_os(MODE_ENV).is_none() {
            return;
        }
        let rt = tokio::runtime::Runtime::new().expect("rt");
        rt.block_on(async {
            let fut = crate::foreground::shutdown_signal();
            println!("HANDLER-READY");
            use std::io::Write as _;
            std::io::stdout().flush().ok();
            fut.await;
        });
        std::process::exit(0);
    }
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
