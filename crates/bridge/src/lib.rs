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
