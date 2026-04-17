pub mod dispatcher;
pub mod filter;
pub mod foreground;
pub mod group;
pub mod ipc;
pub mod logging;
pub mod platform;
pub mod plugin_recovery;
pub mod plugin_state;
pub mod proxy;
pub mod proxy_manager;
pub mod retry;
pub mod server_test;
pub mod socket;

// Cross-cutting test helpers. Deviates from the sibling `foo_tests.rs`
// convention used everywhere else in this crate because there is no
// business-logic counterpart: `test_support` is pure test infrastructure
// consumed by multiple `*_tests.rs` files.
#[cfg(test)]
mod test_support;

#[cfg(test)]
fn main() {
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
