pub mod gateway;
pub mod group;
pub mod ipc;
pub mod logging;
pub mod platform;
pub mod proxy;
pub mod proxy_manager;
pub mod routing;
pub mod socket;

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
