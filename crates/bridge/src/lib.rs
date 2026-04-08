pub mod foreground;
pub mod gateway;
pub mod group;
pub mod guards;
pub mod ipc;
pub mod logging;
pub mod platform;
pub mod proxy;
pub mod proxy_manager;
pub mod route_state;
pub mod routing;
pub mod server_test;
pub mod socket;
#[cfg(target_os = "windows")]
pub mod wintun;

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
