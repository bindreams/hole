pub mod filter;
pub mod foreground;
pub mod gateway;
pub mod group;
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

// Diagnostic test-only module for issue #165 — Windows CI loopback
// timeout regression. This module is throwaway and will be removed in
// the same PR that ships the root-cause fix.
#[cfg(test)]
mod server_test_diag;

// Test harness: initialize a tracing subscriber so `RUST_LOG` works
// during `cargo test`. Originally added during the investigation of
// issue #165 to surface `shadowsocks_service::*` listener logs; kept
// as permanent fixture hardening.
#[cfg(test)]
fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .with_writer(std::io::stderr)
        .try_init();
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
