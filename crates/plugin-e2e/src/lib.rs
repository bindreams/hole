//! Plugin interop/e2e test area.
//!
//! `lib` = the shared harness (real `shadowsocks_service` server +/- a
//! server-mode plugin, self-signed certs, a fake sentinel, a garter-based
//! client `roundtrip` driver, and binary locators). Consumed as a dev-dep by
//! `hole-bridge` (which reuses the harness for its own bridge tests) and by
//! this crate's own `tests/` (the ex-ray/galoshes system-test suites).
//!
//! `DistHarness` deliberately stays in `hole-bridge` — it spawns `hole bridge
//! run` and is Hole-specific. This crate touches no `hole-bridge` code.

pub mod certs;
pub mod locators;
pub mod roundtrip;
pub mod sentinel;
pub mod ssserver;
pub mod util;

// Install the workspace test subscriber + panic hook for this crate's test
// binaries. The dev-dep is gated on cfg(test).
#[cfg(test)]
hole_test_observability::register!();

#[cfg(test)]
fn main() {
    skuld::run_all();
}
