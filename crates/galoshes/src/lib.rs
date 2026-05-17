#![cfg_attr(v2ray_plugin_missing, allow(dead_code, unused_imports))]

pub mod embedded;
pub mod yamux;

#[cfg(test)]
mod embedded_tests;
#[cfg(test)]
mod yamux_tests;

// Install the workspace test subscriber + panic hook. The dev-dep
// is gated on cfg(test) because it isn't linked in non-test builds.
// See `crates/test-observability/` and bindreams/hole#301.
#[cfg(test)]
hole_test_observability::register!();

#[cfg(test)]
fn main() {
    skuld::run_all();
}
