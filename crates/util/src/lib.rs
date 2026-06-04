//! Small cross-platform utilities shared across the workspace.
//!
//! - [`port_alloc`] — ephemeral port allocation with multi-transport
//!   verification and retry around Windows bind races.
//! - [`retry`] — exponential-backoff retry helpers + transient-error
//!   predicates (`is_bind_race` / `is_file_contention`).
//!
//! Apache-2.0 (unlike Hole's own GPL crates) so the Apache plugin world
//! (`garter`/`galoshes`/`plugin-e2e`) can depend on it alongside Hole's GPL
//! crates without license friction. Nothing here is Hole- or
//! shadowsocks-specific.

pub mod port_alloc;
pub mod retry;

// Install the workspace test subscriber + panic hook. The dev-dep is gated on
// cfg(test) because it isn't linked in non-test builds.
#[cfg(test)]
hole_test_observability::register!();

#[cfg(test)]
fn main() {
    skuld::run_all();
}
