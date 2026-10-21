//! Cross-process exclusive file lock. See [`Exclusive`].

mod exclusive;

pub use exclusive::{Exclusive, Refused};

// Install the workspace test subscriber + panic hook.
#[cfg(test)]
hole_test_observability::register!();

#[cfg(test)]
fn main() {
    skuld::run_all();
}
