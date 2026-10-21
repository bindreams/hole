//! Cross-process exclusive file lock ([`Exclusive`]) and a directory opened without following a
//! symlink ([`Dir`]), for files in a directory another principal can write.

pub mod dir;
mod exclusive;

pub use dir::Dir;
pub use exclusive::{Exclusive, Refused};

// Install the workspace test subscriber + panic hook.
#[cfg(test)]
hole_test_observability::register!();

#[cfg(test)]
fn main() {
    skuld::run_all();
}
