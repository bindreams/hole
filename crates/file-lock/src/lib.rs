//! Cross-process exclusive file lock ([`Exclusive`]) for a file in a directory another principal can
//! write. The directory is opened with [`util::dir::Dir`].

mod exclusive;

pub use exclusive::{Exclusive, Refused};

// Install the workspace test subscriber + panic hook.
#[cfg(test)]
hole_test_observability::register!();

#[cfg(test)]
fn main() {
    skuld::run_all();
}
