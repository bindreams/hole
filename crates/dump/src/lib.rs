//! YAML-shaped representation for logging.
//!
//! `Dump` complements [`std::fmt::Debug`] and [`std::fmt::Display`]. Debug
//! favors unambiguous, Rust-syntax output (closer to Python's `__repr__`);
//! Display favors compact user-facing strings (closer to `__str__`). Dump
//! is the third leg: human-readable, multi-line, YAML-shaped output
//! suited for logging large structured values where Debug jams everything
//! onto one unreadable line.
//!
//! This commit introduces only the data model and trait; the `dump!`
//! macro, YAML formatter, derive macro, and built-in impls ship in
//! subsequent commits.

mod display;
mod dump_trait;
mod format;
mod value;

pub use display::DumpDisplay;
pub use dump_trait::Dump;
pub use format::YamlFormatter;
pub use value::{tag, DumpValue};

#[cfg(test)]
fn main() {
    skuld::run_all();
}
