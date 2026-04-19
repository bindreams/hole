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

mod debug_bridge;
mod display;
mod dump_trait;
mod format;
mod impls;
mod ladder;
mod serde_bridge;
mod value;

pub use display::DumpDisplay;
pub use dump_macros::Dump as DeriveDump;
pub use dump_trait::Dump;
pub use format::YamlFormatter;
pub use value::{tag, DumpValue};

/// Convenience: render a [`DumpValue`] to a YAML string with default
/// formatter settings.
pub fn to_yaml(value: &DumpValue) -> String {
    YamlFormatter::default().to_string(value)
}

#[doc(hidden)]
pub mod __private {
    pub use crate::ladder::{DebugPick, DumpPick, SerializePick, Wrap};
}

/// Render any value as YAML for logging, picking at compile time
/// between [`Dump`], [`serde::Serialize`], and [`std::fmt::Debug`] in
/// that priority order.
///
/// Returns a [`DumpDisplay`] that implements [`std::fmt::Display`], so
/// it drops into `tracing::info!("state: {}", dump!(state))` and into
/// field positions as `info!(state = %dump!(state), "...")`.
#[macro_export]
macro_rules! dump {
    ($v:expr) => {{
        // `match &$v { tmp => ... }` extends temporaries' lifetime to
        // cover the arm, so `dump!(some_function())` sees the rvalue
        // through a borrow without moving.
        match &$v {
            __dump_tmp => {
                #[allow(unused_imports)]
                use $crate::__private::{DebugPick as _, DumpPick as _, SerializePick as _};
                $crate::DumpDisplay::new((&&&$crate::__private::Wrap(__dump_tmp)).__pick__())
            }
        }
    }};
}

#[cfg(test)]
fn main() {
    skuld::run_all();
}
