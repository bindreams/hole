//! [`DumpDisplay`] — a [`std::fmt::Display`] wrapper around a
//! [`DumpValue`].

use std::fmt;

use crate::format::YamlFormatter;
use crate::DumpValue;

/// Owns a [`DumpValue`] and renders it as YAML via [`std::fmt::Display`].
///
/// This is what the `dump!` macro (added in a later commit) returns.
/// `Clone` is derived because `tracing` captures field values into
/// span storage, and non-`Clone` wrappers are an ergonomic trap.
#[derive(Clone, Debug)]
pub struct DumpDisplay {
    value: DumpValue,
}

impl DumpDisplay {
    pub fn new(value: DumpValue) -> Self {
        Self { value }
    }

    pub fn value(&self) -> &DumpValue {
        &self.value
    }

    pub fn into_value(self) -> DumpValue {
        self.value
    }
}

impl fmt::Display for DumpDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        YamlFormatter::default().write(f, &self.value)
    }
}

#[cfg(test)]
#[path = "display_tests.rs"]
mod display_tests;
