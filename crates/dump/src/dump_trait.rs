//! The [`Dump`] trait.

use crate::DumpValue;

/// Produce a YAML-shaped representation of a value for logging.
///
/// Unlike [`std::fmt::Debug`], `Dump` is allowed (and encouraged) to
/// omit fields, reorder, tag values as secret, or otherwise present
/// information in a form that serves a human reader. A failing Dump
/// impl reports the failure as `DumpValue::tagged(tag::ERROR, ...)`
/// rather than panicking — the trait is infallible by construction so
/// that logging can never itself fail.
pub trait Dump {
    fn dump(&self) -> DumpValue;
}

/// Blanket `&T`: referencing a Dump type dumps the same way.
impl<T: Dump + ?Sized> Dump for &T {
    fn dump(&self) -> DumpValue {
        (**self).dump()
    }
}

/// Blanket `&mut T`: mutably-referencing a Dump type dumps the same way.
impl<T: Dump + ?Sized> Dump for &mut T {
    fn dump(&self) -> DumpValue {
        (**self).dump()
    }
}

#[cfg(test)]
#[path = "dump_trait_tests.rs"]
mod dump_trait_tests;
