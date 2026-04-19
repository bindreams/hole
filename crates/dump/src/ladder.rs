//! Compile-time trait-priority resolution for `dump!`.
//!
//! On stable Rust we cannot write `if constexpr (T: Dump) ... else if
//! (T: Serialize) ...` directly — the trait solver forbids overlapping
//! blanket impls. The canonical workaround is *autoref-specialization*:
//! define three same-named methods on types at different reference
//! depths. The `dump!` macro calls through a `(&&&Wrap(&v)).__pick__()`
//! receiver, and Rust's method resolution starts at the deepest level
//! and auto-derefs down on each failed rung. Result: Dump > Serialize >
//! Debug at compile time with no runtime cost.
//!
//! This module is `#[doc(hidden)]` via the `__private` re-export in
//! `lib.rs`; the only intended caller is the `dump!` macro.

use std::fmt::Debug;

use serde::Serialize;

use crate::{debug_bridge, serde_bridge, Dump, DumpValue};

/// Transparent wrapper used by the `dump!` macro. Holds a `&T` so the
/// macro can evaluate its argument into a temp via `match &$v {...}`
/// and pass it through the ladder without moving.
#[doc(hidden)]
pub struct Wrap<T>(pub T);

// Level 1 — highest priority, picked first because method resolution
// checks this ref depth before auto-dereffing down.
#[doc(hidden)]
pub trait DumpPick {
    fn __pick__(self) -> DumpValue;
}

impl<T: Dump + ?Sized> DumpPick for &&&Wrap<&T> {
    #[inline]
    fn __pick__(self) -> DumpValue {
        self.0.dump()
    }
}

// Level 2 — one auto-deref down from the call-site receiver.
#[doc(hidden)]
pub trait SerializePick {
    fn __pick__(self) -> DumpValue;
}

impl<T: Serialize + ?Sized> SerializePick for &&Wrap<&T> {
    #[inline]
    fn __pick__(self) -> DumpValue {
        serde_bridge::to_dump_value(self.0)
    }
}

// Level 3 — two auto-derefs down.
#[doc(hidden)]
pub trait DebugPick {
    fn __pick__(self) -> DumpValue;
}

impl<T: Debug + ?Sized> DebugPick for &Wrap<&T> {
    #[inline]
    fn __pick__(self) -> DumpValue {
        debug_bridge::to_dump_value(self.0)
    }
}

#[cfg(test)]
#[path = "ladder_tests.rs"]
mod ladder_tests;
