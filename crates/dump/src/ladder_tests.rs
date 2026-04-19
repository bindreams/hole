//! Ladder priority tests.
//!
//! We construct types that implement specific combinations of Dump,
//! Serialize, and Debug, then invoke `dump!` through each and confirm
//! the expected rung was picked. The macro lives in `lib.rs`; this
//! module exercises it indirectly.

use serde::Serialize;

use crate::value::tag;
use crate::{dump, DumpDisplay, DumpValue};

fn dv(d: &DumpDisplay) -> DumpValue {
    d.value().clone()
}

// Type that implements Dump with an easily recognizable output.
struct OnlyDump;
impl crate::Dump for OnlyDump {
    fn dump(&self) -> DumpValue {
        DumpValue::String("from-Dump".into())
    }
}

// Type that implements only Serialize.
#[derive(Serialize)]
struct OnlySerialize {
    tag: &'static str,
}

// Type that implements only Debug.
struct OnlyDebug;
impl std::fmt::Debug for OnlyDebug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("from-Debug")
    }
}

// Type that implements Dump + Serialize. Dump wins.
struct DumpAndSerialize;
impl crate::Dump for DumpAndSerialize {
    fn dump(&self) -> DumpValue {
        DumpValue::String("chose-Dump".into())
    }
}
impl Serialize for DumpAndSerialize {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str("chose-Serialize")
    }
}

#[skuld::test]
fn picks_dump_when_available() {
    let d = dump!(OnlyDump);
    assert_eq!(dv(&d), DumpValue::String("from-Dump".into()));
}

#[skuld::test]
fn picks_serde_when_no_dump() {
    let d = dump!(OnlySerialize { tag: "via-serde" });
    assert_eq!(
        dv(&d),
        DumpValue::Map(vec![(
            DumpValue::String("tag".into()),
            DumpValue::String("via-serde".into()),
        )])
    );
}

#[skuld::test]
fn picks_debug_when_no_dump_no_serde() {
    let d = dump!(OnlyDebug);
    assert_eq!(
        dv(&d),
        DumpValue::tagged(tag::DEBUG, DumpValue::String("from-Debug".into()))
    );
}

#[skuld::test]
fn dump_beats_serialize_in_priority() {
    let d = dump!(DumpAndSerialize);
    assert_eq!(dv(&d), DumpValue::String("chose-Dump".into()));
}

// References, double references, rvalues, and Box all produce the same
// output for a given inner type.

#[skuld::test]
fn same_output_for_references_and_rvalues() {
    // Rvalue, value, reference, double reference — all produce identical
    // output when the inner type implements Dump. (Box<T>: Dump ships in
    // the impls commit.)
    let x = OnlyDump;
    let rx = &x;
    let rrx = &rx;

    let a = dv(&dump!(OnlyDump));
    let b = dv(&dump!(x));
    let c = dv(&dump!(rx));
    let d = dv(&dump!(rrx));
    assert_eq!(a, b);
    assert_eq!(a, c);
    assert_eq!(a, d);
}

#[skuld::test]
fn rvalue_expression_evaluates_once() {
    // If the macro double-evaluated its argument, the counter would
    // advance twice.
    use std::cell::Cell;
    thread_local! {
        static COUNTER: Cell<i32> = const { Cell::new(0) };
    }
    fn bump() -> i32 {
        COUNTER.with(|c| {
            c.set(c.get() + 1);
            c.get()
        })
    }
    let _ = dump!(bump());
    assert_eq!(COUNTER.with(|c| c.get()), 1);
}
