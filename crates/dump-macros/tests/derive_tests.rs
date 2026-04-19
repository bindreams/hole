//! Integration tests for `#[derive(Dump)]`.
//!
//! Kept as an integration test rather than a unit test because the
//! derive macro emits `::dump::...` paths, which resolve to the `dump`
//! crate only from a separate compilation unit.

use dump::{tag, Dump, DumpValue};
use dump_macros::Dump as DeriveDump;

fn main() {
    skuld::run_all();
}

// Structs =============================================================================================================

#[derive(DeriveDump)]
struct Empty;

#[derive(DeriveDump)]
struct Point {
    x: i32,
    y: i32,
}

#[derive(DeriveDump)]
struct Pair(i32, i32);

#[derive(DeriveDump)]
struct Credentials {
    user: String,
    #[dump(secret)]
    password: String,
    #[dump(skip)]
    _internal: i32,
    #[dump(rename = "api-key")]
    api_key: String,
}

#[skuld::test]
fn unit_struct_dumps_as_null() {
    assert_eq!(Empty.dump(), DumpValue::Null);
}

#[skuld::test]
fn named_struct_dumps_as_map_in_declaration_order() {
    let p = Point { x: 1, y: 2 };
    assert_eq!(
        p.dump(),
        DumpValue::Map(vec![
            (DumpValue::String("x".into()), DumpValue::Int(1)),
            (DumpValue::String("y".into()), DumpValue::Int(2)),
        ])
    );
}

#[skuld::test]
fn tuple_struct_dumps_as_seq() {
    assert_eq!(
        Pair(10, 20).dump(),
        DumpValue::Seq(vec![DumpValue::Int(10), DumpValue::Int(20)])
    );
}

#[skuld::test]
fn field_attributes_work() {
    let c = Credentials {
        user: "alice".into(),
        password: "hunter2".into(),
        _internal: 99,
        api_key: "xyz".into(),
    };
    assert_eq!(
        c.dump(),
        DumpValue::Map(vec![
            (DumpValue::String("user".into()), DumpValue::String("alice".into())),
            (
                DumpValue::String("password".into()),
                DumpValue::tagged(tag::SECRET, DumpValue::String("hunter2".into())),
            ),
            // _internal is skipped.
            (DumpValue::String("api-key".into()), DumpValue::String("xyz".into()),),
        ])
    );
}

// Enums ===============================================================================================================

#[derive(DeriveDump)]
enum Shape {
    Dot,
    Line(i32),
    Segment(i32, i32),
    Rect { w: i32, h: i32 },
}

#[skuld::test]
fn unit_variant_dumps_as_string() {
    assert_eq!(Shape::Dot.dump(), DumpValue::String("Dot".into()));
}

#[skuld::test]
fn newtype_variant_dumps_as_single_key_map() {
    assert_eq!(
        Shape::Line(5).dump(),
        DumpValue::Map(vec![(DumpValue::String("Line".into()), DumpValue::Int(5),)])
    );
}

#[skuld::test]
fn tuple_variant_dumps_as_map_with_seq_payload() {
    assert_eq!(
        Shape::Segment(1, 2).dump(),
        DumpValue::Map(vec![(
            DumpValue::String("Segment".into()),
            DumpValue::Seq(vec![DumpValue::Int(1), DumpValue::Int(2)]),
        )])
    );
}

#[skuld::test]
fn struct_variant_dumps_as_map_with_map_payload() {
    assert_eq!(
        Shape::Rect { w: 3, h: 4 }.dump(),
        DumpValue::Map(vec![(
            DumpValue::String("Rect".into()),
            DumpValue::Map(vec![
                (DumpValue::String("w".into()), DumpValue::Int(3)),
                (DumpValue::String("h".into()), DumpValue::Int(4)),
            ]),
        )])
    );
}

// Generic structs =====================================================================================================

#[derive(DeriveDump)]
struct Wrapper<T> {
    inner: T,
}

#[skuld::test]
fn generic_struct_works_with_dump_bound() {
    let w = Wrapper { inner: 7_i32 };
    assert_eq!(
        w.dump(),
        DumpValue::Map(vec![(DumpValue::String("inner".into()), DumpValue::Int(7),)])
    );
}
