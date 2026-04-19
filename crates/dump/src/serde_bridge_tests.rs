use serde::Serialize;

use super::to_dump_value;
use crate::DumpValue;

#[skuld::test]
fn scalars_via_serde() {
    assert_eq!(to_dump_value(&true), DumpValue::Bool(true));
    assert_eq!(to_dump_value(&-3_i32), DumpValue::Int(-3));
    assert_eq!(to_dump_value(&42_u64), DumpValue::UInt(42));
    assert_eq!(to_dump_value(&1.5_f64), DumpValue::Float(1.5));
    assert_eq!(to_dump_value("hi"), DumpValue::String("hi".into()));
}

#[skuld::test]
fn option_some_and_none() {
    let some: Option<i32> = Some(7);
    let none: Option<i32> = None;
    assert_eq!(to_dump_value(&some), DumpValue::Int(7));
    assert_eq!(to_dump_value(&none), DumpValue::Null);
}

#[skuld::test]
fn vec_becomes_seq() {
    let v = vec![1_i32, 2, 3];
    assert_eq!(
        to_dump_value(&v),
        DumpValue::Seq(vec![DumpValue::Int(1), DumpValue::Int(2), DumpValue::Int(3)])
    );
}

#[skuld::test]
fn struct_becomes_map_with_declaration_order() {
    #[derive(Serialize)]
    struct S {
        b: i32,
        a: i32,
    }
    let got = to_dump_value(&S { b: 2, a: 1 });
    assert_eq!(
        got,
        DumpValue::Map(vec![
            (DumpValue::String("b".into()), DumpValue::Int(2)),
            (DumpValue::String("a".into()), DumpValue::Int(1)),
        ])
    );
}

#[skuld::test]
fn enum_variant_shapes() {
    #[derive(Serialize)]
    enum E {
        Unit,
        Newtype(i32),
        Tuple(i32, i32),
        Struct { a: i32 },
    }
    // Unit variant → string
    assert_eq!(to_dump_value(&E::Unit), DumpValue::String("Unit".into()));
    // Newtype → map { Newtype: inner }
    assert_eq!(
        to_dump_value(&E::Newtype(5)),
        DumpValue::Map(vec![(DumpValue::String("Newtype".into()), DumpValue::Int(5))])
    );
    // Tuple → map { Tuple: [...] }
    assert_eq!(
        to_dump_value(&E::Tuple(1, 2)),
        DumpValue::Map(vec![(
            DumpValue::String("Tuple".into()),
            DumpValue::Seq(vec![DumpValue::Int(1), DumpValue::Int(2)]),
        )])
    );
    // Struct variant → map { Struct: { a: 1 } }
    assert_eq!(
        to_dump_value(&E::Struct { a: 1 }),
        DumpValue::Map(vec![(
            DumpValue::String("Struct".into()),
            DumpValue::Map(vec![(DumpValue::String("a".into()), DumpValue::Int(1))]),
        )])
    );
}

#[skuld::test]
fn bytes_roundtrip() {
    // serde_bytes would normally be used; serialize_bytes is only called
    // via the ByteBuf / Bytes wrappers. Check the method directly.
    use serde::Serializer;
    let got = super::DumpSerializer.serialize_bytes(&[1, 2, 3]).unwrap();
    assert_eq!(got, DumpValue::Bytes(vec![1, 2, 3]));
}

#[skuld::test]
fn unit_variants_in_collections() {
    #[derive(Serialize)]
    enum Color {
        Red,
        Blue,
    }
    let v = vec![Color::Red, Color::Blue];
    assert_eq!(
        to_dump_value(&v),
        DumpValue::Seq(vec![DumpValue::String("Red".into()), DumpValue::String("Blue".into()),])
    );
}
