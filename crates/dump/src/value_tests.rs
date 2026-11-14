use std::borrow::Cow;

use super::tag;
use super::DumpValue;

#[skuld::test]
fn int_and_uint_are_distinct_variants() {
    // Same number, different variants: the signed impls produce Int, the
    // unsigned ones UInt. They must not compare equal.
    assert_ne!(DumpValue::Int(1), DumpValue::UInt(1));
}

#[skuld::test]
fn tagged_helper_borrows_static_tag() {
    let v = DumpValue::tagged(tag::SECRET, DumpValue::String("pw".into()));
    match v {
        DumpValue::Tagged(Cow::Borrowed(t), inner) => {
            assert_eq!(t, "secret");
            assert_eq!(*inner, DumpValue::String("pw".into()));
        }
        _ => panic!("expected borrowed tag"),
    }
}

#[skuld::test]
fn tagged_owned_helper_stores_owned_tag() {
    let v = DumpValue::tagged_owned("MyApp:thing".into(), DumpValue::Null);
    match v {
        DumpValue::Tagged(Cow::Owned(t), _) => assert_eq!(t, "MyApp:thing"),
        _ => panic!("expected owned tag"),
    }
}

#[skuld::test]
fn blessed_tag_constants_match_documented_values() {
    // These strings are part of the public contract between Dump impls,
    // the derive macro, and the formatter. Pinning them in a test stops
    // accidental renames.
    assert_eq!(tag::SECRET, "secret");
    assert_eq!(tag::ELIDED, "elided");
    assert_eq!(tag::TRUNCATED, "truncated");
    assert_eq!(tag::DEBUG, "debug");
    assert_eq!(tag::ERROR, "error");
}

#[skuld::test]
fn map_preserves_insertion_order() {
    let m = DumpValue::Map(vec![
        (DumpValue::String("b".into()), DumpValue::Int(2)),
        (DumpValue::String("a".into()), DumpValue::Int(1)),
        (DumpValue::String("c".into()), DumpValue::Int(3)),
    ]);
    let DumpValue::Map(entries) = m else {
        panic!("expected Map")
    };
    let keys: Vec<_> = entries.into_iter().map(|(k, _)| k).collect();
    assert_eq!(
        keys,
        vec![
            DumpValue::String("b".into()),
            DumpValue::String("a".into()),
            DumpValue::String("c".into()),
        ]
    );
}
