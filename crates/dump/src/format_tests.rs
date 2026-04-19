use super::YamlFormatter;
use crate::value::tag;
use crate::DumpValue;

fn emit(v: &DumpValue) -> String {
    YamlFormatter::default().to_string(v)
}

// Scalars =============================================================================================================

#[skuld::test]
fn null_emits_tilde() {
    assert_eq!(emit(&DumpValue::Null), "~");
}

#[skuld::test]
fn bools() {
    assert_eq!(emit(&DumpValue::Bool(true)), "true");
    assert_eq!(emit(&DumpValue::Bool(false)), "false");
}

#[skuld::test]
fn ints() {
    assert_eq!(emit(&DumpValue::Int(0)), "0");
    assert_eq!(emit(&DumpValue::Int(-42)), "-42");
    assert_eq!(emit(&DumpValue::Int(i128::MAX)), i128::MAX.to_string());
    assert_eq!(emit(&DumpValue::UInt(u128::MAX)), u128::MAX.to_string());
}

#[skuld::test]
fn floats_including_specials() {
    assert_eq!(emit(&DumpValue::Float(2.5)), "2.5");
    // Integer-valued floats gain ".0" so YAML readers parse them as floats.
    assert_eq!(emit(&DumpValue::Float(1.0)), "1.0");
    assert_eq!(emit(&DumpValue::Float(f64::NAN)), ".nan");
    assert_eq!(emit(&DumpValue::Float(f64::INFINITY)), ".inf");
    assert_eq!(emit(&DumpValue::Float(f64::NEG_INFINITY)), "-.inf");
}

#[skuld::test]
fn plain_string() {
    assert_eq!(emit(&DumpValue::String("hello".into())), "hello");
}

#[skuld::test]
fn string_that_looks_like_bool_gets_quoted() {
    assert_eq!(emit(&DumpValue::String("true".into())), r#""true""#);
    assert_eq!(emit(&DumpValue::String("null".into())), r#""null""#);
}

#[skuld::test]
fn string_that_looks_like_number_gets_quoted() {
    assert_eq!(emit(&DumpValue::String("42".into())), r#""42""#);
    assert_eq!(emit(&DumpValue::String("3.14".into())), r#""3.14""#);
}

#[skuld::test]
fn string_with_leading_indicator_gets_quoted() {
    assert_eq!(emit(&DumpValue::String("- item".into())), r#""- item""#);
    assert_eq!(emit(&DumpValue::String("#hash".into())), "\"#hash\"");
}

#[skuld::test]
fn string_with_colon_space_gets_quoted() {
    assert_eq!(emit(&DumpValue::String("a: b".into())), r#""a: b""#);
}

#[skuld::test]
fn string_with_control_char_escapes() {
    assert_eq!(emit(&DumpValue::String("\t".into())), r#""\t""#);
    assert_eq!(emit(&DumpValue::String("\x01".into())), r#""\x01""#);
}

#[skuld::test]
fn multiline_string_uses_block_scalar() {
    let out = emit(&DumpValue::String("line1\nline2".into()));
    assert_eq!(out, "|-\nline1\nline2");
}

#[skuld::test]
fn bytes_emit_as_yaml_binary_base64() {
    assert_eq!(emit(&DumpValue::Bytes(b"hi".to_vec())), "!!binary aGk=");
    assert_eq!(emit(&DumpValue::Bytes(vec![])), "!!binary ");
}

// Seq / Map ===========================================================================================================

#[skuld::test]
fn empty_seq_and_map_use_flow_form() {
    assert_eq!(emit(&DumpValue::Seq(vec![])), "[]");
    assert_eq!(emit(&DumpValue::Map(vec![])), "{}");
}

#[skuld::test]
fn simple_seq() {
    let v = DumpValue::Seq(vec![DumpValue::Int(1), DumpValue::Int(2), DumpValue::Int(3)]);
    assert_eq!(emit(&v), "- 1\n- 2\n- 3");
}

#[skuld::test]
fn simple_map() {
    let v = DumpValue::Map(vec![
        (DumpValue::String("a".into()), DumpValue::Int(1)),
        (DumpValue::String("b".into()), DumpValue::Int(2)),
    ]);
    assert_eq!(emit(&v), "a: 1\nb: 2");
}

#[skuld::test]
fn nested_map_in_map() {
    let inner = DumpValue::Map(vec![
        (DumpValue::String("x".into()), DumpValue::Int(1)),
        (DumpValue::String("y".into()), DumpValue::Int(2)),
    ]);
    let outer = DumpValue::Map(vec![(DumpValue::String("pt".into()), inner)]);
    assert_eq!(emit(&outer), "pt:\n  x: 1\n  y: 2");
}

#[skuld::test]
fn nested_seq_in_map() {
    let v = DumpValue::Map(vec![(
        DumpValue::String("xs".into()),
        DumpValue::Seq(vec![DumpValue::Int(1), DumpValue::Int(2)]),
    )]);
    assert_eq!(emit(&v), "xs:\n  - 1\n  - 2");
}

#[skuld::test]
fn nested_map_in_seq() {
    let v = DumpValue::Seq(vec![DumpValue::Map(vec![(
        DumpValue::String("a".into()),
        DumpValue::Int(1),
    )])]);
    assert_eq!(emit(&v), "-\n  a: 1");
}

#[skuld::test]
fn non_string_map_key_uses_complex_form() {
    let v = DumpValue::Map(vec![(DumpValue::Int(1), DumpValue::String("one".into()))]);
    assert_eq!(emit(&v), "? 1\n: one");
}

// Tagged values =======================================================================================================

#[skuld::test]
fn secret_redacts_by_default() {
    let v = DumpValue::tagged(tag::SECRET, DumpValue::String("hunter2".into()));
    assert_eq!(emit(&v), "!secret [REDACTED]");
}

#[skuld::test]
fn secret_shown_when_redaction_disabled() {
    let v = DumpValue::tagged(tag::SECRET, DumpValue::String("hunter2".into()));
    let out = YamlFormatter::new().redact_secrets(false).to_string(&v);
    assert_eq!(out, "!secret hunter2");
}

#[skuld::test]
fn elided_renders_with_reason() {
    let v = DumpValue::tagged(tag::ELIDED, DumpValue::String("Instant".into()));
    assert_eq!(emit(&v), "!elided [elided: Instant]");
}

#[skuld::test]
fn debug_tag_emits_inline_string() {
    let v = DumpValue::tagged(tag::DEBUG, DumpValue::String("Foo(42)".into()));
    assert_eq!(emit(&v), "!debug Foo(42)");
}

#[skuld::test]
fn user_tag_passthrough() {
    let v = DumpValue::tagged_owned("MyApp:thing".into(), DumpValue::Int(7));
    assert_eq!(emit(&v), "!MyApp:thing 7");
}

#[skuld::test]
fn tagged_map_goes_on_new_line() {
    let v = DumpValue::tagged(
        tag::TRUNCATED,
        DumpValue::Map(vec![
            (DumpValue::String("shown".into()), DumpValue::Int(3)),
            (DumpValue::String("total".into()), DumpValue::Int(10)),
        ]),
    );
    assert_eq!(emit(&v), "!truncated\nshown: 3\ntotal: 10");
}

// Secret redaction at depth ===========================================================================================

#[skuld::test]
fn secret_redacts_even_inside_structure() {
    let v = DumpValue::Map(vec![
        (DumpValue::String("user".into()), DumpValue::String("alice".into())),
        (
            DumpValue::String("password".into()),
            DumpValue::tagged(tag::SECRET, DumpValue::String("hunter2".into())),
        ),
    ]);
    assert_eq!(emit(&v), "user: alice\npassword: !secret [REDACTED]");
}

// Configurable indent =================================================================================================

#[skuld::test]
fn indent_width_is_configurable() {
    let v = DumpValue::Map(vec![(
        DumpValue::String("a".into()),
        DumpValue::Map(vec![(DumpValue::String("b".into()), DumpValue::Int(1))]),
    )]);
    assert_eq!(YamlFormatter::new().indent(4).to_string(&v), "a:\n    b: 1");
}
