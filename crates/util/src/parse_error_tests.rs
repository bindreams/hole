use super::{describe_parse_error, parse_kind};

/// The two echo shapes, both of which quote caller-supplied bytes verbatim:
/// a value of the wrong type, and an unknown variant tag (an arbitrary
/// *string*). Each carries a guard so the test cannot pass against a
/// `serde_json` that stopped echoing.
#[skuld::test]
fn a_description_never_echoes_the_input() {
    const SECRET: &str = "203.0.113.7";

    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct Probe {
        version: u32,
    }

    let mistyped = serde_json::from_str::<Probe>(&format!(r#"{{"version":"{SECRET}"}}"#))
        .expect_err("a string where a u32 is expected must not parse");
    assert!(
        mistyped.to_string().contains(SECRET),
        "guard: serde_json echoes the offending value: {mistyped}"
    );

    let unknown_field = serde_json::from_str::<Probe>(&format!(r#"{{"version":1,"{SECRET}":2}}"#))
        .expect_err("an unknown field must not parse under deny_unknown_fields");
    assert!(
        unknown_field.to_string().contains(SECRET),
        "guard: serde_json echoes the offending field name: {unknown_field}"
    );

    for e in [mistyped, unknown_field] {
        let described = describe_parse_error(&e);
        assert!(!described.contains(SECRET), "the input survived: {described}");
        assert!(
            described.contains("line 1"),
            "position must survive so the message stays actionable: {described}"
        );
    }
}

/// The paired positive: the description has to stay a real diagnostic, so
/// each category renders its own label rather than one flat string.
#[skuld::test]
fn each_category_gets_its_own_label() {
    let syntax = serde_json::from_str::<serde_json::Value>(r#"{"a":,}"#).expect_err("must not parse");
    let data = serde_json::from_str::<u32>(r#""x""#).expect_err("must not parse");
    let eof = serde_json::from_str::<serde_json::Value>("[1,").expect_err("must not parse");

    assert_eq!(parse_kind(&syntax), "syntax error");
    assert_eq!(parse_kind(&data), "data error");
    assert_eq!(parse_kind(&eof), "unexpected end of input");

    // Whole-string equality: the format is what every caller's message is
    // built from, so a change to it should surface here and not only as a
    // `contains("line 1")` that any wording would satisfy.
    assert_eq!(describe_parse_error(&data), "data error (line 1, column 3)");
}
