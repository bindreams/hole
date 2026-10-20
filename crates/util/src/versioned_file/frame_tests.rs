use super::{read_version, Version};

fn parsed(json: &str, unversioned_as: Option<u32>) -> Result<Version, String> {
    read_version(json.as_bytes(), unversioned_as).map_err(|f| f.to_string())
}

/// The version of a document that must fit a `u32`.
fn version(json: &str, unversioned_as: Option<u32>) -> Result<u32, String> {
    parsed(json, unversioned_as).map(|v| match v {
        Version::Known(n) => n,
        Version::BeyondU32 => panic!("{json}: beyond u32"),
    })
}

#[skuld::test]
fn a_positive_integer_above_u32_max_is_beyond_u32_whatever_its_size() {
    for token in [
        "4294967296",
        "9007199254740993",
        "18446744073709551616",
        "99999999999999999999999999",
    ] {
        let body = format!(r#"{{"x":1,"version":{token}}}"#);
        assert_eq!(parsed(&body, None), Ok(Version::BeyondU32), "{body}");
        assert_eq!(parsed(&body, Some(1)), Ok(Version::BeyondU32), "{body} with a default");
    }
    assert_eq!(parsed(r#"{"version": 4294967296 }"#, None), Ok(Version::BeyondU32));
    assert_eq!(parsed(r#"{"version":4294967295}"#, None), Ok(Version::Known(u32::MAX)));
}

#[skuld::test]
fn within_splits_readable_from_newer() {
    assert_eq!(Version::Known(3).within(3), Ok(3));
    assert_eq!(Version::Known(1).within(3), Ok(1));
    assert_eq!(Version::Known(4).within(3), Err(Some(4)));
    assert_eq!(Version::BeyondU32.within(3), Err(None));
    assert_eq!(Version::BeyondU32.within(u32::MAX), Err(None));
    assert_eq!(Version::Known(u32::MAX).within(u32::MAX), Ok(u32::MAX));
}

#[skuld::test]
fn a_positive_integer_version_is_read_wherever_the_key_sits() {
    assert_eq!(version(r#"{"version":1}"#, None), Ok(1));
    assert_eq!(version(r#"{"a":[1,{"version":9}],"version":7,"b":"x"}"#, None), Ok(7));
    assert_eq!(version(r#"{"version":4294967295}"#, None), Ok(u32::MAX));
}

#[skuld::test]
fn version_zero_negative_string_fractional_is_corrupt() {
    for body in [
        r#"{"version":0}"#,
        r#"{"version":-1}"#,
        r#"{"version":"1"}"#,
        r#"{"version":1.5}"#,
        r#"{"version":1.0}"#,
        r#"{"version":1e0}"#,
        r#"{"version":true}"#,
        r#"{"version":null}"#,
        r#"{"version":[1]}"#,
        r#"{"version":{"v":1}}"#,
        // Not integer syntax, however large.
        r#"{"version":4294967296.0}"#,
        r#"{"version":1e20}"#,
        r#"{"version":-4294967296}"#,
        r#"{"version":"4294967296"}"#,
    ] {
        assert!(version(body, None).is_err(), "{body} must be corrupt");
        // A declared default must not rescue a version that is present and wrong.
        assert!(
            version(body, Some(1)).is_err(),
            "{body} must be corrupt even with a default"
        );
    }
}

#[skuld::test]
fn a_missing_version_is_corrupt_unless_the_file_declares_one() {
    assert!(version("{}", None).is_err());
    assert!(version(r#"{"other":1}"#, None).is_err());
    assert_eq!(version("{}", Some(1)), Ok(1));
    assert_eq!(version(r#"{"other":1}"#, Some(3)), Ok(3));
}

#[skuld::test]
fn unversioned_reads_as_declared_version_only_when_declared() {
    // A declared default applies to a missing key and to nothing else.
    assert_eq!(version("{}", Some(2)), Ok(2));
    assert_eq!(version(r#"{"version":5}"#, Some(2)), Ok(5));
    assert!(version("{}", None).is_err());
}

#[skuld::test]
fn non_object_top_level_is_corrupt() {
    for body in [
        "[1]",
        "[]",
        "[1,2,3]",
        "7",
        r#""version""#,
        "true",
        "null",
        "",
        "   ",
        "{",
        r#"{"version":1"#,
    ] {
        assert!(version(body, None).is_err(), "{body:?} must be corrupt");
        assert!(
            version(body, Some(1)).is_err(),
            "{body:?} must be corrupt even with a default"
        );
    }
}

#[skuld::test]
fn a_duplicated_version_key_is_corrupt() {
    assert!(version(r#"{"version":1,"version":2}"#, None).is_err());
}

#[skuld::test]
fn trailing_bytes_after_the_object_are_corrupt() {
    assert!(version(r#"{"version":1} x"#, None).is_err());
}

#[skuld::test]
fn a_failure_never_echoes_the_input() {
    const SECRET: &str = "203.0.113.7";
    for body in [
        format!(r#"{{"version":"{SECRET}"}}"#),
        format!(r#"{{"{SECRET}":1}}"#),
        format!(r#"["{SECRET}"]"#),
        format!(r#"{{"version":1,"{SECRET}":"#),
    ] {
        let failure = read_version(body.as_bytes(), None).expect_err("must be corrupt");
        assert!(!failure.to_string().contains(SECRET), "{body}: {failure}");
        assert!(!format!("{failure:?}").contains(SECRET), "{body}: {failure:?}");
    }
}
