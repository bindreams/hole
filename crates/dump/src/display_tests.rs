use super::DumpDisplay;
use crate::value::tag;
use crate::DumpValue;

#[skuld::test]
fn display_renders_via_default_formatter() {
    let d = DumpDisplay::new(DumpValue::String("hi".into()));
    assert_eq!(format!("{}", d), "hi");
}

#[skuld::test]
fn display_redacts_secrets_by_default() {
    let d = DumpDisplay::new(DumpValue::tagged(tag::SECRET, DumpValue::String("pw".into())));
    assert_eq!(format!("{}", d), "!secret [REDACTED]");
}

#[skuld::test]
fn display_is_cloneable() {
    let d = DumpDisplay::new(DumpValue::Int(1));
    let d2 = d.clone();
    assert_eq!(format!("{}", d), format!("{}", d2));
}
