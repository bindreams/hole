use super::*;

#[skuld::test]
fn version_is_not_empty() {
    assert!(!VERSION.is_empty());
}

#[skuld::test]
fn version_starts_with_digit() {
    assert!(
        VERSION.starts_with(|c: char| c.is_ascii_digit()),
        "version should start with a digit, got: {VERSION}"
    );
}

#[skuld::test]
fn version_has_valid_base() {
    // The base is everything before the first '-' (if any).
    let base = VERSION.split('-').next().unwrap();
    // Strip optional ".dirty" suffix from the base (for on-tag dirty builds: "0.1.0.dirty").
    let base = base.strip_suffix(".dirty").unwrap_or(base);
    let parts: Vec<&str> = base.split('.').collect();
    assert_eq!(parts.len(), 3, "version base should be MAJOR.MINOR.PATCH, got: {base}");
    for part in &parts {
        assert!(
            part.parse::<u32>().is_ok(),
            "version component should be numeric: {part} (in {VERSION})"
        );
    }
}
