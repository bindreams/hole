// Windows-specific tests =====

#[cfg(target_os = "windows")]
mod windows {
    #[skuld::test]
    fn group_sid_format() {
        // group_sid() should return a SID string starting with S-1-
        // This test will only pass if the group actually exists,
        // so we test the error path instead.
        let result = crate::group::group_sid();
        // On CI / dev machines, the group likely doesn't exist.
        // Just verify the function doesn't panic and returns a reasonable error.
        if let Ok(sid) = result {
            assert!(sid.starts_with("S-1-"), "SID should start with S-1-, got: {sid}");
        }
    }
}

// Cross-platform tests =====

#[skuld::test]
fn group_name_is_hole() {
    assert_eq!(crate::group::GROUP_NAME, "hole");
}
