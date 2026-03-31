// Windows-specific tests ==============================================================================================

#[cfg(target_os = "windows")]
mod windows {
    #[skuld::test]
    fn group_sid_format() {
        // group_sid() should return a SID string starting with S-1-
        // On CI / dev machines, the group likely doesn't exist.
        // Just verify the function doesn't panic and returns a reasonable error.
        let result = crate::group::group_sid();
        if let Ok(sid) = result {
            assert!(sid.starts_with("S-1-"), "SID should start with S-1-, got: {sid}");
        }
    }

    #[skuld::test]
    fn lookup_sid_resolves_current_user() {
        // The current user always has a SID — this must succeed.
        let username = crate::group::installing_username().expect("should detect current user");
        let sid = crate::group::lookup_sid(&username).expect("lookup_sid should resolve current user");
        assert!(sid.starts_with("S-1-"), "SID should start with S-1-, got: {sid}");
    }

    #[skuld::test]
    fn lookup_sid_nonexistent_returns_error() {
        let result = crate::group::lookup_sid("nonexistent_user_that_does_not_exist_12345");
        assert!(result.is_err());
    }
}

// Cross-platform tests ================================================================================================

#[skuld::test]
fn group_name_is_hole() {
    assert_eq!(crate::group::GROUP_NAME, "hole");
}
