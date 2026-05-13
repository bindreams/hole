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

// macOS-specific tests ================================================================================================

#[cfg(target_os = "macos")]
mod macos {
    /// Per-process suffix for the "missing group" test name. Vanishingly
    /// unlikely to collide with a real group on the test machine, even
    /// under parallel runs. macOS local-group names cap around 32 chars;
    /// `hole_test_missing_<10-digit pid>` fits.
    fn missing_group_name() -> String {
        format!("hole_test_missing_{}", std::process::id())
    }

    /// `getgrnam("wheel")` must return a record on every macOS install
    /// (uid 0's primary group). Locale-independent — runs in CI under any user.
    #[skuld::test]
    fn group_exists_finds_wheel() {
        assert!(crate::group::group_exists("wheel"));
    }

    /// `getgrnam` must return NULL (→ false) for a clearly-nonexistent name.
    #[skuld::test]
    fn group_exists_returns_false_for_missing() {
        assert!(!crate::group::group_exists(&missing_group_name()));
    }

    /// A name with an embedded NUL is not a valid POSIX group name and
    /// returns `false` rather than panicking.
    #[skuld::test]
    fn group_exists_returns_false_for_name_with_nul() {
        assert!(!crate::group::group_exists("foo\0bar"));
    }
}

// Cross-platform tests ================================================================================================

#[skuld::test]
fn group_name_is_hole() {
    assert_eq!(crate::group::GROUP_NAME, "hole");
}
