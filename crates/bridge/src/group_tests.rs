// Windows-specific tests ==============================================================================================

#[cfg(target_os = "windows")]
mod windows {
    #[skuld::test]
    fn group_sid_format() {
        // group_sid() should return a SID string starting with S-1-, or None.
        // On CI / dev machines, the group likely doesn't exist.
        let result = crate::group::group_sid().expect("the lookup of the `hole` group");
        if let Some(sid) = result {
            assert!(sid.starts_with("S-1-"), "SID should start with S-1-, got: {sid}");
        }
    }

    #[skuld::test]
    fn lookup_sid_resolves_current_user() {
        // The current user always has a SID — this must succeed.
        let username = crate::group::installing_username().expect("should detect current user");
        let sid = crate::group::lookup_sid(&username)
            .expect("lookup_sid should resolve current user")
            .expect("the current user has an account");
        assert!(sid.starts_with("S-1-"), "SID should start with S-1-, got: {sid}");
    }

    /// An account that is not there is an answer, not a failure: the caller must be able to tell it from a lookup
    /// that could not be made. No name makes `LookupAccountNameW` fail in another way (measured: 257 and 100000
    /// characters, a lone surrogate, illegal characters, a domain that does not exist and a server form all answer
    /// "none mapped"), so the failure arm has no test.
    #[skuld::test]
    fn a_missing_account_is_not_an_error() {
        let result = crate::group::lookup_sid("nonexistent_user_that_does_not_exist_12345");
        assert_eq!(
            result.expect("the lookup of a missing account answers Ok(None), not an error"),
            None
        );
    }

    /// The name this machine gives the account with `sid`: a built-in group's name follows the display language.
    fn account_name(sid: &str) -> String {
        use windows::core::{HSTRING, PWSTR};
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
        use windows::Win32::Security::{LookupAccountSidW, PSID, SID_NAME_USE};

        let mut psid = PSID::default();
        // SAFETY: the string outlives the call; `psid` receives a LocalAlloc'd SID freed below.
        unsafe { ConvertStringSidToSidW(&HSTRING::from(sid), &mut psid) }.expect("ConvertStringSidToSidW failed");
        let mut name = vec![0u16; 256];
        let mut domain = vec![0u16; 256];
        let (mut name_len, mut domain_len) = (name.len() as u32, domain.len() as u32);
        let mut kind = SID_NAME_USE::default();
        // SAFETY: `psid` is the valid SID from above; each buffer is as long as its length says.
        unsafe {
            LookupAccountSidW(
                None,
                psid,
                Some(PWSTR(name.as_mut_ptr())),
                &mut name_len,
                Some(PWSTR(domain.as_mut_ptr())),
                &mut domain_len,
                &mut kind,
            )
        }
        .expect("LookupAccountSidW failed");
        // SAFETY: `psid` came from LocalAlloc in ConvertStringSidToSidW and is freed once.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(psid.0)));
        }
        String::from_utf16(&name[..name_len as usize]).expect("an account name is UTF-16")
    }

    /// Windows puts INTERACTIVE and Authenticated Users in the built-in Users group on every install, so the
    /// expected members do not come from the function under test. Neither is a user account: a member is listed
    /// whatever kind of account it is.
    #[skuld::test]
    fn the_members_of_a_builtin_group_are_read_as_sids() {
        let users = account_name("S-1-5-32-545");

        let members = crate::group::os::member_sids(&users).expect("the members of the built-in Users group");

        for well_known in ["S-1-5-4", "S-1-5-11"] {
            assert!(
                members.iter().any(|member| member == well_known),
                "{well_known} is not among the members of {users}: {members:?}"
            );
        }
    }

    #[skuld::test]
    fn members_of_a_group_that_does_not_exist_are_an_error() {
        let missing = format!("hole_test_missing_{}", std::process::id());

        assert!(crate::group::os::member_sids(&missing).is_err());
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

    /// The lookup of "wheel" must find a record on every macOS install
    /// (uid 0's primary group). Locale-independent — runs in CI under any user.
    #[skuld::test]
    fn group_exists_finds_wheel() {
        assert!(crate::group::group_exists("wheel"));
    }

    /// The lookup must find nothing (→ false) for a clearly-nonexistent name.
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

    #[skuld::test]
    fn resolve_real_user_returns_an_absolute_home() {
        let ru = crate::group::resolve_real_user().expect("resolve current user");
        assert!(!ru.name.is_empty());
        assert!(ru.home.is_absolute(), "home must be absolute, got {:?}", ru.home);
    }
}

// Cross-platform tests ================================================================================================

#[skuld::test]
fn group_name_is_hole() {
    assert_eq!(crate::group::GROUP_NAME, "hole");
}
