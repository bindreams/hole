use std::os::windows::io::AsRawHandle;

use windows::core::PWSTR;
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SetSecurityInfo, EXPLICIT_ACCESS_W, REVOKE_ACCESS, SE_KERNEL_OBJECT,
};
use windows::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, SetTokenInformation, TokenDefaultDacl, ACCESS_ALLOWED_ACE, ACL,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_ACCESS_MASK,
    TOKEN_ADJUST_DEFAULT, TOKEN_DEFAULT_DACL, TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::READ_CONTROL;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::{
    apply_to_process, apply_to_token_default, first_failure, grant_administrators_retirement_access,
    widen_token_default, AdministratorsSid, RETIREMENT_ACCESS,
};
use crate::test_support::reap_child::EchoChild;

/// `BUILTIN\Administrators`.
const ADMINISTRATORS: &str = "S-1-5-32-544";
/// `ACCESS_ALLOWED_ACE_TYPE` (`winnt.h`).
const ACCESS_ALLOWED: u8 = 0;
/// What a default DACL stores for Administrators: generic rights, mapped per object when one is created.
const DEFAULT_DACL_ACCESS: u32 = GENERIC_READ.0 | GENERIC_EXECUTE.0;

/// `GENERIC_READ | GENERIC_EXECUTE` as Windows maps it on a child process (see
/// the module doc of `process_access.rs`).
const CHILD_PROCESS_MASK: u32 = 0x0012_1411;
/// The same on a child's token.
const CHILD_TOKEN_MASK: u32 = 0x0002_001F;

/// One entry of a DACL, read back from the OS.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ace {
    kind: u8,
    mask: u32,
    sid: String,
}

impl Ace {
    fn is_administrators_allow(&self) -> bool {
        self.kind == ACCESS_ALLOWED && self.sid == ADMINISTRATORS
    }

    fn carries(&self, access: u32) -> bool {
        self.mask & access == access
    }
}

/// Every entry of `acl`. A null DACL has none, and grants everyone everything.
fn read_acl(acl: *const ACL) -> Vec<Ace> {
    if acl.is_null() {
        return Vec::new();
    }
    let mut size = ACL_SIZE_INFORMATION::default();
    // SAFETY: `acl` is a valid ACL and `size` is the `ACL_SIZE_INFORMATION` the class asks for.
    unsafe {
        GetAclInformation(
            acl,
            std::ptr::from_mut(&mut size).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    }
    .expect("read the ACL's size");
    (0..size.AceCount)
        .map(|index| {
            let mut ace = std::ptr::null_mut();
            // SAFETY: `index` is below the ACL's entry count.
            unsafe { GetAce(acl, index, &mut ace) }.expect("read an ACL entry");
            // SAFETY: the allow, deny, audit and alarm entries share `ACCESS_ALLOWED_ACE`'s layout.
            let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            let mut text = PWSTR::null();
            // SAFETY: `SidStart` is the first word of the entry's SID.
            unsafe { ConvertSidToStringSidW(PSID(std::ptr::from_ref(&ace.SidStart).cast_mut().cast()), &mut text) }
                .expect("print an entry's SID");
            // SAFETY: the call returned a NUL-terminated string it allocated.
            let sid = unsafe { text.to_string() }.expect("a SID prints as UTF-16");
            // SAFETY: `text` was allocated by the call above and is not used again.
            unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
            Ace {
                kind: ace.Header.AceType,
                mask: ace.Mask,
                sid,
            }
        })
        .collect()
}

/// The DACL of the process `handle` names.
fn process_dacl(handle: HANDLE) -> Vec<Ace> {
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `handle` is a live process handle with `READ_CONTROL`; the descriptor it returns owns `dacl`.
    unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            Some(&mut descriptor),
        )
    }
    .ok()
    .expect("read a process DACL");
    let aces = read_acl(dacl);
    // SAFETY: the descriptor was allocated by the call above and is not used again.
    unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    aces
}

/// The DACL of the token of the process `handle` names.
fn process_token_dacl(handle: HANDLE) -> Vec<Ace> {
    let mut token = HANDLE::default();
    // SAFETY: `handle` is a live process handle with query access.
    unsafe { OpenProcessToken(handle, TOKEN_ACCESS_MASK(READ_CONTROL.0), &mut token) }
        .expect("open the process's token");
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `token` is a live token handle with `READ_CONTROL`; the descriptor it returns owns `dacl`.
    unsafe {
        GetSecurityInfo(
            token,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            Some(&mut descriptor),
        )
    }
    .ok()
    .expect("read a token DACL");
    let aces = read_acl(dacl);
    // SAFETY: the descriptor was allocated by the call above and is not used again.
    unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    // SAFETY: `token` is the handle opened above.
    unsafe { CloseHandle(token) }.expect("close the token");
    aces
}

fn own_process_dacl() -> Vec<Ace> {
    // SAFETY: plain FFI call; the pseudo-handle needs no close.
    process_dacl(unsafe { GetCurrentProcess() })
}

/// The default DACL of this process's token, which every child is created with.
fn token_default_dacl() -> Vec<Ace> {
    let mut token = HANDLE::default();
    // SAFETY: plain FFI call on this process.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.expect("open this process's token");
    let buffer =
        crate::platform::os::token::information(token, TokenDefaultDacl).expect("read the token's default DACL");
    // SAFETY: on success `buffer` holds a `TOKEN_DEFAULT_DACL` whose ACL lives in the same allocation.
    let acl = unsafe { (*buffer.as_ptr().cast::<TOKEN_DEFAULT_DACL>()).DefaultDacl };
    let aces = read_acl(acl);
    // SAFETY: `token` is the handle opened above.
    unsafe { CloseHandle(token) }.expect("close the token");
    aces
}

fn administrators_allows(aces: &[Ace]) -> Vec<&Ace> {
    aces.iter().filter(|ace| ace.is_administrators_allow()).collect()
}

/// Panics outside nextest's one process per test, for a test that changes this
/// process's security for good.
fn assert_process_per_test() {
    assert_eq!(
        std::env::var("NEXTEST_EXECUTION_MODE").as_deref(),
        Ok("process-per-test"),
        "This test changes the process's security for good: run it under `cargo nextest`, which gives each test its own process"
    );
}

/// Removes every Administrators entry from this process's DACL and its token's
/// default DACL: an elevated test process starts with full access for the group,
/// which would make the grant unobservable. Permanent for the process, so it
/// panics outside nextest's one process per test.
fn revoke_administrators() {
    assert_process_per_test();
    let sid = AdministratorsSid::new().expect("build the Administrators SID");
    let revoke = EXPLICIT_ACCESS_W {
        grfAccessMode: REVOKE_ACCESS,
        ..sid.allow(0)
    };
    apply_to_process(&revoke).expect("revoke from the process DACL");
    apply_to_token_default(&revoke).expect("revoke from the default DACL");
    assert!(administrators_allows(&own_process_dacl()).is_empty());
    assert!(administrators_allows(&token_default_dacl()).is_empty());
}

/// After the grant, `after` allows Administrators `access` and every entry of
/// `before` is still there, with at least the access it had.
fn assert_grant_added_without_removing(before: &[Ace], after: &[Ace], access: u32) {
    assert!(
        administrators_allows(after).iter().any(|ace| ace.carries(access)),
        "no allow entry for Administrators carries {access:#x}: {after:?}"
    );
    for entry in before {
        assert!(
            after
                .iter()
                .any(|a| a.kind == entry.kind && a.sid == entry.sid && a.mask & entry.mask == entry.mask),
            "the entry {entry:?} is gone: {after:?}"
        );
    }
}

#[skuld::test]
fn own_process_dacl_gains_the_administrators_entry() {
    revoke_administrators();
    let before = own_process_dacl();
    grant_administrators_retirement_access().expect("grant");
    assert_grant_added_without_removing(&before, &own_process_dacl(), RETIREMENT_ACCESS.0);
}

#[skuld::test]
fn default_dacl_gains_the_administrators_entry() {
    revoke_administrators();
    let before = token_default_dacl();
    grant_administrators_retirement_access().expect("grant");
    assert_grant_added_without_removing(&before, &token_default_dacl(), DEFAULT_DACL_ACCESS);
}

/// A child's process and token take their DACLs from the creator token's default
/// DACL at creation, so only a child started after the grant has the entries, and
/// the grant touches no process that exists. The token must be readable by
/// Administrators: the uninstaller proves a process is the service's by reading it.
#[skuld::test]
fn a_child_started_after_the_grant_carries_the_entry() {
    revoke_administrators();
    let before = EchoChild::spawn();
    let before_handle = HANDLE(before.as_raw_handle());
    let before_grant = process_dacl(before_handle);
    assert!(administrators_allows(&before_grant).is_empty(), "{before_grant:?}");
    let before_token = process_token_dacl(before_handle);

    grant_administrators_retirement_access().expect("grant");

    let after = EchoChild::spawn();
    let after_dacl = process_dacl(HANDLE(after.as_raw_handle()));
    let on_process: Vec<u32> = administrators_allows(&after_dacl).iter().map(|ace| ace.mask).collect();
    assert_eq!(
        on_process,
        [CHILD_PROCESS_MASK],
        "the child started after the grant carries one entry of the mapped mask: {after_dacl:?}"
    );
    let after_token = process_token_dacl(HANDLE(after.as_raw_handle()));
    let on_token: Vec<u32> = administrators_allows(&after_token).iter().map(|ace| ace.mask).collect();
    assert_eq!(
        on_token,
        [CHILD_TOKEN_MASK],
        "the child's token carries one entry of the mapped mask: {after_token:?}"
    );
    assert_eq!(
        process_dacl(before_handle),
        before_grant,
        "the grant changed a process that already existed"
    );
    assert_eq!(
        process_token_dacl(before_handle),
        before_token,
        "the grant changed the token of a process that already existed"
    );
}

#[skuld::test]
fn granting_twice_adds_no_second_entry() {
    revoke_administrators();
    let (process_before, token_before) = (own_process_dacl(), token_default_dacl());
    grant_administrators_retirement_access().expect("first grant");
    let (process_once, token_once) = (own_process_dacl(), token_default_dacl());
    grant_administrators_retirement_access().expect("second grant");
    let (process_twice, token_twice) = (own_process_dacl(), token_default_dacl());

    for (before, once, twice) in [
        (&process_before, &process_once, &process_twice),
        (&token_before, &token_once, &token_twice),
    ] {
        assert_eq!(administrators_allows(before).len(), 0, "{before:?}");
        assert_eq!(administrators_allows(once).len(), 1, "{once:?}");
        assert_eq!(twice, once, "the second grant changed the DACL");
    }
}

/// Whether this process has no DACL (a null one, which grants everyone everything).
fn own_process_dacl_is_null() -> bool {
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: this process grants itself `READ_CONTROL`; the descriptor returned owns `dacl`.
    unsafe {
        GetSecurityInfo(
            GetCurrentProcess(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            Some(&mut descriptor),
        )
    }
    .ok()
    .expect("read this process's DACL");
    // SAFETY: the descriptor was allocated by the call above and is not used again.
    unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    dacl.is_null()
}

/// Whether this process's token has no default DACL.
fn token_default_dacl_is_null() -> bool {
    let token = crate::platform::os::token::open_own_token(TOKEN_QUERY).expect("open this process's token");
    let buffer = crate::platform::os::token::information(HANDLE(token.as_raw_handle()), TokenDefaultDacl)
        .expect("read the token's default DACL");
    // SAFETY: on success `buffer` holds a `TOKEN_DEFAULT_DACL`.
    unsafe { (*buffer.as_ptr().cast::<TOKEN_DEFAULT_DACL>()).DefaultDacl }.is_null()
}

/// An Administrators entry that carries less than the grant is widened to carry
/// what it had and what the grant adds, and is not joined by a second one.
#[skuld::test]
fn an_existing_narrower_entry_is_widened_not_duplicated() {
    revoke_administrators();
    // Rights the grant does not give, so the old entry's survival shows in the mask.
    let administrators = AdministratorsSid::new().expect("build the Administrators SID");
    let narrow_process = READ_CONTROL.0;
    let narrow_default = GENERIC_WRITE.0;
    apply_to_process(&administrators.allow(narrow_process)).expect("add a narrow entry to the process DACL");
    apply_to_token_default(&administrators.allow(narrow_default)).expect("add a narrow entry to the default DACL");
    assert_eq!(administrators_allows(&own_process_dacl()).len(), 1);
    assert_eq!(administrators_allows(&token_default_dacl()).len(), 1);

    grant_administrators_retirement_access().expect("grant");

    for (after, old, new) in [
        (own_process_dacl(), narrow_process, RETIREMENT_ACCESS.0),
        (token_default_dacl(), narrow_default, DEFAULT_DACL_ACCESS),
    ] {
        let entries = administrators_allows(&after);
        assert_eq!(entries.len(), 1, "{after:?}");
        assert!(
            entries[0].carries(old | new),
            "the entry lost the old or the new access: {after:?}"
        );
    }
}

/// A null DACL grants everyone everything already: the grant leaves it null
/// instead of replacing it with an ACL that restricts.
#[skuld::test]
fn a_null_dacl_is_left_alone() {
    assert_process_per_test();
    // SAFETY: plain FFI call; the pseudo-handle needs no close, and a null DACL only widens access to this process.
    unsafe {
        SetSecurityInfo(
            GetCurrentProcess(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
        )
    }
    .ok()
    .expect("give the process a null DACL");
    let token = crate::platform::os::token::open_own_token(TOKEN_QUERY | TOKEN_ADJUST_DEFAULT)
        .expect("open this process's token");
    let null_default = TOKEN_DEFAULT_DACL {
        DefaultDacl: std::ptr::null_mut(),
    };
    // SAFETY: `null_default` is a `TOKEN_DEFAULT_DACL` of the size passed.
    unsafe {
        SetTokenInformation(
            HANDLE(token.as_raw_handle()),
            TokenDefaultDacl,
            std::ptr::from_ref(&null_default).cast(),
            size_of::<TOKEN_DEFAULT_DACL>() as u32,
        )
    }
    .expect("give the token a null default DACL");
    assert!(own_process_dacl_is_null() && token_default_dacl_is_null());

    grant_administrators_retirement_access().expect("grant");

    assert!(own_process_dacl_is_null(), "the grant replaced the process's null DACL");
    assert!(
        token_default_dacl_is_null(),
        "the grant replaced the token's null default DACL"
    );
}

/// A grant call that fails reaches the log once, as the error the start writes,
/// and not also as the info line a logged conversion adds.
#[skuld::test]
fn a_failed_grant_call_is_logged_once() {
    let administrators = AdministratorsSid::new().expect("build the Administrators SID");
    let log = garter::tracing_test::captured(|| {
        // A null handle makes the first call of the token half fail.
        let failure = widen_token_default(HANDLE::default(), &administrators.allow(DEFAULT_DACL_ACCESS))
            .expect_err("no token behind a null handle");
        crate::platform::os::report_administrators_grant(Err(failure));
    });
    assert_eq!(log.lines().count(), 1, "{log}");
    assert!(log.contains("ERROR"), "{log}");
    assert!(log.contains("GetTokenInformation failed"), "{log}");
    assert!(!log.contains("SCM call failed"), "{log}");
}

/// When both halves of the grant fail, the error returned (and logged once, as an
/// error, by the start) is the process half's, and the token half's is not lost.
#[skuld::test]
fn both_halves_failing_leaves_both_in_the_log() {
    let log = garter::tracing_test::captured(|| {
        let error = first_failure(
            Err(std::io::Error::other("process half refused")),
            Err(std::io::Error::other("token half refused")),
        )
        .expect_err("both halves failed");
        assert_eq!(error.to_string(), "process half refused");
        crate::platform::os::report_administrators_grant(Err(error));
    });

    let errors: Vec<&str> = log.lines().filter(|line| line.contains("ERROR")).collect();
    assert_eq!(errors.len(), 1, "{log}");
    assert!(errors[0].contains("process half refused"), "{log}");
    let warnings: Vec<&str> = log.lines().filter(|line| line.contains("WARN")).collect();
    assert_eq!(warnings.len(), 1, "{log}");
    assert!(warnings[0].contains("token half refused"), "{log}");
}

/// A single failed half is returned as it is, with nothing else in the log.
#[skuld::test]
fn one_failed_half_is_returned_alone() {
    let log = garter::tracing_test::captured(|| {
        let error = first_failure(Ok(()), Err(std::io::Error::other("token half refused"))).expect_err("one failed");
        assert_eq!(error.to_string(), "token half refused");
        let error = first_failure(Err(std::io::Error::other("process half refused")), Ok(())).expect_err("one failed");
        assert_eq!(error.to_string(), "process half refused");
        first_failure(Ok(()), Ok(())).expect("both worked");
    });
    assert_eq!(log, "");
}
