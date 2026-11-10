use super::*;
use std::io;
use std::path::{Path, PathBuf};

fn cause() -> io::Error {
    io::Error::other("no passwd entry")
}

fn alice() -> RealUser {
    RealUser {
        name: "alice".into(),
        uid: 501,
        gid: 20,
        home: PathBuf::from("/Users/alice"),
    }
}

// from_identity =======================================================================================================

#[skuld::test]
fn the_daemon_is_no_person_whoever_the_account_is() {
    for identity in [
        Identity::Person,
        Identity::ServiceAccount,
        Identity::Unreadable(cause()),
        Identity::Root(Ok(alice())),
        Identity::Root(Err(cause())),
    ] {
        let resolved = Principal::from_identity(true, || identity);
        assert_eq!(resolved.principal, Principal::Service);
        assert!(resolved.warning.is_none());
    }
}

/// Reading the identity costs a `stat`, a `logname` and a passwd lookup on macOS: the daemon, whose answer is fixed,
/// never pays it.
#[skuld::test]
fn the_daemon_never_reads_the_account() {
    let resolved = Principal::from_identity(true, || panic!("the daemon read the account"));
    assert_eq!(resolved.principal, Principal::Service);
}

#[skuld::test]
fn a_person_running_as_themselves_is_themselves() {
    let resolved = Principal::from_identity(false, || Identity::Person);
    assert_eq!(resolved.principal, Principal::Person);
    assert!(resolved.warning.is_none());
}

#[skuld::test]
fn a_service_account_is_no_person() {
    let resolved = Principal::from_identity(false, || Identity::ServiceAccount);
    assert_eq!(resolved.principal, Principal::Service);
    assert!(resolved.warning.is_none());
}

#[skuld::test]
fn root_behind_a_person_is_that_person() {
    let resolved = Principal::from_identity(false, || Identity::Root(Ok(alice())));
    assert_eq!(resolved.principal, Principal::Elevated(alice()));
    assert!(resolved.warning.is_none());
}

// An account the OS would not name still resolves, and the reason travels to the log: the principal picks the log
// directory, so nothing can log it until it is resolved.
#[skuld::test]
fn root_with_no_person_behind_it_is_no_person_and_says_why() {
    let resolved = Principal::from_identity(false, || Identity::Root(Err(cause())));
    assert_eq!(resolved.principal, Principal::Service);
    let warning = resolved.warning.expect("a warning");
    assert_eq!(
        warning.message,
        "no person behind this elevation; treating it as the system"
    );
    assert_eq!(warning.cause.to_string(), "no passwd entry");
}

#[skuld::test]
fn an_unreadable_account_is_a_person_and_says_why() {
    let resolved = Principal::from_identity(false, || Identity::Unreadable(cause()));
    assert_eq!(resolved.principal, Principal::Person);
    let warning = resolved.warning.expect("a warning");
    assert_eq!(
        warning.message,
        "could not read this process's account; treating it as a person"
    );
    assert_eq!(warning.cause.to_string(), "no passwd entry");
}

// Per-principal policy ================================================================================================

#[skuld::test]
fn a_person_logs_to_their_own_profile() {
    assert_eq!(Principal::Person.log_dir(), hole_common::logging::default_log_dir());
    assert_eq!(Principal::Person.owner(), None);
}

#[skuld::test]
fn an_elevated_person_logs_to_their_home_and_owns_the_files() {
    let p = Principal::Elevated(alice());
    assert_eq!(
        p.log_dir(),
        Path::new("/Users/alice/Library/Application Support/hole/logs")
    );
    assert_eq!(p.owner(), Some((501, 20)));
}

#[skuld::test]
fn no_person_logs_to_the_system_dir_and_owns_nothing() {
    assert_eq!(
        Principal::Service.log_dir(),
        hole_common::update_marker::service_log_dir()
    );
    assert_eq!(Principal::Service.owner(), None);
}

#[skuld::test]
fn only_an_elevation_has_a_person_behind_it() {
    assert_eq!(Principal::Person.elevated(), None);
    assert_eq!(Principal::Elevated(alice()).elevated(), Some(&alice()));
    assert_eq!(Principal::Service.elevated(), None);
}

// A process that is not the installed service (the GUI, a foreground bridge) never writes where the installed
// service does.
#[skuld::test]
fn a_process_that_is_not_the_service_never_logs_to_the_installed_services_dir() {
    let own = hole_common::logging::default_log_dir();
    assert_eq!(Principal::Person.own_log_dir(), own);
    assert_eq!(Principal::Service.own_log_dir(), own);
    assert_ne!(
        Principal::Service.own_log_dir(),
        hole_common::update_marker::service_log_dir()
    );
    assert_eq!(
        Principal::Elevated(alice()).own_log_dir(),
        Path::new("/Users/alice/Library/Application Support/hole/logs")
    );
}

// Windows account classification ======================================================================================

#[skuld::test]
fn the_windows_service_accounts_are_no_person() {
    for sid in [
        "S-1-5-18",                                                        // LocalSystem
        "S-1-5-19",                                                        // LocalService
        "S-1-5-20",                                                        // NetworkService
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",  // NT SERVICE\TrustedInstaller
        "S-1-5-80-2652153423-1316403861-3031651187-3300538310-1457273846", // a per-service virtual account
    ] {
        assert!(matches!(Identity::of_sid(sid), Identity::ServiceAccount), "{sid}");
    }
}

#[skuld::test]
fn every_other_windows_account_is_a_person() {
    for sid in [
        "S-1-5-21-1004336348-1177238915-682003330-1000", // a local or domain user
        "S-1-5-21-1004336348-1177238915-682003330-500",  // the built-in Administrator
        "S-1-5-32-544",                                  // BUILTIN\Administrators
        "S-1-5-180",                                     // exact match, not a prefix of LocalSystem's
        "S-1-5-190",
        "S-1-5-200",
        "S-1-5-80", // the NT SERVICE domain itself, not an account in it
        "S-1-1-0",
    ] {
        assert!(matches!(Identity::of_sid(sid), Identity::Person), "{sid}");
    }
}

// The live process ====================================================================================================

/// The account running the tests is a person (a developer, the CI runner's administrator), elevated or not: on
/// Windows an elevated administrator keeps their own SID.
#[cfg(windows)]
#[skuld::test]
fn this_process_is_a_person_on_windows() {
    assert_eq!(Principal::resolve(false).principal, Principal::Person);
}

#[cfg(windows)]
#[skuld::test]
fn the_daemon_flag_overrides_the_live_account() {
    assert_eq!(Principal::resolve(true).principal, Principal::Service);
}
