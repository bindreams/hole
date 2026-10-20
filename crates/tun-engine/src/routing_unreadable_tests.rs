//! A route record this release cannot read is the only evidence of what an
//! earlier run left in the routing table: it is never acted on, never
//! overwritten, never deleted, and every path that reads it says so by name.
//!
//! Expected values are hand-written bytes and literal paths, not what the
//! loader returns.

use std::cell::{Cell, RefCell};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use super::state::STATE_FILE_NAME;
use super::*;

// Fixtures ============================================================================================================

fn server() -> IpAddr {
    "1.2.3.4".parse().unwrap()
}

fn gateway() -> GatewayInfo {
    let gateway_ip: IpAddr = "192.168.1.1".parse().unwrap();
    GatewayInfo {
        gateway_ip,
        next_hop: gateway::NextHop::Via(gateway_ip),
        interface_name: "en0".into(),
        interface_index: 1,
        ipv6_available: true,
    }
}

/// A schema-4 record, as a release wrote it, with one key from the future.
const WITH_UNKNOWN_FIELD: &str = r#"{
  "version": 4,
  "tun_name": "hole-tun",
  "server_ip": "9.9.9.9",
  "interface_name": "en0",
  "original_gateway": "192.168.1.1",
  "route_form": "via",
  "installed": ["server-bypass"],
  "stale": [],
  "from_the_future": true
}"#;

/// Written by a release newer than this one; carries the server address.
const NEWER: &str = r#"{"version": 5, "server_ip": "203.0.113.42", "tun_name": "hole-tun", "routes": []}"#;

/// Each a file this release cannot read as a record, whatever the cause.
const CORRUPT: [(&str, &str); 4] = [
    ("not json", "not json { ."),
    (
        "wrong shape for its version",
        r#"{"version": 4, "server_ip": "203.0.113.42"}"#,
    ),
    ("version zero", r#"{"version": 0, "server_ip": "203.0.113.42"}"#),
    ("version is a string", r#"{"version": "203.0.113.42"}"#),
];

/// Every unreadable record the tests below must treat alike.
fn unreadable_records() -> Vec<(&'static str, &'static str)> {
    std::iter::once(("newer", NEWER)).chain(CORRUPT).collect()
}

fn write_record(dir: &Path, bytes: &str) -> PathBuf {
    let path = dir.join(STATE_FILE_NAME);
    std::fs::write(&path, bytes).unwrap();
    path
}

/// Runs `body` with this thread's `tracing` output at `level` and above
/// captured.
fn logs_at(level: tracing_subscriber::filter::LevelFilter, body: impl FnOnce()) -> String {
    use tracing_subscriber::layer::{Layer, SubscriberExt};
    let writer = garter::test_utils::WaitableWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(level),
    );
    {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        body();
    }
    writer.snapshot()
}

fn logs_of(body: impl FnOnce()) -> String {
    logs_at(tracing_subscriber::filter::LevelFilter::WARN, body)
}

/// Only ERROR: a record that needs a person to move or remove it.
fn errors_of(body: impl FnOnce()) -> String {
    logs_at(tracing_subscriber::filter::LevelFilter::ERROR, body)
}

fn argv_of(tool: SystemTool, args: &[String]) -> Vec<String> {
    std::iter::once(tool.name().to_string())
        .chain(args.iter().cloned())
        .collect()
}

// install =============================================================================================================

/// `install_with` over whatever record `dir` holds, with runners that note
/// being called. Returns the error text (`None` when the install succeeded)
/// and whether any route command ran.
fn install_over(dir: &Path) -> (Option<String>, bool) {
    let ran = Cell::new(false);
    let routing = SystemRouting::new(dir.to_path_buf(), None);
    let result = routing.install_with(
        "hole-tun",
        server(),
        &gateway(),
        |_, _, _| {
            ran.set(true);
            Err(CommandFailure::Exit(1))
        },
        |_, _, _| {
            ran.set(true);
            Ok(())
        },
    );
    match result {
        Ok(routes) => {
            // `SystemRoutes::drop` runs real route commands.
            std::mem::forget(routes);
            (None, ran.get())
        }
        Err(e) => (Some(e.to_string()), ran.get()),
    }
}

fn assert_install_refused(dir: &Path, path: &Path, bytes: &str, what: &str) {
    let (error, ran) = install_over(dir);
    let error = error.unwrap_or_else(|| panic!("{what}: an install over an unreadable record must fail"));
    assert!(
        error.contains(&path.display().to_string()),
        "{what}: the error must name the record: {error}"
    );
    assert!(
        !error.contains("203.0.113.42"),
        "{what}: the error must not echo the record: {error}"
    );
    assert!(!ran, "{what}: no route command may run over an unreadable record");
    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        bytes,
        "{what}: the record must be left as it was"
    );
}

#[skuld::test]
fn install_over_a_newer_route_record_fails_naming_the_path_and_leaves_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_record(dir.path(), NEWER);
    assert_install_refused(dir.path(), &path, NEWER, "newer");
}

#[skuld::test]
fn install_over_a_corrupt_route_record_fails_naming_the_path_and_leaves_it() {
    for (what, bytes) in CORRUPT {
        let dir = tempfile::tempdir().unwrap();
        let path = write_record(dir.path(), bytes);
        assert_install_refused(dir.path(), &path, bytes, what);
    }
}

#[skuld::test]
fn install_sweeps_a_leftover_record_that_has_an_unknown_field() {
    let dir = tempfile::tempdir().unwrap();
    write_record(dir.path(), WITH_UNKNOWN_FIELD);
    let swept = RefCell::new(Vec::new());
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);

    let result = routing.install_with(
        "hole-tun",
        server(),
        &gateway(),
        |_, _, _| Err(CommandFailure::Exit(1)),
        |_, argv, _| {
            swept.borrow_mut().push(argv.join(" "));
            Ok(())
        },
    );

    assert!(result.is_err(), "the setup runner fails on purpose");
    assert!(
        swept.borrow().iter().any(|cmd| cmd.contains("9.9.9.9")),
        "the leftover's bypass route must be swept, got {:?}",
        swept.borrow()
    );
}

// recovery ============================================================================================================

/// Recovery over `dir`, with a runner that notes its commands. Returns them
/// and whether the cover step was reached.
fn recover_over(dir: &Path) -> (Vec<String>, bool) {
    let commands = RefCell::new(Vec::new());
    let cover_reached = Cell::new(false);
    recover_routes_with(
        dir,
        None,
        Some("hole-tun"),
        |tool, args, _| {
            commands.borrow_mut().push(argv_of(tool, args).join(" "));
            Ok(())
        },
        |_, _| {},
        failclosed::lockdown_state::Intent::Off,
        || CoverPresence::Absent,
        |_, _| cover_reached.set(true),
    );
    (commands.into_inner(), cover_reached.get())
}

#[skuld::test]
fn recovery_over_an_unreadable_route_record_logs_the_path_and_leaves_it() {
    for (what, bytes) in unreadable_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_record(dir.path(), bytes);

        let mut outcome = (Vec::new(), false);
        let logs = logs_of(|| outcome = recover_over(dir.path()));
        let (commands, cover_reached) = outcome;

        assert!(
            logs.contains(&path.display().to_string()),
            "{what}: the log must name the record: {logs}"
        );
        assert!(
            !logs.contains("203.0.113.42"),
            "{what}: the log must not echo the record: {logs}"
        );
        assert!(commands.is_empty(), "{what}: no route command may run: {commands:?}");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            bytes,
            "{what}: the record must be left as it was"
        );
        assert!(
            cover_reached,
            "{what}: an unreadable route record must not stop the cover's own recovery"
        );
    }
}

#[skuld::test]
fn recovery_acts_on_a_route_record_that_has_an_unknown_field() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_record(dir.path(), WITH_UNKNOWN_FIELD);

    let (commands, _) = recover_over(dir.path());

    assert!(
        commands.iter().any(|cmd| cmd.contains("9.9.9.9")),
        "the record's bypass route must be deleted, got {commands:?}"
    );
    assert!(!path.exists(), "a fully drained record is cleared");
}

// default_gateway's stale-bypass clear ================================================================================

#[skuld::test]
fn the_stale_bypass_clear_leaves_an_unreadable_record_alone_and_names_it() {
    for (what, bytes) in unreadable_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_record(dir.path(), bytes);
        let ran = Cell::new(false);

        let logs = logs_of(|| {
            clear_stale_server_bypass(&state::file(dir.path()), None, "9.9.9.9".parse().unwrap(), |_, _, _| {
                ran.set(true);
                Ok(())
            })
        });

        assert!(!ran.get(), "{what}: no route command may run");
        assert!(
            logs.contains(&path.display().to_string()),
            "{what}: the log must name the record: {logs}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), bytes, "{what}");
    }
}

#[skuld::test]
fn the_stale_bypass_clear_acts_on_a_record_that_has_an_unknown_field() {
    let dir = tempfile::tempdir().unwrap();
    write_record(dir.path(), WITH_UNKNOWN_FIELD);
    let ran = Cell::new(false);

    clear_stale_server_bypass(&state::file(dir.path()), None, "9.9.9.9".parse().unwrap(), |_, _, _| {
        ran.set(true);
        Ok(())
    });

    assert!(ran.get(), "the record's bypass route must be deleted");
}

// A read that fails (as opposed to a record that cannot be read) ======================================================
//
// A read can fail with an I/O error (a sharing violation, a permission). That
// says nothing about the bytes, but the record may name a leak, so it is
// treated like a newer or corrupt one: left alone, never acted on, never
// replaced, and the connect is refused naming the path.

/// A file system whose reads are all denied; links and publishes are real.
struct DeniedRead;

impl util::versioned_file::Fs for DeniedRead {
    fn read(&self, _path: &Path) -> std::io::Result<Vec<u8>> {
        Err(std::io::ErrorKind::PermissionDenied.into())
    }
}

/// A directory where the record's file should be: every read of it fails.
fn record_that_is_a_directory(dir: &Path) -> PathBuf {
    let path = dir.join(STATE_FILE_NAME);
    std::fs::create_dir(&path).unwrap();
    path
}

#[skuld::test]
fn install_over_a_record_whose_read_fails_fails_naming_the_path_and_leaves_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = record_that_is_a_directory(dir.path());

    let (error, ran) = install_over(dir.path());

    let error = error.expect("an install over a record it cannot read must fail");
    assert!(error.contains(&path.display().to_string()), "{error}");
    assert!(!ran, "no route command may run over a record that cannot be read");
    assert!(path.is_dir(), "the record must be left as it was");
}

#[skuld::test]
fn recovery_over_a_record_whose_read_fails_logs_the_path_and_leaves_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = record_that_is_a_directory(dir.path());

    let mut outcome = (Vec::new(), false);
    let logs = errors_of(|| outcome = recover_over(dir.path()));
    let (commands, cover_reached) = outcome;

    assert!(logs.contains(&path.display().to_string()), "{logs}");
    assert!(commands.is_empty(), "no route command may run: {commands:?}");
    assert!(path.is_dir(), "the record must be left as it was");
    assert!(
        cover_reached,
        "an unreadable route record must not stop the cover's own recovery"
    );
}

#[skuld::test]
fn the_stale_bypass_clear_leaves_a_record_whose_read_fails_alone_and_names_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = record_that_is_a_directory(dir.path());
    let ran = Cell::new(false);

    let logs = errors_of(|| {
        clear_stale_server_bypass(&state::file(dir.path()), None, "9.9.9.9".parse().unwrap(), |_, _, _| {
            ran.set(true);
            Ok(())
        })
    });

    assert!(!ran.get(), "no route command may run");
    assert!(logs.contains(&path.display().to_string()), "{logs}");
    assert!(path.is_dir());
}

fn persisted_with_no_routes() -> state::RouteState {
    state::RouteState {
        tun_name: "hole-tun".into(),
        server_ip: server(),
        interface_name: "en0".into(),
        original_gateway: None,
        route_form: state::RouteForm::Via,
        installed: Vec::new(),
        stale: Vec::new(),
    }
}

/// The record turned unreadable after the sweep read it.
#[skuld::test]
fn a_checkpoint_over_a_record_whose_read_fails_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_record(dir.path(), WITH_UNKNOWN_FIELD);
    let file = state::RouteFile::with_fs(dir.path(), std::sync::Arc::new(DeniedRead));
    let mut persisted = persisted_with_no_routes();

    let mut result = Ok(());
    let logs = logs_of(|| {
        result = checkpoint_installed(&mut persisted, &file, None, &[RouteId::SplitV4Low]);
    });

    let error = result.expect_err("the record must not be overwritten").to_string();
    assert!(!error.contains(&dir.path().display().to_string()), "{error}");
    assert!(logs.contains(&path.display().to_string()), "{logs}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), WITH_UNKNOWN_FIELD);
    assert!(
        persisted.installed.is_empty(),
        "a refused write must not advance the in-memory value"
    );
}

#[skuld::test]
fn teardown_over_a_record_whose_read_fails_leaves_it_and_names_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_record(dir.path(), WITH_UNKNOWN_FIELD);
    let routing = SystemRouting::new(dir.path().to_path_buf(), None).with_record_fs(std::sync::Arc::new(DeniedRead));
    let mut persisted = persisted_with_no_routes();
    persisted.original_gateway = Some("192.168.1.1".parse().unwrap());

    let logs = logs_of(|| {
        // The delete is not confirmed, so the route would stay recorded.
        routing.rollback_and_record(
            "hole-tun",
            server(),
            "en0",
            &[RouteId::SplitV4Low],
            persisted,
            vec![RouteId::ServerBypass],
            |_, _, _| Err(CommandFailure::Exit(1)),
        );
    });

    assert!(logs.contains(&path.display().to_string()), "{logs}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), WITH_UNKNOWN_FIELD);
}

#[skuld::test]
fn a_checkpoint_over_a_record_that_turned_unreadable_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_record(dir.path(), NEWER);
    let mut persisted = persisted_with_no_routes();

    let mut result = Ok(());
    let logs = logs_of(|| {
        result = checkpoint_installed(&mut persisted, &state::file(dir.path()), None, &[RouteId::SplitV4Low]);
    });

    let error = result.expect_err("the record must not be overwritten").to_string();
    assert!(!error.contains(&dir.path().display().to_string()), "{error}");
    assert!(logs.contains(&path.display().to_string()), "{logs}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), NEWER);
    assert!(
        persisted.installed.is_empty(),
        "a refused write must not advance the in-memory value"
    );
}

/// A checkpoint whose record was replaced but is not known durable has landed:
/// memory follows the disk, so no recovery reads ids memory never installed.
#[skuld::test]
fn a_checkpoint_published_but_not_finalized_has_landed() {
    let path = PathBuf::from("/state/bridge-routes.json");
    let mut persisted = persisted_with_no_routes();

    let result = checkpoint_installed_with(&mut persisted, &path, &[RouteId::SplitV4Low], |_| {
        Err(StoreError::PublishedNotFinalized(std::io::Error::from(
            std::io::ErrorKind::TimedOut,
        )))
    });

    result.unwrap();
    assert_eq!(persisted.installed, vec![RouteId::SplitV4Low]);
}

/// Any other write failure leaves the in-memory value where it was.
#[skuld::test]
fn a_checkpoint_that_did_not_land_rolls_memory_back() {
    let path = PathBuf::from("/state/bridge-routes.json");
    let mut persisted = persisted_with_no_routes();

    let result = checkpoint_installed_with(&mut persisted, &path, &[RouteId::SplitV4Low], |_| {
        Err(StoreError::Io(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied,
        )))
    });

    assert!(result.is_err());
    assert!(persisted.installed.is_empty());
}
