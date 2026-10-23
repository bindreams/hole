//! Every privileged writer that goes through [`util::dir::Dir`], held to the same two properties, and the readers of
//! the same names held to a third (below).
//!
//! These code paths run as root/SYSTEM in folders the interactive user may own, so the user can plant a name and
//! shape the layout above it:
//!
//! - A hard link, a symlink or a FIFO planted at a name the writer writes to is never written through, and the
//!   file it leads to is left as it was (content, mode, owner).
//! - A second run in the same layout succeeds, with or without a link the user owns on the path: the folders the
//!   first run made must pass the walk of the second.
//!
//! The table below is the list of writers. A source file that opens a `Dir` and is not in it fails
//! [`every_file_that_opens_a_dir_has_a_row`], so a new writer cannot skip these tests. The owner observations
//! (a file given away, a made folder handed over) need root or an elevated token; run as the user, the same
//! tests check what they can.

use std::ffi::OsStr;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use hole_common::logging::dir_rotate::DirRotate;
use hole_common::update_marker::{self, MarkerInfo, MARKER_FILE, MARKER_VERSION};
use tun_engine::routing::state as route_state;
use util::dir::testing::{plant_link, user_dir};
use util::dir::Dir;

use crate::target::{self, Target};

// The table -----------------------------------------------------------------------------------------------------------

/// The unix ids a writer hands its files to.
type Owner = Option<(u32, u32)>;

struct Writer {
    name: &'static str,
    /// The production source files whose `Dir` use this row exercises, from the workspace root.
    sources: &'static [&'static str],
    /// The names in the writer's directory it writes to, which a user can plant.
    names: &'static [&'static str],
    /// Runs the writer once in `dir`, creating it if missing.
    run: fn(dir: &Path, owner: Owner) -> io::Result<()>,
}

const LOCK_NAME: &str = "writers.lock";
const STATE_NAME: &str = "state.json";
const LOG_NAME: &str = "bridge.log";
const LOG_ROTATED_NAME: &str = "bridge.log.1";
const SOCKET_NAME: &str = "hole-bridge.sock";
const CRASH_PID: u32 = 4242;
const CRASH_MARKER_NAME: &str = "crash-bridge-4242.marker";

fn marker_info() -> MarkerInfo {
    MarkerInfo {
        version: MARKER_VERSION,
        driver: cosca::identity::ProcessIdRecord {
            version: cosca::identity::RECORD_VERSION,
            platform: cosca::identity::Platform::Windows,
            pid: 4242,
            token: 133_700_000_000_000_000,
            boot_id: None,
            pid_ns: None,
        },
    }
}

fn route_record() -> route_state::RouteState {
    route_state::RouteState {
        tun_name: "hole-tun".to_owned(),
        server_ip: "192.0.2.1".parse().unwrap(),
        interface_name: "eth0".to_owned(),
        original_gateway: Some("192.0.2.254".parse().unwrap()),
        route_form: route_state::RouteForm::Via,
        installed: Vec::new(),
        stale: Vec::new(),
    }
}

/// A claim that is lost is the right second answer of a single-occupancy write.
fn claimed_or_taken(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        result => result,
    }
}

fn writers() -> Vec<Writer> {
    vec![
        Writer {
            name: "the lock",
            sources: &[
                "crates/file-lock/src/exclusive/unix.rs",
                "crates/file-lock/src/exclusive/windows.rs",
            ],
            names: &[LOCK_NAME],
            run: |dir, owner| file_lock::Exclusive::acquire(&dir.join(LOCK_NAME), owner).map(drop),
        },
        Writer {
            name: "write_state_file",
            sources: &["crates/util/src/dir.rs"],
            names: &[STATE_NAME],
            run: |dir, owner| util::dir::write_state_file(dir, OsStr::new(STATE_NAME), b"{}", owner),
        },
        Writer {
            name: "the route record, written",
            sources: &["crates/util/src/versioned_file/store.rs"],
            names: &[route_state::STATE_FILE_NAME],
            run: |dir, owner| {
                route_state::write(&route_state::file(dir), &route_record(), owner)
                    .map_err(|err| io::Error::other(err.to_string()))
            },
        },
        Writer {
            name: "the route record, removed",
            sources: &["crates/util/src/versioned_file/store.rs"],
            names: &[route_state::STATE_FILE_NAME],
            run: |dir, _| route_state::remove(&route_state::file(dir)).map(drop),
        },
        Writer {
            name: "the target file",
            sources: &["crates/bridge/src/target.rs"],
            names: &[target::STATE_FILE_NAME],
            run: |dir, owner| target::save(dir, &Target::Off, owner).map_err(|err| io::Error::other(err.to_string())),
        },
        Writer {
            name: "the update marker, written",
            sources: &["crates/common/src/update_marker.rs"],
            names: &[MARKER_FILE],
            run: |dir, owner| update_marker::write(dir, &marker_info(), owner),
        },
        Writer {
            name: "the update marker, claimed",
            sources: &["crates/common/src/update_marker.rs"],
            names: &[MARKER_FILE],
            run: |dir, owner| claimed_or_taken(update_marker::write_new(dir, &marker_info(), owner)),
        },
        Writer {
            name: "the update marker, cleared",
            sources: &["crates/common/src/update_marker.rs"],
            names: &[MARKER_FILE],
            run: |dir, _| update_marker::clear(dir),
        },
        Writer {
            name: "the plugin state, cleared",
            sources: &[],
            names: &[crate::plugin_state::STATE_FILE_NAME],
            run: |dir, _| crate::plugin_state::clear(dir),
        },
        Writer {
            name: "the dns state, cleared",
            sources: &[],
            names: &[crate::dns_state::STATE_FILE_NAME],
            run: |dir, _| crate::dns_state::clear(dir),
        },
        Writer {
            name: "the dns state, superseded",
            sources: &["crates/bridge/src/dns_state.rs"],
            names: &[
                crate::dns_state::STATE_FILE_NAME,
                crate::dns_state::SUPERSEDED_FILE_NAME,
            ],
            run: |dir, _| crate::dns_state::supersede(dir),
        },
        Writer {
            name: "the lockdown state, cleared",
            sources: &[],
            names: &[tun_engine::routing::failclosed::lockdown_state::STATE_FILE_NAME],
            run: |dir, _| tun_engine::routing::failclosed::lockdown_state::clear(dir),
        },
        Writer {
            name: "the socket, bound",
            sources: &[],
            names: &[SOCKET_NAME],
            run: |dir, _| {
                // `tokio`'s listener registers with the runtime that is current when it binds.
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(async { crate::socket::bind(&dir.join(SOCKET_NAME)).map(drop) })
            },
        },
        Writer {
            name: "the crash marker, written",
            sources: &["crates/tombstone/src/crash.rs"],
            names: &[CRASH_MARKER_NAME],
            // The marker is the crash handler's, left root-owned on purpose: it takes no owner.
            run: |dir, _| tombstone::crash::write_marker_for("bridge", CRASH_PID, dir),
        },
        Writer {
            name: "the crash marker, swept",
            sources: &["crates/tombstone/src/crash.rs"],
            names: &[CRASH_MARKER_NAME],
            run: |dir, _| {
                tombstone::sweep(dir);
                Ok(())
            },
        },
        Writer {
            name: "the log, rotated",
            sources: &[
                "crates/common/src/logging.rs",
                "crates/common/src/logging/dir_rotate.rs",
            ],
            names: &[LOG_NAME, LOG_ROTATED_NAME],
            run: |dir, owner| {
                let handle = Dir::open(dir, true, owner)?;
                // More than the limit, so that the file is rotated and opened again.
                DirRotate::new(handle, OsStr::new(LOG_NAME), 16, owner).write_all(&[b'x'; 40])
            },
        },
    ]
}

// Layout --------------------------------------------------------------------------------------------------------------

/// Who the writers hand their files to when the runner can give files away: `nobody` as root. An unprivileged
/// runner can give nothing away, so for it this is itself.
fn owner() -> Owner {
    #[cfg(unix)]
    {
        // SAFETY: geteuid and getegid take no arguments and cannot fail.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        match uid {
            0 => Some((65534, 65534)),
            _ => Some((uid, gid)),
        }
    }
    #[cfg(windows)]
    None
}

/// An owner that is not the runner, so that the victim a test plants (the runner's own file) is not the owner's: a
/// writer must replace the name rather than take the victim for the owner's file. An unprivileged runner cannot
/// give a file to it, so a writer may fail on that; the test looks only at the victim.
fn owner_other_than_the_runner() -> Owner {
    #[cfg(unix)]
    {
        // SAFETY: geteuid and getegid take no arguments and cannot fail.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        match uid {
            0 => Some((65534, 65534)),
            _ => Some((uid + 1, gid + 1)),
        }
    }
    #[cfg(windows)]
    None
}

/// What a planted victim looks like, to compare before and after.
#[derive(Debug, PartialEq, Eq)]
struct Victim {
    content: Vec<u8>,
    readonly: bool,
    #[cfg(unix)]
    mode_and_owner: (u32, u32),
}

impl Victim {
    fn of(path: &Path) -> Victim {
        let meta = std::fs::metadata(path).unwrap();
        Victim {
            content: std::fs::read(path).unwrap(),
            readonly: meta.permissions().readonly(),
            #[cfg(unix)]
            mode_and_owner: {
                use std::os::unix::fs::MetadataExt;
                (meta.mode(), meta.uid())
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Plant {
    HardLink,
    Symlink,
    #[cfg(unix)]
    Fifo,
}

#[cfg(unix)]
const PLANTS: &[Plant] = &[Plant::HardLink, Plant::Symlink, Plant::Fifo];
#[cfg(windows)]
const PLANTS: &[Plant] = &[Plant::HardLink, Plant::Symlink];

fn plant(kind: Plant, victim: &Path, at: &Path) {
    match kind {
        Plant::HardLink => std::fs::hard_link(victim, at).unwrap(),
        #[cfg(unix)]
        Plant::Symlink => std::os::unix::fs::symlink(victim, at).unwrap(),
        #[cfg(windows)]
        Plant::Symlink => std::os::windows::fs::symlink_file(victim, at).unwrap(),
        #[cfg(unix)]
        Plant::Fifo => {
            use std::os::unix::ffi::OsStrExt;
            let path = std::ffi::CString::new(at.as_os_str().as_bytes()).unwrap();
            // SAFETY: `path` is a valid NUL-terminated path.
            assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        }
    }
}

// What a planted name does to a writer --------------------------------------------------------------------------------

#[skuld::test]
fn no_writer_changes_the_file_a_planted_name_leads_to() {
    for writer in writers() {
        for &name in writer.names {
            for &kind in PLANTS {
                let tmp = tempfile::tempdir().unwrap();
                let dir = tmp.path().join("state");
                std::fs::create_dir(&dir).unwrap();
                // A victim only this test's owner may change: what the writer must not.
                let victim = tmp.path().join("victim");
                std::fs::write(&victim, b"victim\n").unwrap();
                let before = Victim::of(&victim);
                // A FIFO has no victim: what is observed is that the writer does not block on it.
                plant(kind, &victim, &dir.join(name));

                // The writer may refuse or replace the name: what it may not do is write through it.
                let _ = (writer.run)(&dir, owner_other_than_the_runner());

                assert_eq!(
                    Victim::of(&victim),
                    before,
                    "{}: a {kind:?} planted at {name} changed the file it leads to",
                    writer.name
                );
            }
        }
    }
}

// What a made folder does to the next run -----------------------------------------------------------------------------

fn run_twice(writer: &Writer, dir: &Path, layout: &str) {
    for run in ["first", "second"] {
        (writer.run)(dir, owner()).unwrap_or_else(|err| panic!("{}: the {run} run {layout}: {err}", writer.name));
    }
}

#[skuld::test]
fn every_writer_runs_twice_in_a_layout_with_no_link() {
    for writer in writers() {
        let tmp = tempfile::tempdir().unwrap();

        run_twice(
            &writer,
            &tmp.path().join("hole").join("state"),
            "with no link on the path",
        );
    }
}

#[skuld::test]
fn every_writer_runs_twice_below_a_link_the_user_owns() {
    // `link` is the user's, to the user's profile: the bridge makes `hole` and `state` below it, as itself.
    for writer in writers() {
        let tmp = tempfile::tempdir().unwrap();
        user_dir(&tmp.path().join("profile"));
        plant_link(&tmp.path().join("profile"), &tmp.path().join("link"));

        run_twice(
            &writer,
            &tmp.path().join("link").join("hole").join("state"),
            "below a link the user owns",
        );
    }
}

// What a planted name does to a reader --------------------------------------------------------------------------------
//
// The readers of the same names run privileged too, and open them as `O_RDONLY`: a FIFO planted at the name makes a
// read by path wait for a writer, and a link is read as whatever it points at. Each row writes a valid file, then
// plants the name and reads again: the reader must not report the valid file the name leads to. A hard link is the
// file's own inode, so a reader cannot tell it from the file and reads what the user put in a folder they own;
// what is read is parsed as that state's schema and never echoed.

struct Reading {
    name: &'static str,
    file: &'static str,
    write_valid: fn(&Path),
    /// Whether the reader reported what `write_valid` wrote.
    reads_it: fn(&Path) -> bool,
}

fn readings() -> Vec<Reading> {
    use crate::{dns_state, plugin_state};
    use hole_common::config::StartupBehavior;
    vec![
        Reading {
            name: "dns_state::load",
            file: dns_state::STATE_FILE_NAME,
            write_valid: |dir| {
                let state = dns_state::DnsState {
                    version: dns_state::SCHEMA_VERSION,
                    advertised: Vec::new(),
                    adapters: Vec::new(),
                };
                util::dir::write_state_file(
                    dir,
                    OsStr::new(dns_state::STATE_FILE_NAME),
                    &serde_json::to_vec(&state).unwrap(),
                    None,
                )
                .unwrap();
            },
            reads_it: |dir| dns_state::load(dir).is_some(),
        },
        Reading {
            name: "plugin_state::load",
            file: plugin_state::STATE_FILE_NAME,
            write_valid: |dir| {
                let state = plugin_state::PluginState {
                    version: plugin_state::SCHEMA_VERSION,
                    plugins: Vec::new(),
                };
                plugin_state::save(dir, &state, None).unwrap();
            },
            reads_it: |dir| matches!(plugin_state::load(dir), plugin_state::Loaded::State(_)),
        },
        Reading {
            name: "target::load",
            file: target::STATE_FILE_NAME,
            // `Off` is what an absent file reads as too, but a planted name is not absent: it reads `Unreadable`.
            write_valid: |dir| target::save(dir, &Target::Off, None).unwrap(),
            reads_it: |dir| matches!(target::load(dir), Target::Off),
        },
        Reading {
            name: "target::load_startup_preference",
            file: target::STARTUP_PREFERENCE_FILE_NAME,
            write_valid: |dir| {
                let preference = target::StartupPreference {
                    on_startup: StartupBehavior::AlwaysConnect,
                    candidate: None,
                };
                target::save_startup_preference(dir, &preference, None).unwrap();
            },
            reads_it: |dir| target::load_startup_preference(dir).on_startup == StartupBehavior::AlwaysConnect,
        },
        Reading {
            name: "update_marker::read",
            file: MARKER_FILE,
            write_valid: |dir| update_marker::write(dir, &marker_info(), None).unwrap(),
            reads_it: |dir| matches!(update_marker::read(dir), update_marker::Marker::Present(_)),
        },
    ]
}

/// Plants `kind` at every reader's name; the failures, one line per reader.
fn readers_that_read_a_planted_name(kind: util::dir::testing::PlantedName) -> Vec<String> {
    let mut failures = Vec::new();
    for reading in readings() {
        let tmp = tempfile::tempdir().unwrap();
        let reader = util::dir::testing::Reader {
            file: reading.file,
            write_valid: &reading.write_valid,
            reads_it: &reading.reads_it,
        };
        if let Err(why) = util::dir::testing::planted_name_is_not_read(tmp.path(), kind, &reader) {
            failures.push(format!("{}: {why}", reading.name));
        }
    }
    failures
}

#[skuld::test]
fn no_reader_reads_through_a_symlink_planted_at_its_name() {
    let failures = readers_that_read_a_planted_name(util::dir::testing::PlantedName::SymlinkToFile);

    assert!(failures.is_empty(), "{failures:#?}");
}

#[skuld::test]
fn no_reader_reads_a_hard_link_the_system_would_not_have_made() {
    // Refused when the runner is the system (a planted second name of a file it owns), read when it is a user.
    let failures = readers_that_read_a_planted_name(util::dir::testing::PlantedName::HardLink);

    assert!(failures.is_empty(), "{failures:#?}");
}

#[cfg(unix)]
#[skuld::test]
fn no_reader_waits_on_a_fifo_planted_at_its_name() {
    let failures = readers_that_read_a_planted_name(util::dir::testing::PlantedName::Fifo);

    assert!(failures.is_empty(), "{failures:#?}");
}

// What a reader says about a file it cannot parse ---------------------------------------------------------------------
//
// A user can put a file they cannot read at a state name: a system file moved into their folder keeps its owner and
// its one link. The parse failure the reader logs goes to `bridge.log`, which the elevated bridge hands to the user,
// so it carries a category and a position and never a fragment of the file.

const ECHOED_SECRET: &str = "hunter2-SECRET";

/// The warnings `read` logs when `file` in a fresh folder holds a `version` that is a string where a number belongs:
/// `serde_json`'s own message for that quotes the string.
fn warnings_for_a_file_that_quotes_a_secret(file: &str, read: fn(&Path)) -> String {
    warnings_for_a_file(file, &format!(r#"{{"version":"{ECHOED_SECRET}"}}"#), read)
}

/// The warnings `read` logs when `file` in a fresh folder holds `content`.
fn warnings_for_a_file(file: &str, content: &str, read: fn(&Path)) -> String {
    use tracing_subscriber::layer::{Layer, SubscriberExt};

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join(file), content).unwrap();
    let writer = crate::test_support::log_capture::VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
    );
    {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        read(tmp.path());
    }
    writer.snapshot_string()
}

/// A reader that logs a parse failure: its name, the file it reads, and a call of it.
type ParseFailureReader = (&'static str, &'static str, fn(&Path));

fn parse_failure_readers() -> [ParseFailureReader; 3] {
    use crate::{dns_state, plugin_state};
    [
        ("update_marker::read", MARKER_FILE, |dir| {
            let _ = update_marker::read(dir);
        }),
        ("dns_state::load", dns_state::STATE_FILE_NAME, |dir| {
            let _ = dns_state::load(dir);
        }),
        ("plugin_state::load", plugin_state::STATE_FILE_NAME, |dir| {
            let _ = plugin_state::load(dir);
        }),
    ]
}

#[skuld::test]
fn no_state_reader_logs_a_fragment_of_a_file_it_cannot_parse() {
    let mut failures = Vec::new();
    for (name, file, read) in parse_failure_readers() {
        let logs = warnings_for_a_file_that_quotes_a_secret(file, read);
        if logs.contains(ECHOED_SECRET) {
            failures.push(format!("{name} logged the file's content: {logs}"));
        } else if !logs.contains("line 1") {
            failures.push(format!("{name}: the warning lost its position: {logs}"));
        }
    }

    assert!(failures.is_empty(), "{failures:#?}");
}

#[skuld::test]
fn the_update_marker_logs_no_fragment_of_a_marker_with_a_secret_field() {
    // `deny_unknown_fields`: serde's message for an unknown field quotes the field's name.
    let content = format!(r#"{{"version":3,"{ECHOED_SECRET}":1}}"#);
    let logs = warnings_for_a_file(MARKER_FILE, &content, |dir| {
        let _ = update_marker::read(dir);
    });

    assert!(
        !logs.contains(ECHOED_SECRET),
        "the marker reader logged the file's content: {logs}"
    );
    assert!(logs.contains("line 1"), "the warning lost its position: {logs}");
}

/// The `serde_json` functions that parse a document into a type.
const JSON_PARSERS: &[&str] = &["from_slice", "from_str", "from_value", "from_reader"];

/// What makes a parse's error content-safe where it happens: a `ParseFailure`, or the two helpers it is built from.
const CONVERSIONS: &[&str] = &["ParseFailure::from(", "parse_kind(", "describe_parse_error("];

/// The privileged crates whose JSON parses the scan covers: the ones that read state a user's folder may hold.
const JSON_PARSE_CRATES: &[&str] = &["bridge", "tun-engine", "util", "common"];

/// One `serde_json` parse in a source and whether its error is converted before it can be logged.
#[derive(Debug, PartialEq, Eq)]
struct JsonParse<'a> {
    line: &'a str,
    converted: bool,
}

/// Whether `line` calls `name` bare: not as part of a longer name or a path (`extend_from_slice(` is not `from_slice(`).
fn calls_by_name(line: &str, name: &str) -> bool {
    line.match_indices(name).any(|(at, _)| {
        let before = line[..at].chars().next_back();
        let after = &line[at + name.len()..];
        !before.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == ':')
            && (after.starts_with('(') || after.starts_with("::<"))
    })
}

/// Every parse of JSON in `text`, whatever the spelling: `serde_json::from_*`, a `from_*` imported by name, and
/// `Deserializer::from_*`. A parse's own error quotes the file back; a conversion within the parse's statement cannot.
/// The conversion is looked for from the parse to the next parse or the next `fn`, so one conversion covers one parse.
fn json_parses(text: &str) -> Vec<JsonParse<'_>> {
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect();
    let imported: Vec<&str> = JSON_PARSERS
        .iter()
        .copied()
        .filter(|name| {
            lines
                .iter()
                .any(|line| line.trim_start().starts_with("use serde_json::") && line.contains(name))
        })
        .collect();
    let is_parse = |line: &str| {
        !line.trim_start().starts_with("use ")
            && (line.contains("serde_json::from_")
                || line.contains("Deserializer::from_")
                || imported.iter().any(|name| calls_by_name(line, name)))
    };
    let starts_a_fn = |line: &str| line.split_whitespace().any(|word| word == "fn");

    let mut parses = Vec::new();
    for (at, line) in lines.iter().enumerate().filter(|(_, line)| is_parse(line)) {
        let following = lines[at + 1..]
            .iter()
            .take_while(|next| !is_parse(next) && !starts_a_fn(next))
            .count();
        let converted = lines[at..=at + following]
            .iter()
            .any(|line| CONVERSIONS.iter().any(|conversion| line.contains(conversion)));
        parses.push(JsonParse { line, converted });
    }
    parses
}

/// Parses of JSON in the privileged crates whose error is not converted, each with why it may be. The text is a part
/// of the parse's line; the reason says where the error goes.
const JSON_PARSE_ALLOWED: &[(&str, &str, &str)] = &[
    (
        "crates/common/src/import.rs",
        "serde_json::from_str(json)?",
        "`?` into `ImportError`, whose `From<serde_json::Error>` keeps a category and a position",
    ),
    (
        "crates/tun-engine/src/routing/failclosed.rs",
        "serde_json::from_slice::<serde_json::Value>(bytes)",
        "`.ok()` drops the error; only a salvaged `pf_token` leaves the function",
    ),
    (
        "crates/bridge/src/test_support/dist_harness.rs",
        "let status: StatusResponse = serde_json::from_slice(&body)?",
        "test support: the harness parses the IPC replies of a bridge the test started",
    ),
    (
        "crates/bridge/src/test_support/dist_harness.rs",
        "BridgeResponse::StartFailed(serde_json::from_slice(&body)?)",
        "test support: the harness parses the IPC replies of a bridge the test started",
    ),
    (
        "crates/bridge/src/test_support/dist_harness.rs",
        "let metrics: MetricsResponse = serde_json::from_slice(&body)?",
        "test support: the harness parses the IPC replies of a bridge the test started",
    ),
    (
        "crates/bridge/src/test_support/dist_harness.rs",
        "let diag: DiagnosticsResponse = serde_json::from_slice(&body)?",
        "test support: the harness parses the IPC replies of a bridge the test started",
    ),
    (
        "crates/bridge/src/test_support/dist_harness.rs",
        "let parsed: TestServerResponse = serde_json::from_slice(&body)?",
        "test support: the harness parses the IPC replies of a bridge the test started",
    ),
    (
        "crates/bridge/src/test_support/dist_harness.rs",
        "let err: ErrorResponse = serde_json::from_slice(&body).unwrap_or(",
        "test support: the harness parses the IPC replies of a bridge the test started",
    ),
];

#[skuld::test]
fn no_privileged_json_parse_keeps_the_raw_error() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let mut hits = Vec::new();
    for (relative, path) in privileged_sources(&root).into_iter().filter(|(relative, _)| {
        JSON_PARSE_CRATES
            .iter()
            .any(|krate| relative.starts_with(&format!("crates/{krate}/")))
    }) {
        let text = std::fs::read_to_string(&path).unwrap();
        for parse in json_parses(&text).into_iter().filter(|parse| !parse.converted) {
            let allowed = JSON_PARSE_ALLOWED
                .iter()
                .any(|(file, part, _)| *file == relative && parse.line.contains(part));
            if !allowed {
                hits.push(format!("{relative}: {}", parse.line.trim()));
            }
        }
    }

    assert!(
        hits.is_empty(),
        "a privileged crate parses JSON and keeps the `serde_json::Error`, whose text quotes the file (and the file may be one a user placed): convert it with `ParseFailure::from(&e)` where the parse happens, or add the parse to JSON_PARSE_ALLOWED with the reason: {hits:#?}"
    );
}

#[skuld::test]
fn every_json_parse_allowance_still_names_an_unconverted_parse() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    for (file, part, reason) in JSON_PARSE_ALLOWED {
        let text = std::fs::read_to_string(root.join(file)).unwrap_or_else(|err| panic!("{file} ({reason}): {err}"));
        assert!(
            json_parses(&text)
                .iter()
                .any(|parse| !parse.converted && parse.line.contains(part)),
            "{file} no longer has an unconverted parse `{part}`: remove its allowance ({reason})"
        );
    }
}

#[skuld::test]
fn the_json_parse_scan_counts_each_parse_against_its_own_conversion() {
    let parse = "    match serde_json::from_slice::<State>(&b) {";
    let convert = "        Err(e) => { let e = util::parse_error::ParseFailure::from(&e); }";
    let converted = |text: &str| -> Vec<bool> { json_parses(text).iter().map(|p| p.converted).collect() };

    assert_eq!(converted(parse), [false]);
    assert_eq!(converted(&format!("{parse}\n{convert}")), [true]);
    // A conversion covers the parse it follows, not the next one.
    assert_eq!(converted(&format!("{parse}\n{convert}\n{parse}")), [true, false]);
    assert_eq!(converted(&format!("{parse}\n{parse}\n{convert}")), [false, true]);
    // ... nor one in the next function.
    assert_eq!(converted(&format!("{parse}\nfn other() {{\n{convert}")), [false]);
    // A conversion on the parse's own line counts.
    assert_eq!(
        converted("serde_json::from_slice(b).map_err(|e| ParseFailure::from(&e))"),
        [true]
    );
    assert!(converted(&format!("// {parse}")).is_empty());
}

#[skuld::test]
fn the_json_parse_scan_sees_every_spelling_of_a_parse() {
    let sites = |text: &str| json_parses(text).len();

    assert_eq!(sites("let v = serde_json::from_str::<T>(s);"), 1);
    assert_eq!(sites("let v = serde_json::from_value(v);"), 1);
    assert_eq!(sites("let v = serde_json::from_reader(r);"), 1);
    assert_eq!(sites("let mut de = serde_json::Deserializer::from_slice(b);"), 1);
    assert_eq!(
        sites("use serde_json::Deserializer;\nlet mut de = Deserializer::from_str(s);"),
        1
    );
    assert_eq!(sites("use serde_json::from_slice;\nlet v: T = from_slice(b)?;"), 1);
    assert_eq!(
        sites("use serde_json::{from_str, Value};\nlet v = from_str::<T>(s);"),
        1
    );
    // Not a parse: a name that is only part of another, an import the file never calls, a `from_*` that is not serde_json's.
    assert_eq!(sites("use serde_json::from_slice;\nbuf.extend_from_slice(b);"), 0);
    assert_eq!(sites("buf.extend_from_slice(b);\nlet a = u8::from_str(s);"), 0);
    assert_eq!(sites("let v = from_slice(b);"), 0);
}

// No privileged read goes by path -------------------------------------------------------------------------------------

/// What opens a file by a path: the reads the privileged state code must make through `util::dir` instead.
const READS_BY_PATH: &[&str] = &["fs::read(", "fs::read_to_string(", "File::open(", "OpenOptions::new("];

/// The crates whose code runs privileged on state or log directories. `hole` is one: `hole bridge run` is the bridge.
const PRIVILEGED_CRATES: &[&str] = &[
    "bridge",
    "tun-engine",
    "util",
    "file-lock",
    "common",
    "tombstone",
    "hole",
];

/// Production sources that open a file by path, each with why it may. A path is a source file from the workspace
/// root; the reason says who runs it and where the path points.
const BY_PATH_ALLOWED: &[(&str, &str)] = &[
    ("crates/bridge/src/bin/test_plugin.rs", "a test binary"),
    ("crates/bridge/src/bin/test_service.rs", "a test binary"),
    (
        "crates/bridge/src/test_support/dist_harness.rs",
        "test support: reads the log of a process the test started",
    ),
    ("crates/tun-engine/src/test_utils/escape.rs", "test support"),
    (
        "crates/tun-engine/src/test_utils/pktmon.rs",
        "test support: reads a capture the test made",
    ),
    ("crates/util/src/dir/testing.rs", "test fixtures"),
    (
        "crates/common/src/config.rs",
        "the GUI's own user config: syncs the folder of the file the user's GUI wrote",
    ),
    (
        "crates/common/src/config_store.rs",
        "the GUI's own user config, read and written as the user",
    ),
    ("crates/common/src/logging/logging_test_helpers.rs", "test helpers"),
    (
        "crates/common/src/verify.rs",
        "hashes an installer the GUI downloaded, as the user",
    ),
    (
        "crates/hole/src/cli.rs",
        "`hole bridge log`, `hole proxy` and the log tail read files the user names, as the user",
    ),
    (
        "crates/hole/src/commands.rs",
        "the GUI imports a file the user picked, as the user",
    ),
    (
        "crates/hole/src/elevation.rs",
        "reads a request and a result file in the requester's own private temp folder",
    ),
    (
        "crates/hole/src/log_collector.rs",
        "the GUI zips its own user's logs, as the user",
    ),
    (
        "crates/hole/src/setup.rs",
        "reads the log of an elevated child from the requester's own private temp folder",
    ),
];

fn production_sources(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let file_name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.is_dir() {
            if !matches!(file_name.as_str(), "tests" | "target") {
                production_sources(&path, found);
            }
        } else if file_name.ends_with(".rs") && !file_name.ends_with("_tests.rs") {
            found.push(path);
        }
    }
}

/// The by-path reads on the code lines of `text`.
fn by_path_reads(text: &str) -> Vec<&'static str> {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .flat_map(|line| READS_BY_PATH.iter().copied().filter(move |read| line.contains(read)))
        .collect()
}

#[skuld::test]
fn no_privileged_state_code_reads_a_file_by_path() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let mut hits = Vec::new();
    for (relative, path) in privileged_sources(&root) {
        if BY_PATH_ALLOWED.iter().any(|(allowed, _)| *allowed == relative) {
            continue;
        }
        for read in by_path_reads(&std::fs::read_to_string(&path).unwrap()) {
            hits.push(format!("{relative}: {read}"));
        }
    }

    assert!(
        hits.is_empty(),
        "a privileged read opens a file by path: use `util::dir::read_state_file` (or a `Dir`), or add the file to BY_PATH_ALLOWED with the reason: {hits:#?}"
    );
}

#[skuld::test]
fn every_by_path_allowance_still_reads_by_path() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    for (path, reason) in BY_PATH_ALLOWED {
        let text = std::fs::read_to_string(root.join(path)).unwrap_or_else(|err| panic!("{path} ({reason}): {err}"));
        assert!(
            !by_path_reads(&text).is_empty(),
            "{path} no longer reads by path: remove its allowance ({reason})"
        );
    }
}

#[skuld::test]
fn the_by_path_scan_tells_a_read_from_a_comment() {
    assert_eq!(by_path_reads("let bytes = std::fs::read(&path)?;"), ["fs::read("]);
    assert_eq!(by_path_reads("let f = std::fs::File::open(p)?;"), ["File::open("]);
    assert!(by_path_reads("    // `std::fs::read(path)` is what this replaces").is_empty());
    assert!(by_path_reads("util::dir::read_state_file(dir, name)").is_empty());
}

// No privileged step resolves a link before the walk ------------------------------------------------------------------
//
// The walk of `util::dir` refuses a link the user planted in a folder's path. A path resolved first has no link left
// to refuse: `canonicalize` follows every link with no rule, so the user's link to a folder of root's becomes the
// folder's own name and the walk accepts it. A privileged step passes the path as it was given.

/// What resolves the links of a path: `std::fs::canonicalize`, `Path::canonicalize`, `dunce::canonicalize`, libc's
/// `realpath`.
const RESOLVES_LINKS: &[&str] = &["canonicalize(", "realpath("];

/// Production lines that resolve a path's links, each with why they may: the file, a fragment of the line and the
/// reason. None names a state or log directory.
const RESOLVING_ALLOWED: &[(&str, &str, &str)] = &[
    (
        "crates/bridge/src/cutover/extract.rs",
        "canonicalize(dir)",
        "a dedup key for the walk of an extracted payload: nothing is opened through it",
    ),
    (
        "crates/bridge/src/proxy/config.rs",
        "canonicalize(&exe)",
        "the bridge's own executable, to find the plugin beside it",
    ),
    (
        "crates/tun-engine/src/device/wintun.rs",
        "canonicalize(&exe)",
        "the process's own executable, to find `wintun.dll` beside it",
    ),
    (
        "crates/hole/src/path_management.rs",
        "canonicalize(&exe)",
        "the process's own executable, for the `PATH` link",
    ),
    (
        "crates/hole/src/setup.rs",
        "canonicalize(&exe)",
        "the process's own executable, to register as the bridge",
    ),
];

/// The code lines of `text` that resolve a path's links.
fn link_resolutions(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .filter(|line| RESOLVES_LINKS.iter().any(|call| line.contains(call)))
        .collect()
}

fn privileged_sources(root: &Path) -> Vec<(String, PathBuf)> {
    let mut found = Vec::new();
    for krate in PRIVILEGED_CRATES {
        let mut sources = Vec::new();
        production_sources(&root.join("crates").join(krate).join("src"), &mut sources);
        for path in sources {
            let relative = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            found.push((relative, path));
        }
    }
    found
}

#[skuld::test]
fn no_privileged_code_resolves_a_link_before_the_walk() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let mut hits = Vec::new();
    for (relative, path) in privileged_sources(&root) {
        for line in link_resolutions(&std::fs::read_to_string(&path).unwrap()) {
            let allowed = RESOLVING_ALLOWED
                .iter()
                .any(|(file, fragment, _)| *file == relative && line.contains(fragment));
            if !allowed {
                hits.push(format!("{relative}: {line}"));
            }
        }
    }

    assert!(
        hits.is_empty(),
        "privileged code resolves the links of a path: pass the path as given (`std::path::absolute` if it must be absolute), or add the line to RESOLVING_ALLOWED with the reason: {hits:#?}"
    );
}

#[skuld::test]
fn every_link_resolution_allowance_still_applies() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    for (path, fragment, reason) in RESOLVING_ALLOWED {
        let text = std::fs::read_to_string(root.join(path)).unwrap_or_else(|err| panic!("{path} ({reason}): {err}"));
        assert!(
            link_resolutions(&text).iter().any(|line| line.contains(fragment)),
            "{path} no longer has `{fragment}`: remove its allowance ({reason})"
        );
    }
}

#[skuld::test]
fn the_link_resolution_scan_tells_a_call_from_a_comment() {
    assert_eq!(
        link_resolutions("let dir = state_dir.canonicalize().unwrap_or(state_dir);"),
        ["let dir = state_dir.canonicalize().unwrap_or(state_dir);"]
    );
    assert_eq!(
        link_resolutions("std::fs::canonicalize(&exe)?"),
        ["std::fs::canonicalize(&exe)?"]
    );
    assert_eq!(link_resolutions("libc::realpath(p, out)"), ["libc::realpath(p, out)"]);
    assert!(link_resolutions("    // `canonicalize()` follows every link").is_empty());
    assert!(link_resolutions("canonicalize_for_match(domain)").is_empty());
    assert!(link_resolutions("std::path::absolute(path)?").is_empty());
}

// No state module logs a path -----------------------------------------------------------------------------------------
//
// `bridge.log` ships in the support bundle, and the state directory sits in the user's profile when the bridge runs
// for a user: the path names the user. The modules that read and write the state files log the file's name.

const STATE_MODULES: &[&str] = &[
    "crates/bridge/src/dns_state.rs",
    "crates/bridge/src/plugin_state.rs",
    "crates/bridge/src/plugin_recovery.rs",
    "crates/bridge/src/target.rs",
    "crates/common/src/update_marker.rs",
    "crates/tun-engine/src/routing/failclosed/boottime_witness.rs",
    "crates/tun-engine/src/routing/failclosed/failclosed_state.rs",
    "crates/tun-engine/src/routing/failclosed/lockdown_pf_state.rs",
    "crates/tun-engine/src/routing/failclosed/lockdown_state.rs",
];

#[skuld::test]
fn no_state_module_logs_a_path() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let mut hits = Vec::new();
    for module in STATE_MODULES {
        let text = std::fs::read_to_string(root.join(module)).unwrap_or_else(|err| panic!("{module}: {err}"));
        for (n, line) in text.lines().enumerate() {
            if !line.trim_start().starts_with("//") && line.contains(".display()") {
                hits.push(format!("{module}:{}: {}", n + 1, line.trim()));
            }
        }
    }

    assert!(
        hits.is_empty(),
        "a state module formats a path (log the file's name): {hits:#?}"
    );
}

// The list is complete ------------------------------------------------------------------------------------------------

fn sources_in(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let file_name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.is_dir() {
            // `tests` holds integration tests; `dir` is `util::dir` itself.
            if !matches!(file_name.as_str(), "tests" | "target" | "dir") {
                sources_in(&path, found);
            }
        } else if file_name.ends_with(".rs") && !file_name.ends_with("_tests.rs") {
            found.push(path);
        }
    }
}

/// Whether the production source `text` opens a `Dir`: a line of code, not a comment, that names one of the openers.
fn opens_a_dir(text: &str) -> bool {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .any(|line| line.contains("Dir::open") || line.contains("append_own_file("))
}

#[skuld::test]
fn every_file_that_opens_a_dir_has_a_row() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let mut found = Vec::new();
    for krate in std::fs::read_dir(root.join("crates")).unwrap() {
        let src = krate.unwrap().path().join("src");
        if src.is_dir() {
            sources_in(&src, &mut found);
        }
    }
    let mut opening: Vec<String> = found
        .iter()
        .filter(|path| opens_a_dir(&std::fs::read_to_string(path).unwrap()))
        .map(|path| path.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/"))
        .collect();
    // `util::dir` itself is a source file of the walk, not a user of it, but `write_state_file` lives in `dir.rs`:
    // the scan skips the folder `dir/` and keeps `dir.rs`.
    opening.sort();
    let mut listed: Vec<String> = writers()
        .iter()
        .flat_map(|writer| writer.sources.iter().map(|source| source.to_string()))
        .collect();
    listed.sort();
    listed.dedup();

    assert_eq!(
        opening, listed,
        "the source files that open a Dir and the files the writer table lists differ: add the writer to `writers()`"
    );
}

#[skuld::test]
fn the_scan_tells_code_from_a_comment() {
    assert!(opens_a_dir("let dir = Dir::open(path, true, None)?;"));
    assert!(opens_a_dir("dir.append_own_file(&name, 0o644, owner)"));
    assert!(!opens_a_dir("    // goes through `Dir::open` first"));
    assert!(!opens_a_dir("/// see [`Dir::open_as`]"));
}

// No privileged step changes an owner or a mode by name ---------------------------------------------------------------
//
// `chown(path)` and `chmod(path)` resolve the name again, so a name the user swaps (a hard link to a file of
// root's, a directory of their own) is what changes. A privileged step changes a file through the handle it holds.

/// What names its target: the by-path calls of unix and Windows that change an owner, a mode or an ACL.
const BY_NAME: &[&str] = &[
    "fchownat",
    "fchmodat",
    "libc::chown",
    "libc::lchown",
    "libc::chmod",
    "libc::lchmod",
    "fs::chown",
    "fs::lchown",
    "fs::set_permissions",
    "SetNamedSecurityInfo",
    "SetFileSecurity",
    "SetFileAttributes",
];

/// The by-name calls on the code lines of `text`.
fn by_name_calls(text: &str) -> Vec<&'static str> {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .flat_map(|line| BY_NAME.iter().copied().filter(move |call| line.contains(call)))
        .collect()
}

/// The files that must not call one: the sources of `util::dir` and every source file that opens a `Dir`. Not
/// `util::dir::testing`, which is compiled for tests and changes only the fixtures a test made.
fn privileged_dir_sources(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for krate in std::fs::read_dir(root.join("crates")).unwrap() {
        let src = krate.unwrap().path().join("src");
        if src.is_dir() {
            sources_in(&src, &mut found);
        }
    }
    found.retain(|path| opens_a_dir(&std::fs::read_to_string(path).unwrap()));
    let util_dir = root.join("crates").join("util").join("src").join("dir");
    found.push(root.join("crates").join("util").join("src").join("dir.rs"));
    for entry in std::fs::read_dir(util_dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.is_file() && name.ends_with(".rs") && !name.ends_with("_tests.rs") && name != "testing.rs" {
            found.push(path);
        }
    }
    let windows = root.join("crates").join("util").join("src").join("dir").join("windows");
    for entry in std::fs::read_dir(windows).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.ends_with(".rs") && !name.ends_with("_tests.rs") {
            found.push(path);
        }
    }
    found.sort();
    found.dedup();
    found
}

#[skuld::test]
fn no_privileged_dir_code_changes_an_owner_or_a_mode_by_name() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let sources = privileged_dir_sources(&root);
    assert!(
        sources.iter().any(|path| path.ends_with("dir/unix.rs")) && sources.iter().any(|path| path.ends_with("dir.rs")),
        "the scan must cover util::dir itself: {sources:?}"
    );

    let mut hits = Vec::new();
    for path in &sources {
        for call in by_name_calls(&std::fs::read_to_string(path).unwrap()) {
            hits.push(format!("{}: {call}", path.strip_prefix(&root).unwrap().display()));
        }
    }

    assert!(
        hits.is_empty(),
        "a privileged step changes an owner or a mode by name; do it through the handle (`fchown`, `fchmod`, \
         `SetSecurityInfo`) after checking what it is: {hits:#?}"
    );
}

#[skuld::test]
fn the_by_name_scan_tells_a_name_from_a_handle() {
    assert_eq!(by_name_calls("libc::fchownat(dir, name, uid, gid, 0)"), ["fchownat"]);
    assert_eq!(
        by_name_calls("std::fs::set_permissions(path, perms)"),
        ["fs::set_permissions"]
    );
    assert_eq!(
        by_name_calls("SetNamedSecurityInfoW(&path, ..)"),
        ["SetNamedSecurityInfo"]
    );
    assert!(by_name_calls("libc::fchown(fd, uid, gid)").is_empty());
    assert!(by_name_calls("file.set_permissions(perms)").is_empty());
    assert!(by_name_calls("SetSecurityInfo(handle, ..)").is_empty());
    assert!(by_name_calls("    // fchownat is the by-name call").is_empty());
}
