//! Every privileged writer into a state directory, held to the same two properties, and the readers of the same names
//! held to a third (below).
//!
//! These code paths run as root/SYSTEM in folders the interactive user may own, so the user can plant a name and
//! shape the layout above it:
//!
//! - A hard link, a symlink or a FIFO planted at a name the writer acts on is never written through, and the file it
//!   leads to is left as it was (content, mode, owner). The writer also answers the name: it takes it over or removes
//!   it, or refuses it with a typed refusal ([`AtAPlantedName`]); one that fails for another reason, or succeeds and
//!   leaves the name alone, fails the test.
//! - A second run in the same layout succeeds, with or without a link the user owns on the path: the folders the
//!   first run made must pass the walk of the second.
//!
//! The table below is the list of writers. A source file that changes a state directory (see [`WRITES_A_DIR`]) and is
//! not in it fails [`every_file_that_opens_a_dir_has_a_row`], so a new writer cannot skip these tests. The owner
//! observations (a file given away, a made folder handed over) need root or an elevated token; run as the user, the
//! same tests check what they can.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use hole_common::logging::dir_rotate::DirRotate;
use hole_common::update_marker::{self, MarkerInfo, MARKER_FILE, MARKER_VERSION};
use tun_engine::routing::state as route_state;
use util::dir::testing::{plant_link, user_dir};
use util::dir::{Dir, Refusal};

use crate::target::{self, Target, TargetError};
use util::versioned_file::StoreError;

mod scan;

// The table -----------------------------------------------------------------------------------------------------------

/// The unix ids a writer hands its files to.
type Owner = Option<(u32, u32)>;

/// What a writer does with a name a user planted where it writes, one answer per row. A refusal that names what was
/// refused (`util::dir::Refusal`, `file_lock::Refused`) is an acceptable answer to any plant.
#[derive(Debug, Clone, Copy)]
enum AtAPlantedName {
    /// Takes the name over or removes it, whatever sits there: afterwards the name no longer leads to what was
    /// planted.
    Replaces,
    /// Like [`Self::Replaces`], except that a file the expected owner already owns is kept and used as it is (the lock
    /// and the log do this by contract): a hard link to a file of the owner's own.
    KeepsAFileItsOwnerOwns,
    /// A claim that is lost: `AlreadyExists`, with the planted name left as it was.
    ClaimedElsewhere,
    /// Writes under another name and leaves the planted one as it was.
    WritesElsewhere,
}

impl AtAPlantedName {
    /// Whether `result` of running the writer is what this kind answers, given what the folder shows afterwards.
    fn accepts(self, result: &io::Result<()>, after: &Afterwards) -> Result<(), String> {
        if let Err(err) = result {
            let refusal = is_a_refusal(err);
            let lost_claim =
                matches!(self, AtAPlantedName::ClaimedElsewhere) && err.kind() == io::ErrorKind::AlreadyExists;
            return match refusal || lost_claim {
                true => Ok(()),
                false => Err(format!(
                    "failed with something that is not a refusal of that name: {err}"
                )),
            };
        }
        match self {
            AtAPlantedName::Replaces if after.name_leads_to_the_victim => {
                Err("succeeded, and the name still leads to the file that was planted".to_owned())
            }
            AtAPlantedName::Replaces => Ok(()),
            AtAPlantedName::KeepsAFileItsOwnerOwns if after.name_leads_to_the_victim && !after.victim_is_the_owners => {
                Err("succeeded, and the name still leads to the file that was planted".to_owned())
            }
            AtAPlantedName::KeepsAFileItsOwnerOwns => Ok(()),
            AtAPlantedName::ClaimedElsewhere => Err("succeeded at a name somebody else holds".to_owned()),
            AtAPlantedName::WritesElsewhere if after.holds_another_name => Ok(()),
            AtAPlantedName::WritesElsewhere => Err("succeeded, and wrote nothing under another name".to_owned()),
        }
    }
}

/// What a writer reports when it left a file it could not read as it was: the route record's `Cleared::Kept`.
#[derive(Debug)]
struct LeftAsItIs;

impl std::fmt::Display for LeftAsItIs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the file was left as it is")
    }
}

impl std::error::Error for LeftAsItIs {}

/// Whether `err` is, or wraps, a refusal that names what it refused: the walk's (`util::dir::Refusal`), the lock's, or a
/// versioned file's decision to leave a file it cannot read as it is.
fn is_a_refusal(err: &io::Error) -> bool {
    let mut current = err.get_ref().map(|inner| inner as &(dyn std::error::Error + 'static));
    while let Some(error) = current {
        let versioned_file_left_it = matches!(
            error.downcast_ref::<StoreError>(),
            Some(StoreError::Unreadable { .. } | StoreError::ReadFailed { .. })
        );
        if error.downcast_ref::<Refusal>().is_some()
            || error.downcast_ref::<file_lock::Refused>().is_some()
            || error.downcast_ref::<LeftAsItIs>().is_some()
            || versioned_file_left_it
        {
            return true;
        }
        current = error.source();
    }
    false
}

/// What the folder shows after a writer ran at a planted name.
struct Afterwards {
    /// The name is, or leads to, the file that was planted.
    name_leads_to_the_victim: bool,
    /// The folder holds a name besides the planted one.
    holds_another_name: bool,
    /// The victim is a file of the owner the writer was given: a hard link to it is the owner's own file.
    victim_is_the_owners: bool,
}

struct Writer {
    name: &'static str,
    /// The production source files whose writes this row exercises, from the workspace root. Every file that writes
    /// into a state directory (see [`WRITES_A_DIR`]) is in the rows, for every platform: the scan reads text.
    sources: &'static [&'static str],
    /// The names in the writer's directory it acts on, which a user can plant.
    names: &'static [&'static str],
    /// What it does at one.
    at_a_planted_name: AtAPlantedName,
    /// Whether this platform runs the row: a writer of another platform is listed for its sources only.
    runs_here: bool,
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

/// The macOS rows. Another platform lists their sources and runs none of them.
#[cfg(target_os = "macos")]
fn macos_writers() -> Vec<Writer> {
    use tun_engine::routing::failclosed::{failclosed_state, lockdown_pf_state};
    vec![
        Writer {
            name: "the pf cover state, saved",
            sources: &["crates/tun-engine/src/routing/failclosed/failclosed_state.rs"],
            names: &[failclosed_state::STATE_FILE_NAME],
            at_a_planted_name: AtAPlantedName::Replaces,
            runs_here: true,
            run: |dir, owner| {
                let state = failclosed_state::FailClosedState {
                    version: failclosed_state::SCHEMA_VERSION,
                    pf_token: "0".to_owned(),
                    pf_was_enabled: false,
                };
                failclosed_state::save(dir, &state, owner)
            },
        },
        Writer {
            name: "the pf cover state, cleared",
            sources: &[],
            names: &[failclosed_state::STATE_FILE_NAME],
            at_a_planted_name: AtAPlantedName::Replaces,
            runs_here: true,
            run: |dir, _| failclosed_state::clear(dir),
        },
        Writer {
            name: "the pf lockdown state, saved",
            sources: &["crates/tun-engine/src/routing/failclosed/lockdown_pf_state.rs"],
            names: &[lockdown_pf_state::STATE_FILE_NAME],
            at_a_planted_name: AtAPlantedName::Replaces,
            runs_here: true,
            run: |dir, owner| {
                let state = lockdown_pf_state::LockdownPfState {
                    version: lockdown_pf_state::SCHEMA_VERSION,
                    pf_token: "0".to_owned(),
                    main_snapshot: String::new(),
                    nat_snapshot: String::new(),
                    main_snapshot_captured: true,
                };
                lockdown_pf_state::save(dir, &state, owner)
            },
        },
        Writer {
            name: "the pf lockdown state, cleared",
            sources: &[],
            names: &[lockdown_pf_state::STATE_FILE_NAME],
            at_a_planted_name: AtAPlantedName::Replaces,
            runs_here: true,
            run: |dir, _| lockdown_pf_state::clear(dir),
        },
    ]
}

#[cfg(not(target_os = "macos"))]
fn macos_writers() -> Vec<Writer> {
    vec![Writer {
        name: "the pf states (macOS)",
        sources: &[
            "crates/tun-engine/src/routing/failclosed/failclosed_state.rs",
            "crates/tun-engine/src/routing/failclosed/lockdown_pf_state.rs",
        ],
        names: &[],
        at_a_planted_name: AtAPlantedName::Replaces,
        runs_here: false,
        run: |_, _| unreachable!("a row of another platform is not run"),
    }]
}

/// The Windows rows. Another platform lists their sources and runs none of them.
#[cfg(windows)]
fn windows_writers() -> Vec<Writer> {
    vec![Writer {
        name: "the installer SID, written",
        sources: &["crates/bridge/src/ipc.rs"],
        names: &[crate::ipc::INSTALLER_USER_SID_FILE],
        at_a_planted_name: AtAPlantedName::Replaces,
        runs_here: true,
        run: |dir, _| crate::ipc::write_installer_user_sid(dir, "S-1-5-32-545"),
    }]
}

#[cfg(not(windows))]
fn windows_writers() -> Vec<Writer> {
    vec![Writer {
        name: "the installer SID (Windows)",
        sources: &["crates/bridge/src/ipc.rs"],
        names: &[],
        at_a_planted_name: AtAPlantedName::Replaces,
        runs_here: false,
        run: |_, _| unreachable!("a row of another platform is not run"),
    }]
}

fn writers() -> Vec<Writer> {
    use tun_engine::routing::failclosed::{boottime_witness, lockdown_state};
    let mut rows = vec![
        Writer {
            name: "the lock",
            sources: &[
                "crates/file-lock/src/exclusive/unix.rs",
                "crates/file-lock/src/exclusive/windows.rs",
            ],
            names: &[LOCK_NAME],
            at_a_planted_name: AtAPlantedName::KeepsAFileItsOwnerOwns,
            runs_here: true,
            run: |dir, owner| file_lock::Exclusive::acquire(&dir.join(LOCK_NAME), owner).map(drop),
        },
        Writer {
            name: "write_state_file",
            sources: &["crates/util/src/dir.rs"],
            names: &[STATE_NAME],
            at_a_planted_name: AtAPlantedName::Replaces,
            runs_here: true,
            run: |dir, owner| util::dir::write_state_file(dir, OsStr::new(STATE_NAME), b"{}", owner),
        },
        Writer {
            name: "the route record, written",
            sources: &[
                "crates/util/src/versioned_file/store.rs",
                "crates/tun-engine/src/routing/state.rs",
            ],
            names: &[route_state::STATE_FILE_NAME],
            at_a_planted_name: AtAPlantedName::Replaces,
            runs_here: true,
            run: |dir, owner| {
                route_state::write(&route_state::file(dir), &route_record(), owner).map_err(io::Error::other)
            },
        },
        Writer {
            name: "the route record, removed",
            sources: &[],
            names: &[route_state::STATE_FILE_NAME],
            at_a_planted_name: AtAPlantedName::Replaces,
            runs_here: true,
            run: |dir, _| match route_state::remove(&route_state::file(dir))? {
                route_state::Cleared::Kept => Err(io::Error::other(LeftAsItIs)),
                _ => Ok(()),
            },
        },
        Writer {
            name: "the target file",
            sources: &["crates/bridge/src/target.rs"],
            names: &[target::STATE_FILE_NAME],
            at_a_planted_name: AtAPlantedName::Replaces,
            runs_here: true,
            run: |dir, owner| {
                target::save(dir, &Target::Off, owner).map_err(|err| match err {
                    // The io error inside is where a refusal of the walk is.
                    TargetError::CreateDir(err)
                    | TargetError::Write(err)
                    | TargetError::SetPermissions(err)
                    | TargetError::Lock(err) => err,
                    err => io::Error::other(err),
                })
            },
        },
        Writer {
            name: "the update marker, written",
            sources: &["crates/common/src/update_marker.rs"],
            names: &[MARKER_FILE],
            at_a_planted_name: AtAPlantedName::Replaces,
            runs_here: true,
            run: |dir, owner| update_marker::write(dir, &marker_info(), owner),
        },
        Writer {
            name: "the update marker, claimed",
            sources: &[],
            names: &[MARKER_FILE],
            at_a_planted_name: AtAPlantedName::ClaimedElsewhere,
            runs_here: true,
            run: |dir, owner| update_marker::write_new(dir, &marker_info(), owner),
        },
        Writer {
            name: "the update marker, cleared",
            sources: &[],
            names: &[MARKER_FILE],
            at_a_planted_name: AtAPlantedName::Replaces,
            runs_here: true,
            run: |dir, _| update_marker::clear(dir),
        },
        Writer {
            name: "the plugin state, saved",
            sources: &["crates/bridge/src/plugin_state.rs"],
            names: &[crate::plugin_state::STATE_FILE_NAME],
            at_a_planted_name: AtAPlantedName::Replaces,
            runs_here: true,
            run: |dir, owner| {
                let state = crate::plugin_state::PluginState {
                    version: crate::plugin_state::SCHEMA_VERSION,
                    plugins: Vec::new(),
                };
                crate::plugin_state::save(dir, &state, owner)
            },
        },
        Writer {
            name: "the plugin state, cleared",
            sources: &[],
            names: &[crate::plugin_state::STATE_FILE_NAME],
            at_a_planted_name: AtAPlantedName::Replaces,
            runs_here: true,
            run: |dir, _| crate::plugin_state::clear(dir),
        },
        Writer {
            name: "the dns state, cleared",
            sources: &[],
            names: &[crate::dns_state::STATE_FILE_NAME],
            at_a_planted_name: AtAPlantedName::Replaces,
            runs_here: true,
            run: |dir, _| crate::dns_state::clear(dir),
        },
        Writer {
            name: "the dns state, superseded",
            sources: &["crates/bridge/src/dns_state.rs"],
            // The name it moves aside; where it moves it to (a free name, never a taken one) is not a name it acts on.
            names: &[crate::dns_state::STATE_FILE_NAME],
            at_a_planted_name: AtAPlantedName::Replaces,
            runs_here: true,
            run: |dir, _| crate::dns_state::supersede(dir),
        },
        Writer {
            name: "the lockdown state, saved",
            sources: &["crates/tun-engine/src/routing/failclosed/lockdown_state.rs"],
            names: &[lockdown_state::STATE_FILE_NAME],
            at_a_planted_name: AtAPlantedName::Replaces,
            runs_here: true,
            run: |dir, owner| lockdown_state::set_enabled(dir, true, owner),
        },
        Writer {
            name: "the lockdown state, cleared",
            sources: &[],
            names: &[lockdown_state::STATE_FILE_NAME],
            at_a_planted_name: AtAPlantedName::Replaces,
            runs_here: true,
            run: |dir, _| lockdown_state::clear(dir),
        },
        Writer {
            name: "the boot-time witness, recorded",
            sources: &["crates/tun-engine/src/routing/failclosed/boottime_witness.rs"],
            names: &[boottime_witness::STATE_FILE_NAME],
            at_a_planted_name: AtAPlantedName::Replaces,
            runs_here: true,
            run: |dir, _| {
                boottime_witness::record_armed_for_test(dir);
                Ok(())
            },
        },
        Writer {
            name: "the socket, bound",
            sources: &["crates/bridge/src/socket.rs"],
            names: &[SOCKET_NAME],
            at_a_planted_name: AtAPlantedName::Replaces,
            runs_here: true,
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
            at_a_planted_name: AtAPlantedName::WritesElsewhere,
            runs_here: true,
            // The marker is the crash handler's, left root-owned on purpose: it takes no owner.
            run: |dir, _| tombstone::crash::write_marker_for("bridge", CRASH_PID, dir),
        },
        Writer {
            name: "the crash marker, swept",
            sources: &[],
            names: &[CRASH_MARKER_NAME],
            at_a_planted_name: AtAPlantedName::Replaces,
            runs_here: true,
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
            at_a_planted_name: AtAPlantedName::KeepsAFileItsOwnerOwns,
            runs_here: true,
            run: |dir, owner| {
                let handle = Dir::open(dir, true, owner)?;
                // More than the limit, so that the file is rotated and opened again.
                DirRotate::new(handle, OsStr::new(LOG_NAME), 16, owner).write_all(&[b'x'; 40])
            },
        },
    ];
    rows.extend(macos_writers());
    rows.extend(windows_writers());
    rows
}

/// The rows this platform runs.
fn writers_here() -> Vec<Writer> {
    writers().into_iter().filter(|writer| writer.runs_here).collect()
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

#[cfg(unix)]
const PLANTS: &[Plant] = &[Plant::HardLink, Plant::Symlink, Plant::Fifo];
#[cfg(windows)]
const PLANTS: &[Plant] = &[Plant::HardLink, Plant::Symlink];

/// Whether `at` is, or leads to, what [`plant`] made from `victim`.
fn leads_to_the_victim(at: &Path, victim: &Path) -> bool {
    let meta = match std::fs::symlink_metadata(at) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return false,
        Err(err) => panic!("{at:?}: {err}"),
    };
    #[cfg(unix)]
    if std::os::unix::fs::FileTypeExt::is_fifo(&meta.file_type()) {
        return true;
    }
    if meta.file_type().is_symlink() {
        return true;
    }
    if !meta.is_file() {
        return false;
    }
    // What cannot be opened (a socket's file on Windows) is not the victim's file, which can.
    let Ok(file) = std::fs::File::open(at) else {
        return false;
    };
    let id = |file: &std::fs::File| util::dir::FileId::of(file).unwrap();
    id(&file) == id(&std::fs::File::open(victim).unwrap())
}

// What a planted name does to a writer --------------------------------------------------------------------------------

#[skuld::test]
fn no_writer_changes_the_file_a_planted_name_leads_to() {
    for writer in writers_here() {
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

                let result = (writer.run)(&dir, owner());

                assert_eq!(
                    Victim::of(&victim),
                    before,
                    "{}: a {kind:?} planted at {name} changed the file it leads to",
                    writer.name
                );
                let after = Afterwards {
                    name_leads_to_the_victim: leads_to_the_victim(&dir.join(name), &victim),
                    holds_another_name: std::fs::read_dir(&dir)
                        .unwrap()
                        .any(|entry| entry.unwrap().file_name() != name),
                    // The runner made the victim; the owner is the runner's unless the runner is the system.
                    victim_is_the_owners: !util::dir::testing::runner_is_the_system(),
                };
                let verdict = writer.at_a_planted_name.accepts(&result, &after);
                if let Err(why) = verdict {
                    panic!("{}: at a {kind:?} planted at {name} it {why}", writer.name);
                }
            }
        }
    }
}

// What a made folder does to the next run -----------------------------------------------------------------------------

fn run_twice(writer: &Writer, dir: &Path, layout: &str) {
    for run in ["first", "second"] {
        let result = (writer.run)(dir, owner());
        // A claim that is lost is the right second answer of a single-occupancy write.
        let result = match (writer.at_a_planted_name, result) {
            (AtAPlantedName::ClaimedElsewhere, Err(err)) if err.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            (_, result) => result,
        };
        result.unwrap_or_else(|err| panic!("{}: the {run} run {layout}: {err}", writer.name));
    }
}

#[skuld::test]
fn every_writer_runs_twice_in_a_layout_with_no_link() {
    for writer in writers_here() {
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
    for writer in writers_here() {
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

/// What opens a file by a path, under any spelling (see [`scan::Use::is`]): the reads the privileged state code must
/// make through `util::dir` instead.
const READS_BY_PATH: &[&str] = &[
    "fs::read",
    "fs::read_to_string",
    "File::open",
    "File::options",
    "OpenOptions::new",
];

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

/// The by-path reads in the code of `text`, each as it was written.
fn by_path_reads(text: &str) -> Vec<String> {
    scan::uses(text)
        .iter()
        .filter(|call| READS_BY_PATH.iter().any(|read| call.is(read)))
        .map(scan::Use::written)
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
    assert_eq!(by_path_reads("let bytes = std::fs::read(&path)?;"), ["std::fs::read"]);
    assert_eq!(
        by_path_reads("let f = std::fs::File::open(p)?;"),
        ["std::fs::File::open"]
    );
    assert!(by_path_reads("    // `std::fs::read(path)` is what this replaces").is_empty());
    assert!(by_path_reads("util::dir::read_state_file(dir, name)").is_empty());
}

#[skuld::test]
fn the_by_path_scan_sees_every_spelling_of_a_read() {
    let sites = |text: &str| by_path_reads(text).len();

    assert_eq!(
        sites(
            "use std::fs::read_to_string;
let text = read_to_string(path)?;"
        ),
        1
    );
    assert_eq!(
        sites(
            "use std::fs::{self, read};
let bytes = read(path)?;"
        ),
        1
    );
    assert_eq!(
        sites(
            "use std::fs::File as F;
let file = F::open(path)?;"
        ),
        1
    );
    assert_eq!(
        sites(
            "use std::fs::{
    File,
    OpenOptions,
};
let o = OpenOptions::new();"
        ),
        1
    );
    assert_eq!(
        sites(
            "use tokio::fs as tfs;
let bytes = tfs::read(path).await?;"
        ),
        1
    );
    assert_eq!(
        sites(
            "use std::fs::*;
let text = read_to_string(path)?;"
        ),
        1
    );
    assert_eq!(sites("let o = std::fs::File::options();"), 1);
    assert_eq!(sites("let bytes = ::std::fs::read(path)?;"), 1);
    assert_eq!(sites("let bytes = std::fs::read::<&Path>(path)?;"), 1);
    // A function named as a value, never called where it is named.
    assert_eq!(sites("let all = paths.iter().map(std::fs::read_to_string).count();"), 1);
    assert_eq!(
        sites(
            "use std::fs;
let f = fs::read;"
        ),
        1
    );
    assert_eq!(
        sites(
            "use std::fs;
let all = paths.iter().map(fs::read);"
        ),
        1
    );
    assert_eq!(sites("let f = std::fs::File::open;"), 1);
    assert_eq!(sites("let r = (std::fs::read)(path);"), 1);
    assert_eq!(
        sites(
            "use std::fs::read;
let all = paths.iter().map(read);"
        ),
        1
    );
    // A `type` alias of the type, resolved like a `use`.
    assert_eq!(
        sites(
            "type F = std::fs::File;
let file = F::open(path)?;"
        ),
        1
    );
    assert_eq!(
        sites(
            "use std::fs;
pub type F = fs::File;
type G = F;
let file = G::open(path)?;"
        ),
        1
    );
    assert_eq!(
        sites(
            "type Opts = std::fs::OpenOptions;
let o = Opts::new();"
        ),
        1
    );
    // Not reads: a `use` is not a use, nor is a field or a parameter that has the name, a macro, or a definition.
    assert_eq!(sites("use std::fs::read;"), 0);
    assert_eq!(sites("pub use std::fs::{read, read_to_string as slurp};"), 0);
    assert_eq!(
        sites(
            "use std::fs::read;
let s = Settings { read: true };"
        ),
        0
    );
    assert_eq!(
        sites(
            "use std::fs::read;
fn run(read: bool) {}"
        ),
        0
    );
    assert_eq!(
        sites(
            "use std::fs::*;
fn read(path: &Path) {}
struct File;"
        ),
        0
    );
    // Not reads: a method of the same name, a function of the file's own, a listing, a name in a string or a comment.
    assert_eq!(
        sites(
            "use std::io::Read;
file.read(&mut buffer)?;"
        ),
        0
    );
    assert_eq!(sites("reader.read_to_string(&mut text)?;"), 0);
    assert_eq!(
        sites(
            "fn read(path: &Path) {}
read(path);"
        ),
        0
    );
    assert_eq!(
        sites(
            "use std::fs::read_dir;
let entries = read_dir(path)?;"
        ),
        0
    );
    assert_eq!(sites("let message = \"call std::fs::read(path)\";"), 0);
    assert_eq!(sites("let a = 1; /* std::fs::read(path) */"), 0);
    assert_eq!(sites("let a = 1; // std::fs::read(path)"), 0);
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
        hits.extend(
            scan::logged_paths(&text)
                .into_iter()
                .map(|hit| format!("{module}:{hit}")),
        );
    }

    assert!(
        hits.is_empty(),
        "a state module formats a path (log the file's name): {hits:#?}"
    );
}

#[skuld::test]
fn the_path_logging_scan_sees_every_spelling_of_a_logged_path() {
    let sites = |text: &str| scan::logged_paths(text).len();
    let with_dir = |statement: &str| {
        format!(
            "fn save(state_dir: &Path) {{
    {statement}
}}"
        )
    };

    assert_eq!(
        sites(&with_dir("tracing::warn!(\"cannot write {}\", state_dir.display());")),
        1
    );
    assert_eq!(sites(&with_dir("let text = state_dir.to_string_lossy();")), 1);
    // The same calls spelled as functions, and as values.
    assert_eq!(sites("let shown = Path::display(dir);"), 1);
    assert_eq!(
        sites("let shown: Vec<_> = dirs.iter().map(Path::display).collect();"),
        1
    );
    assert_eq!(
        sites("let shown: Vec<_> = names.iter().map(OsStr::to_string_lossy).collect();"),
        1
    );
    assert_eq!(sites(&with_dir("tracing::warn!(\"cannot write {state_dir:?}\");")), 1);
    assert_eq!(sites(&with_dir("tracing::warn!(\"cannot write {:?}\", state_dir);")), 1);
    assert_eq!(
        sites(&with_dir("tracing::warn!(dir = ?state_dir, \"cannot write\");")),
        1
    );
    assert_eq!(
        sites(&with_dir(
            "tracing::warn!(dir = %state_dir.display(), \"cannot write\");"
        )),
        1
    );
    assert_eq!(
        sites(&with_dir(
            "tracing::warn!(
        error = %e,
        ?state_dir,
        \"cannot write\",
    );"
        )),
        1
    );
    assert_eq!(
        sites(
            "fn save(dir: PathBuf) {
    let e = io::Error::other(format!(\"{dir:?}\"));
}"
        ),
        1
    );
    assert_eq!(
        sites(
            "struct S { dir: PathBuf }
fn f(s: &S) { tracing::warn!(\"{:?}\", s.dir); }"
        ),
        1
    );
    assert_eq!(
        sites(
            "fn f(p: &Path) {
    let target = p.join(NAME);
    tracing::warn!(?target);
}"
        ),
        1
    );
    // Not a path: the file's name, an error, a field that only shares a word with a path binding.
    assert_eq!(
        sites(&with_dir(
            "tracing::warn!(error = %e, file = STATE_FILE_NAME, \"cannot write\");"
        )),
        0
    );
    assert_eq!(
        sites(&with_dir("tracing::warn!(\"cannot write {STATE_FILE_NAME}: {e}\");")),
        0
    );
    assert_eq!(sites(&with_dir("let dir = Dir::open(state_dir, true, owner)?;")), 0);
    assert_eq!(
        sites(&with_dir("// tracing::warn!(\"cannot write {state_dir:?}\");")),
        0
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

/// What a privileged writer calls to change a state directory (see [`scan::Use::is`]): open one, or hand it a file to
/// write or remove through `util::dir`, or write a versioned file, which stages through one.
const WRITES_A_DIR: &[&str] = &[
    "Dir::open*",
    "write_state_file",
    "remove_state_file",
    "make_dir_and_free_name",
    "VersionedFile::new",
    ".append_own_file",
    ".write_atomic",
    ".rename_noreplace",
];

/// Whether the production source `text` changes a state directory: it calls one of [`WRITES_A_DIR`].
fn opens_a_dir(text: &str) -> bool {
    scan::uses(text)
        .iter()
        .any(|call| WRITES_A_DIR.iter().any(|writes| call.is(writes)))
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
fn the_completeness_scan_sees_every_way_to_write_into_a_state_directory() {
    assert!(opens_a_dir("util::dir::write_state_file(dir, name, bytes, owner)"));
    assert!(opens_a_dir(
        "use util::dir::write_state_file;
write_state_file(dir, name, bytes, owner)?;"
    ));
    assert!(opens_a_dir("util::dir::remove_state_file(dir, name)"));
    assert!(opens_a_dir("util::dir::make_dir_and_free_name(dir, name)"));
    assert!(opens_a_dir("VersionedFile::<State>::new(dir)"));
    assert!(opens_a_dir(
        "let dir = util::dir::Dir::open_as(path, true, owner, caller)?;"
    ));
    assert!(opens_a_dir("dir.write_atomic(name, bytes, owner, |_| Ok(()))"));
    // A function named as a value, or a type reached through an alias.
    assert!(opens_a_dir("names.iter().for_each(util::dir::remove_state_file);"));
    assert!(opens_a_dir("let w = util::dir::write_state_file;"));
    assert!(opens_a_dir(
        "type D = util::dir::Dir;
let dir = D::open(path, true, None)?;"
    ));
    // Reading a state file writes nothing.
    assert!(!opens_a_dir("util::dir::read_state_file(dir, name)"));
}

#[skuld::test]
fn the_scan_tells_code_from_a_comment() {
    assert!(opens_a_dir("let dir = Dir::open(path, true, None)?;"));
    assert!(opens_a_dir("dir.append_own_file(&name, 0o644, owner)"));
    assert!(!opens_a_dir("    // goes through `Dir::open` first"));
    assert!(!opens_a_dir("/// see [`Dir::open_as`]"));
}

// No privileged step acts on a file by name ---------------------------------------------------------------------------
//
// `chown(path)` and `chmod(path)` resolve the name again, so a name the user swaps (a hard link to a file of
// root's, a directory of their own) is what changes. `remove_file(path)`, `rename(path, ..)`, `create_dir_all(path)`
// and `File::create(path)` resolve every component of the path again, so a link the user plants on the way takes the
// unlink, the rename or the new name to a folder of root's. A privileged step in a folder a user may add names to
// changes a file, and makes, removes or renames a name, through the handle it holds on the folder.

/// What names its target: the by-path calls of unix and Windows that change an owner, a mode or an ACL, and the ones
/// that make, remove, rename or link a name.
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
    "SetNamedSecurityInfo*",
    "SetFileSecurity*",
    "SetFileAttributes*",
    "fs::remove_file",
    "fs::remove_dir",
    "fs::remove_dir_all",
    "fs::rename",
    "fs::create_dir",
    "fs::create_dir_all",
    "fs::write",
    "fs::copy",
    "fs::hard_link",
    "fs::soft_link",
    "fs::symlink",
    "fs::symlink_file",
    "fs::symlink_dir",
    "File::create",
    "File::create_new",
    "libc::unlink",
    "libc::rmdir",
    "libc::rename",
    "libc::mkdir",
    "libc::link",
    "libc::symlink",
    "DeleteFile*",
    "MoveFile*",
    "CreateDirectory*",
    "RemoveDirectory*",
    "CreateHardLink*",
    "CreateSymbolicLink*",
];

/// The by-name calls in the code of `text`, each as it was written. A call on a handle (`file.set_permissions(..)`)
/// is not one.
fn by_name_calls(text: &str) -> Vec<String> {
    scan::uses(text)
        .iter()
        .filter(|call| BY_NAME.iter().any(|name| call.is(name)))
        .map(scan::Use::written)
        .collect()
}

/// By-name acts on a file that stay, each with its count and why: the file, the call as written, how many, and the
/// reason. A site not in it is new, and the guard reports it. "Open owner question" is a site whose folder is one a
/// user may add names to and which waits for a decision of the owner (1134-troyka2.md). The others name whose folder
/// it is: one no user can add names to (the Windows `%ProgramFiles%` folders grant `BUILTIN\Users` read and execute
/// only; macOS's `/Library`, `/var/log` and `/var/db` are root's), the acting user's own, or a test's.
const BY_NAME_ALLOWED: &[(&str, &str, usize, &str)] = &[
    (
        "crates/bridge/src/cutover/extract.rs",
        "std::fs::set_permissions",
        1,
        "open owner question: the folder that stages an update payload is the state dir, which only the service owns",
    ),
    (
        "crates/bridge/src/ipc.rs",
        "SetNamedSecurityInfoW",
        1,
        "open owner question: socket folder (the Windows DACL of the socket file, by path)",
    ),
    (
        "crates/bridge/src/ipc.rs",
        "libc::chmod",
        3,
        "open owner question: socket folder (the mode of the socket file, by path)",
    ),
    (
        "crates/bridge/src/ipc.rs",
        "libc::chown",
        1,
        "open owner question: socket folder (the owner of the socket file, by path)",
    ),
    (
        "crates/bridge/src/socket.rs",
        "libc::chmod",
        1,
        "open owner question: socket folder (the mode of the socket file, by path)",
    ),
    (
        "crates/bridge/src/platform/macos.rs",
        "std::fs::set_permissions",
        1,
        "the install runs once as root, on a file in /Library/PrivilegedHelperTools, which only root can add names to",
    ),
    (
        "crates/common/src/config.rs",
        "std::fs::set_permissions",
        1,
        "the GUI's own user config folder, changed as the user",
    ),
    (
        "crates/hole/src/setup.rs",
        "std::os::unix::fs::lchown",
        1,
        "open owner question: the macOS repair of a user's data folder walks it as root and changes each entry by path",
    ),
    (
        "crates/util/src/ownership.rs",
        "libc::lchown",
        1,
        "no caller in production code: only tests/elevated_ownership_privileged.rs and its own tests call it",
    ),
    (
        "crates/bridge/src/cutover/extract.rs",
        "std::fs::copy",
        2,
        "open owner question: the macOS update cutover stages and extracts by path in the state dir; on Windows, the Windows install folder under %ProgramFiles%, which users cannot add names to",
    ),
    (
        "crates/bridge/src/cutover/extract.rs",
        "std::fs::create_dir_all",
        3,
        "open owner question: the macOS update cutover stages and extracts by path in the state dir; on Windows, the Windows install folder under %ProgramFiles%, which users cannot add names to",
    ),
    (
        "crates/bridge/src/cutover/extract.rs",
        "std::fs::remove_dir_all",
        3,
        "open owner question: the macOS update cutover stages and extracts by path in the state dir; on Windows, the Windows install folder under %ProgramFiles%, which users cannot add names to",
    ),
    (
        "crates/bridge/src/cutover/os/windows.rs",
        "std::fs::remove_file",
        1,
        "the Windows install folder under %ProgramFiles%, which users cannot add names to (the swap of the installed binaries)",
    ),
    (
        "crates/bridge/src/cutover/os/windows.rs",
        "std::fs::rename",
        5,
        "the Windows install folder under %ProgramFiles%, which users cannot add names to (the swap of the installed binaries)",
    ),
    (
        "crates/bridge/src/ipc.rs",
        "std::fs::remove_dir_all",
        7,
        "open owner question: the macOS update cutover stages and extracts by path in the state dir (the private payload dir); on Windows, the Windows install folder under %ProgramFiles%, which users cannot add names to",
    ),
    (
        "crates/bridge/src/platform/macos.rs",
        "std::fs::copy",
        1,
        "the install and uninstall run as root, in /Library/PrivilegedHelperTools, /Library/LaunchDaemons, /var/log/hole and /var/db/hole/state, which only root can add names to",
    ),
    (
        "crates/bridge/src/platform/macos.rs",
        "std::fs::create_dir_all",
        3,
        "the install and uninstall run as root, in /Library/PrivilegedHelperTools, /Library/LaunchDaemons, /var/log/hole and /var/db/hole/state, which only root can add names to",
    ),
    (
        "crates/bridge/src/platform/macos.rs",
        "std::fs::remove_file",
        2,
        "the install and uninstall run as root, in /Library/PrivilegedHelperTools, /Library/LaunchDaemons, /var/log/hole and /var/db/hole/state, which only root can add names to",
    ),
    (
        "crates/bridge/src/platform/macos.rs",
        "std::fs::rename",
        1,
        "the install and uninstall run as root, in /Library/PrivilegedHelperTools, /Library/LaunchDaemons, /var/log/hole and /var/db/hole/state, which only root can add names to",
    ),
    (
        "crates/bridge/src/platform/macos.rs",
        "std::fs::write",
        1,
        "the install and uninstall run as root, in /Library/PrivilegedHelperTools, /Library/LaunchDaemons, /var/log/hole and /var/db/hole/state, which only root can add names to",
    ),
    (
        "crates/bridge/src/platform/swap.rs",
        "std::fs::remove_dir_all",
        1,
        "open owner question: the macOS update cutover stages and extracts by path in the state dir (the swap moves the staged images out of it and removes what is left)",
    ),
    (
        "crates/bridge/src/platform/swap.rs",
        "std::fs::rename",
        1,
        "open owner question: the macOS update cutover stages and extracts by path in the state dir (the swap moves the staged images out of it and removes what is left)",
    ),
    (
        "crates/bridge/src/platform/windows.rs",
        "std::fs::create_dir_all",
        2,
        "open owner question: install() makes the log and state folders under %ProgramData%\\hole, which users can add names to (the DACL follow-up)",
    ),
    (
        "crates/bridge/src/platform/windows.rs",
        "std::fs::remove_file",
        1,
        "the Windows install folder under %ProgramFiles%, which users cannot add names to (the sweep of hole.exe.old-* beside the running binary)",
    ),
    (
        "crates/bridge/src/test_support/dist_harness.rs",
        "std::fs::remove_file",
        1,
        "test support: removes the socket of a process the test started",
    ),
    (
        "crates/common/src/config.rs",
        "std::fs::create_dir_all",
        1,
        "the GUI's own user config folder, made as the user",
    ),
    (
        "crates/common/src/config_store.rs",
        "fs::remove_file",
        2,
        "the GUI's own user config, written as the user",
    ),
    (
        "crates/common/src/config_store.rs",
        "fs::rename",
        1,
        "the GUI's own user config, written as the user",
    ),
    (
        "crates/common/src/logging/logging_test_helpers.rs",
        "std::fs::write",
        1,
        "test helpers",
    ),
    (
        "crates/hole/src/autostart_registration.rs",
        "std::fs::remove_file",
        1,
        "the user's own LaunchAgents folder, written by the GUI as the user",
    ),
    (
        "crates/hole/src/autostart_registration.rs",
        "std::fs::rename",
        1,
        "the user's own LaunchAgents folder, written by the GUI as the user",
    ),
    (
        "crates/hole/src/elevation.rs",
        "std::fs::remove_file",
        2,
        "open owner question: elevation.rs names the request and result files by path (the requester's private temp folder)",
    ),
    (
        "crates/hole/src/elevation.rs",
        "std::fs::write",
        1,
        "open owner question: elevation.rs names the request and result files by path (the requester's private temp folder)",
    ),
    (
        "crates/hole/src/log_collector.rs",
        "std::fs::File::create",
        1,
        "the GUI zips its own user's logs into a temp folder it made, as the user",
    ),
    (
        "crates/hole/src/orphan_sweep.rs",
        "std::fs::remove_dir_all",
        1,
        "the GUI sweeps its own user's temp folder at start, as the user",
    ),
    (
        "crates/hole/src/orphan_sweep.rs",
        "std::fs::remove_file",
        1,
        "the GUI sweeps its own user's temp folder at start, as the user",
    ),
    (
        "crates/hole/src/path_management.rs",
        "std::fs::remove_file",
        2,
        "run by the administrator who invokes `hole path add` or `remove`: one fixed name, /usr/local/bin/hole",
    ),
    (
        "crates/hole/src/path_management.rs",
        "symlink",
        1,
        "run by the administrator who invokes `hole path add` or `remove`: one fixed name, /usr/local/bin/hole",
    ),
    (
        "crates/hole/src/tray.rs",
        "std::fs::copy",
        1,
        "the GUI copies the log bundle where its user chose, as the user",
    ),
    (
        "crates/hole/src/tray.rs",
        "std::fs::remove_dir",
        1,
        "the GUI removes the temp folder it made, as the user",
    ),
    (
        "crates/hole/src/tray.rs",
        "std::fs::remove_file",
        1,
        "the GUI removes the temp file it made, as the user",
    ),
    (
        "crates/hole/src/update/download.rs",
        "std::fs::File::create",
        1,
        "the GUI and `hole update` download to a path their user chose, as the user",
    ),
    (
        "crates/hole/src/update/download.rs",
        "std::fs::rename",
        1,
        "the GUI and `hole update` download to a path their user chose, as the user",
    ),
    (
        "crates/tombstone/src/bin/crash_child.rs",
        "std::fs::rename",
        1,
        "a test binary: built only by the test workflow (feature crash-child) to plant links under a crash",
    ),
    (
        "crates/tombstone/src/bin/crash_child.rs",
        "std::os::unix::fs::symlink",
        2,
        "a test binary: built only by the test workflow (feature crash-child) to plant links under a crash",
    ),
    (
        "crates/tombstone/src/bin/crash_child.rs",
        "std::os::windows::fs::symlink_dir",
        1,
        "a test binary: built only by the test workflow (feature crash-child) to plant links under a crash",
    ),
    (
        "crates/tombstone/src/bin/crash_child.rs",
        "std::os::windows::fs::symlink_file",
        1,
        "a test binary: built only by the test workflow (feature crash-child) to plant links under a crash",
    ),
    (
        "crates/tun-engine/src/test_utils/escape.rs",
        "std::fs::remove_file",
        1,
        "test support",
    ),
    (
        "crates/tun-engine/src/test_utils/escape.rs",
        "std::fs::write",
        1,
        "test support",
    ),
    (
        "crates/util/src/versioned_file/fixtures.rs",
        "std::fs::create_dir_all",
        1,
        "fixtures of the unit tests (`#[cfg(test)]`)",
    ),
    (
        "crates/util/src/versioned_file/fixtures.rs",
        "std::fs::write",
        1,
        "fixtures of the unit tests (`#[cfg(test)]`)",
    ),
];

/// The by-name calls of the privileged crates, once per file and spelling, with how many there are. Not
/// `util::dir::testing`, which is compiled for tests and changes only the fixtures a test made.
fn by_name_sites(root: &Path) -> BTreeMap<(String, String), usize> {
    let mut sites = BTreeMap::new();
    for (relative, path) in privileged_sources(root) {
        if relative == "crates/util/src/dir/testing.rs" {
            continue;
        }
        for call in by_name_calls(&std::fs::read_to_string(&path).unwrap()) {
            *sites.entry((relative.clone(), call)).or_insert(0) += 1;
        }
    }
    sites
}

#[skuld::test]
fn no_privileged_code_acts_on_a_file_by_name() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let covered = privileged_sources(&root);
    for must_cover in [
        "crates/util/src/dir.rs",
        "crates/util/src/dir/unix.rs",
        "crates/bridge/src/ipc.rs",
    ] {
        assert!(
            covered.iter().any(|(relative, _)| relative == must_cover),
            "the scan must cover {must_cover}"
        );
    }

    let mut hits = Vec::new();
    for ((file, call), count) in by_name_sites(&root) {
        let allowed = BY_NAME_ALLOWED
            .iter()
            .find(|(allowed_file, allowed_call, ..)| *allowed_file == file && *allowed_call == call)
            .map_or(0, |(_, _, count, _)| *count);
        if count > allowed {
            hits.push(format!("{file}: {call} x{count} (allowed: {allowed})"));
        }
    }

    assert!(
        hits.is_empty(),
        "privileged code acts on a file by name, which resolves the whole path again: do it through a handle on the folder (`util::dir::Dir`: `unlink`, `rename`, `write_atomic`; `fchown`, `fchmod`, `SetSecurityInfo` for an owner, a mode or an ACL), or add the site to BY_NAME_ALLOWED with the reason: {hits:#?}"
    );
}

#[skuld::test]
fn every_by_name_allowance_still_applies() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let sites = by_name_sites(&root);
    for (file, call, count, reason) in BY_NAME_ALLOWED {
        assert_eq!(
            sites.get(&(file.to_string(), call.to_string())),
            Some(count),
            "{file} no longer calls `{call}` {count} time(s): update or remove its allowance ({reason})"
        );
    }
}

#[skuld::test]
fn the_by_name_scan_sees_every_spelling_of_a_call() {
    let sites = |text: &str| by_name_calls(text).len();

    assert_eq!(
        sites(
            "use std::os::unix::fs::chown;
chown(path, Some(0), None)?;"
        ),
        1
    );
    assert_eq!(
        sites(
            "use std::fs::{set_permissions, File};
set_permissions(path, perms)?;"
        ),
        1
    );
    assert_eq!(
        sites(
            "use std::os::unix::fs as ufs;
ufs::lchown(path, None, None)?;"
        ),
        1
    );
    assert_eq!(
        sites(
            "use windows::Win32::Security::Authorization::SetNamedSecurityInfoW;
SetNamedSecurityInfoW(p);"
        ),
        1
    );
    assert_eq!(
        sites(
            "use libc::*;
unsafe { chmod(path, 0o600) };"
        ),
        1
    );
    assert_eq!(sites("unsafe { libc::chmod(path.as_ptr(), 0o600) };"), 1);
    // Making, removing or renaming a name by path.
    assert_eq!(sites("std::fs::remove_file(path)?;"), 1);
    assert_eq!(
        sites(
            "use std::fs::{remove_dir_all, create_dir_all};
remove_dir_all(a)?;
create_dir_all(b)?;"
        ),
        2
    );
    assert_eq!(sites("let r = fs::rename(from, to);"), 1);
    assert_eq!(sites("let f = std::fs::File::create(path)?;"), 1);
    assert_eq!(sites("std::fs::write(path, bytes)?;"), 1);
    assert_eq!(sites("tokio::fs::remove_file(path).await?;"), 1);
    assert_eq!(sites("unsafe { libc::unlink(path.as_ptr()) };"), 1);
    assert_eq!(sites("paths.iter().for_each(|p| drop(std::fs::remove_file(p)));"), 1);
    assert_eq!(sites("paths.into_iter().map(std::fs::remove_file).count();"), 1);
    assert_eq!(
        sites(
            "use std::os::unix::fs::symlink;
symlink(target, link)?;"
        ),
        1
    );
    // A function named as a value, never called where it is named.
    assert_eq!(sites("let change = std::fs::set_permissions;"), 1);
    assert_eq!(sites("let all = paths.iter().map(|p| p).for_each(libc::chmod);"), 1);
    assert_eq!(
        sites(
            "use std::os::unix::fs as ufs;
let f = ufs::lchown;"
        ),
        1
    );
    assert_eq!(sites("let f = SetNamedSecurityInfoW;"), 1);
    // Not by name: the methods that act on a handle, and a function of the file's own.
    assert_eq!(sites("file.set_permissions(perms)?;"), 0);
    assert_eq!(sites("dir.unlink(name)?;"), 0);
    assert_eq!(sites("dir.rename(from, to)?;"), 0);
    assert_eq!(sites("self.fs.remove_file(&dir, name)"), 0);
    assert_eq!(sites("util::dir::remove_state_file(dir, name)?;"), 0);
    assert_eq!(sites("fs::read_dir(path)?;"), 0);
    assert_eq!(
        sites(
            "fn chown(fd: i32) {}
chown(fd);"
        ),
        0
    );
}

#[skuld::test]
fn the_by_name_scan_tells_a_name_from_a_handle() {
    assert_eq!(
        by_name_calls("libc::fchownat(dir, name, uid, gid, 0)"),
        ["libc::fchownat"]
    );
    assert_eq!(
        by_name_calls("std::fs::set_permissions(path, perms)"),
        ["std::fs::set_permissions"]
    );
    assert_eq!(
        by_name_calls("SetNamedSecurityInfoW(&path, ..)"),
        ["SetNamedSecurityInfoW"]
    );
    assert!(by_name_calls("libc::fchown(fd, uid, gid)").is_empty());
    assert!(by_name_calls("file.set_permissions(perms)").is_empty());
    assert!(by_name_calls("SetSecurityInfo(handle, ..)").is_empty());
    assert!(by_name_calls("    // fchownat is the by-name call").is_empty());
}
