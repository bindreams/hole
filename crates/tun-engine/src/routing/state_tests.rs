use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use std::path::{Path, PathBuf};

use util::versioned_file::CannotRead;

use super::*;

fn sample_ipv4() -> RouteState {
    let server_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
    RouteState {
        tun_name: "hole-tun".into(),
        server_ip,
        interface_name: "en0".into(),
        original_gateway: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
        route_form: RouteForm::Via,
        installed: planned_routes(server_ip),
        stale: Vec::new(),
    }
}

fn sample_ipv6() -> RouteState {
    let server_ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    RouteState {
        tun_name: "hole-tun".into(),
        server_ip,
        interface_name: "Wi-Fi".into(),
        original_gateway: None,
        route_form: RouteForm::Via,
        installed: vec![RouteId::SplitV6Low],
        stale: Vec::new(),
    }
}

/// A record carrying a stale group from an earlier, still-unswept session —
/// the schema-3 shape [`load_v1_migrates_to_the_full_planned_set`] and
/// friends never exercise.
fn sample_ipv4_with_stale() -> RouteState {
    let stale_server_ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
    RouteState {
        stale: vec![StaleRecord {
            tun_name: "hole-tun".into(),
            server_ip: stale_server_ip,
            interface_name: "en1".into(),
            original_gateway: Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 1))),
            route_form: RouteForm::Via,
            installed: vec![RouteId::ServerBypass],
        }],
        ..sample_ipv4()
    }
}

fn save(dir: &Path, state: &RouteState, owner: Option<(u32, u32)>) -> Result<(), StoreError> {
    write(&file(dir), state, owner)
}

fn clear(dir: &Path) -> std::io::Result<Cleared> {
    remove(&file(dir))
}

fn load_record(dir: &Path) -> Option<RouteState> {
    match read(&file(dir)) {
        Found::Records(record) => Some(record),
        Found::Nothing | Found::Unreadable { .. } => None,
    }
}

fn state_file(dir: &Path) -> PathBuf {
    dir.join(STATE_FILE_NAME)
}

fn write_raw(dir: &Path, bytes: &str) -> PathBuf {
    let path = state_file(dir);
    std::fs::write(&path, bytes).unwrap();
    path
}

#[skuld::test]
fn save_then_load_roundtrip_ipv4() {
    let dir = tempfile::tempdir().unwrap();
    let state = sample_ipv4();
    save(dir.path(), &state, None).unwrap();
    let loaded = load_record(dir.path()).unwrap();
    assert_eq!(loaded, state);
}

#[skuld::test]
fn save_then_load_roundtrip_ipv6() {
    let dir = tempfile::tempdir().unwrap();
    let state = sample_ipv6();
    save(dir.path(), &state, None).unwrap();
    let loaded = load_record(dir.path()).unwrap();
    assert_eq!(loaded, state);
}

#[skuld::test]
fn save_then_load_roundtrip_with_stale_groups() {
    let dir = tempfile::tempdir().unwrap();
    let state = sample_ipv4_with_stale();
    save(dir.path(), &state, None).unwrap();
    let loaded = load_record(dir.path()).unwrap();
    assert_eq!(loaded, state);
}

#[skuld::test]
fn load_missing_is_absent() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(load(dir.path()), Loaded::Absent));
    assert!(matches!(read(&file(dir.path())), Found::Nothing));
    assert_eq!(blocking(dir.path()), None);
}

/// Every cause that makes a record unreadable, with what `read` must report.
fn unreadable_cases() -> Vec<(&'static str, String, CannotRead)> {
    vec![
        ("not json", "not valid json { .".into(), CannotRead::Corrupt),
        ("empty", String::new(), CannotRead::Corrupt),
        (
            "wrong shape",
            r#"{"version": 4, "server_ip": "203.0.113.1"}"#.into(),
            CannotRead::Corrupt,
        ),
        (
            "version zero",
            r#"{"version": 0, "tun_name": "t"}"#.into(),
            CannotRead::Corrupt,
        ),
        ("version a string", r#"{"version": "4"}"#.into(), CannotRead::Corrupt),
        ("version fractional", r#"{"version": 4.5}"#.into(), CannotRead::Corrupt),
        (
            "no version",
            r#"{"tun_name": "hole-tun", "server_ip": "203.0.113.1", "interface_name": "en0"}"#.into(),
            CannotRead::Corrupt,
        ),
        (
            "newer",
            r#"{"version": 5, "tun_name": "hole-tun", "server_ip": "203.0.113.1"}"#.into(),
            CannotRead::Newer,
        ),
        ("far newer", r#"{"version": 99}"#.into(), CannotRead::Newer),
    ]
}

#[skuld::test]
fn an_unreadable_record_is_reported_with_its_path_and_cause() {
    for (what, bytes, expected) in unreadable_cases() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_raw(dir.path(), &bytes);
        match read(&file(dir.path())) {
            Found::Unreadable { path: found, cause } => {
                assert_eq!(found, path, "{what}");
                assert_eq!(cause, WhyUnreadable::CannotRead(expected), "{what}");
            }
            other => panic!("{what}: expected an unreadable record, got {other:?}"),
        }
    }
}

#[skuld::test]
fn only_an_unreadable_record_blocks_a_connect() {
    for (what, bytes, _) in unreadable_cases() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_raw(dir.path(), &bytes);
        assert_eq!(blocking(dir.path()), Some(path), "{what}");
    }

    let dir = tempfile::tempdir().unwrap();
    assert_eq!(blocking(dir.path()), None, "no record");
    save(dir.path(), &sample_ipv4(), None).unwrap();
    assert_eq!(blocking(dir.path()), None, "a current record");
    write_raw(
        dir.path(),
        r#"{"version": 1, "tun_name": "t", "server_ip": "1.1.1.1", "interface_name": "e"}"#,
    );
    assert_eq!(blocking(dir.path()), None, "an older record migrates");
}

/// A file system whose reads are all denied; links and publishes are real.
struct DeniedRead;

impl util::versioned_file::Fs for DeniedRead {
    fn read(&self, _dir: &util::dir::Dir, _name: &std::ffi::OsStr) -> std::io::Result<Vec<u8>> {
        Err(std::io::ErrorKind::PermissionDenied.into())
    }
}

/// A record that is readable bytes on disk, whose read fails.
fn file_whose_reads_fail(dir: &Path) -> RouteFile {
    RouteFile::with_fs(dir, std::sync::Arc::new(DeniedRead))
}

/// A failed read is treated like a newer or corrupt record.
#[skuld::test]
fn a_read_that_fails_is_an_unreadable_record_with_its_kind() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_raw(dir.path(), r#"{"version": 4}"#);
    match read(&file_whose_reads_fail(dir.path())) {
        Found::Unreadable { path: found, cause } => {
            assert_eq!(found, path);
            assert_eq!(cause, WhyUnreadable::ReadFailed(std::io::ErrorKind::PermissionDenied));
        }
        other => panic!("expected an unreadable record, got {other:?}"),
    }
}

/// The path where the record should be is a directory, so the real read fails.
#[skuld::test]
fn a_record_whose_read_fails_blocks_a_connect() {
    let dir = tempfile::tempdir().unwrap();
    let path = state_file(dir.path());
    std::fs::create_dir(&path).unwrap();
    assert!(matches!(
        read(&file(dir.path())),
        Found::Unreadable {
            cause: WhyUnreadable::ReadFailed(_),
            ..
        }
    ));
    assert_eq!(blocking(dir.path()), Some(path));
}

#[skuld::test]
fn save_over_a_record_whose_read_fails_is_refused_and_leaves_it() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = r#"{"version": 4, "tun_name": "t"}"#;
    let path = write_raw(dir.path(), bytes);

    let err = write(&file_whose_reads_fail(dir.path()), &sample_ipv4(), None).expect_err("must refuse");

    assert!(
        matches!(&err, StoreError::ReadFailed { path: p, kind } if *p == path && *kind == std::io::ErrorKind::PermissionDenied),
        "{err:?}"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), bytes);
    let leftovers: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert_eq!(leftovers.len(), 1, "no temp file or backup may appear");
}

#[skuld::test]
fn clear_over_a_record_whose_read_fails_keeps_it() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = r#"{"version": 4, "tun_name": "t"}"#;
    let path = write_raw(dir.path(), bytes);

    let cleared = remove(&file_whose_reads_fail(dir.path())).unwrap();

    assert_eq!(cleared, Cleared::Kept);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), bytes);
}

#[skuld::test]
fn save_over_an_unreadable_record_is_refused_and_leaves_it() {
    for (what, bytes, cause) in unreadable_cases() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_raw(dir.path(), &bytes);

        let err = save(dir.path(), &sample_ipv4(), None).expect_err(what);

        assert!(
            matches!(err, StoreError::Unreadable { cause: c, .. } if c == cause),
            "{what}: {err:?}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), bytes, "{what}");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(leftovers.len(), 1, "{what}: no temp file or backup may appear");
    }
}

#[skuld::test]
fn clear_over_an_unreadable_record_keeps_it() {
    for (what, bytes, _) in unreadable_cases() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_raw(dir.path(), &bytes);

        let cleared = clear(dir.path()).expect(what);

        assert_eq!(cleared, Cleared::Kept, "{what}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), bytes, "{what}");
    }
}

#[skuld::test]
fn clear_missing_leaves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(clear(dir.path()).unwrap(), Cleared::Gone);
}

#[skuld::test]
fn clear_existing_removes_file() {
    let dir = tempfile::tempdir().unwrap();
    save(dir.path(), &sample_ipv4(), None).unwrap();
    assert!(dir.path().join(STATE_FILE_NAME).exists());
    assert_eq!(clear(dir.path()).unwrap(), Cleared::Gone);
    assert!(!dir.path().join(STATE_FILE_NAME).exists());
}

#[skuld::test]
fn save_creates_missing_dir() {
    let parent = tempfile::tempdir().unwrap();
    let nested = parent.path().join("a").join("b").join("c");
    save(&nested, &sample_ipv4(), None).unwrap();
    assert!(nested.join(STATE_FILE_NAME).exists());
}

// Golden files ========================================================================================================
//
// Bytes a shipped release wrote, hand-written from its `save` (v0.6.0 wrote
// schema 4 with this exact layout), so a change to the type cannot also move
// what it is checked against.

const V4_ON_DISK: &str = r#"{
  "version": 4,
  "tun_name": "hole-tun",
  "server_ip": "203.0.113.42",
  "interface_name": "en0",
  "original_gateway": "203.0.113.1",
  "route_form": "via",
  "installed": [
    "split-v4-low",
    "split-v4-high",
    "split-v6-low",
    "split-v6-high",
    "server-bypass"
  ],
  "stale": [
    {
      "tun_name": "hole-tun",
      "server_ip": "9.9.9.9",
      "interface_name": "en1",
      "original_gateway": "9.9.9.1",
      "route_form": "via",
      "installed": [
        "server-bypass"
      ]
    }
  ]
}"#;

#[skuld::test]
fn a_v4_file_written_by_v0_6_0_loads_as_it_was_written() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(state_file(dir.path()), V4_ON_DISK).unwrap();
    assert_eq!(load_record(dir.path()), Some(sample_ipv4_with_stale()));
}

#[skuld::test]
fn save_writes_the_bytes_v0_6_0_wrote() {
    let dir = tempfile::tempdir().unwrap();
    save(dir.path(), &sample_ipv4_with_stale(), None).unwrap();
    assert_eq!(std::fs::read_to_string(state_file(dir.path())).unwrap(), V4_ON_DISK);
}

// Unknown fields ======================================================================================================
//
// A record is the only evidence of what a run left in the routing table, so a
// field this release does not know must not make it unreadable: it is
// ignored, at every depth and in every version.

#[skuld::test]
fn route_record_with_an_unknown_field_still_loads() {
    let dir = tempfile::tempdir().unwrap();
    let mut json: serde_json::Value = serde_json::from_str(V4_ON_DISK).unwrap();
    json["from_the_future"] = serde_json::json!({"anything": [1, 2]});
    json["stale"][0]["also_from_the_future"] = serde_json::json!("x");
    std::fs::write(state_file(dir.path()), json.to_string()).unwrap();

    assert_eq!(
        load_record(dir.path()),
        Some(sample_ipv4_with_stale()),
        "an extra key at the top and inside a stale group must not discard the record"
    );
}

#[skuld::test]
fn older_route_records_ignore_unknown_fields_at_every_level() {
    let server_ip: IpAddr = "203.0.113.1".parse().unwrap();
    let expected = |installed: Vec<RouteId>, original_gateway: Option<IpAddr>, stale: Vec<StaleRecord>| RouteState {
        tun_name: "hole-tun".into(),
        server_ip,
        interface_name: "en0".into(),
        original_gateway,
        route_form: RouteForm::Via,
        installed,
        stale,
    };
    let stale_group = StaleRecord {
        tun_name: "hole-tun".into(),
        server_ip: "9.9.9.9".parse().unwrap(),
        interface_name: "en1".into(),
        original_gateway: Some("9.9.9.1".parse().unwrap()),
        route_form: RouteForm::Via,
        installed: vec![RouteId::ServerBypass],
    };
    let cases = [
        (
            serde_json::json!({
                "version": 1, "tun_name": "hole-tun", "server_ip": "203.0.113.1", "interface_name": "en0",
                "extra": true,
            }),
            expected(planned_routes(server_ip), None, Vec::new()),
        ),
        (
            serde_json::json!({
                "version": 2, "tun_name": "hole-tun", "server_ip": "203.0.113.1", "interface_name": "en0",
                "installed": ["split-v4-low"], "extra": true,
            }),
            expected(vec![RouteId::SplitV4Low], None, Vec::new()),
        ),
        (
            serde_json::json!({
                "version": 3, "tun_name": "hole-tun", "server_ip": "203.0.113.1", "interface_name": "en0",
                "original_gateway": "203.0.113.254", "installed": ["split-v4-low"], "extra": true,
                "stale": [{
                    "tun_name": "hole-tun", "server_ip": "9.9.9.9", "interface_name": "en1",
                    "original_gateway": "9.9.9.1", "installed": ["server-bypass"], "extra": true,
                }],
            }),
            expected(
                vec![RouteId::SplitV4Low],
                Some("203.0.113.254".parse().unwrap()),
                vec![stale_group],
            ),
        ),
    ];
    for (json, expected) in cases {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(state_file(dir.path()), json.to_string()).unwrap();
        assert_eq!(load_record(dir.path()), Some(expected), "{json}");
    }
}

// Schema migration ====================================================================================================
//
// A schema bump must not silently turn recovery into a no-op: the state file
// is the only record of what a crashed run leaked, so a rejected file leaves
// the host on split routes pointing at a TUN that no longer exists.

#[skuld::test]
fn load_v1_migrates_to_the_full_planned_set() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": 1,
        "tun_name": "hole-tun",
        "server_ip": "203.0.113.1",
        "interface_name": "en0",
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();

    let loaded = load_record(dir.path()).expect("a v1 file must still drive recovery, not be discarded");
    assert_eq!(loaded.tun_name, "hole-tun");
    assert_eq!(loaded.interface_name, "en0");
    assert_eq!(
        loaded.installed,
        planned_routes(loaded.server_ip),
        "v1 had no provenance and deleted every planned route; the migration must delete the same set"
    );
    assert_eq!(loaded.original_gateway, None, "v1 never persisted a gateway");
    assert_eq!(loaded.stale, Vec::new(), "v1 had no stale-group concept");
}

#[skuld::test]
fn load_v2_migrates_preserving_installed_and_leaving_gateway_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": 2,
        "tun_name": "hole-tun",
        "server_ip": "203.0.113.1",
        "interface_name": "en0",
        "installed": ["split-v4-low", "server-bypass"],
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();

    let loaded = load_record(dir.path()).expect("a v2 file must still drive recovery, not be discarded");
    assert_eq!(loaded.tun_name, "hole-tun");
    assert_eq!(loaded.interface_name, "en0");
    assert_eq!(
        loaded.installed,
        vec![RouteId::SplitV4Low, RouteId::ServerBypass],
        "v2 DID have provenance — unlike v1, the migration must preserve it exactly, not widen to the full planned set"
    );
    assert_eq!(
        loaded.original_gateway, None,
        "v2 never persisted a gateway — the migrated record falls back to an unscoped delete"
    );
    assert_eq!(loaded.stale, Vec::new(), "v2 had no stale-group concept");
}

/// A record without a `route_form` field predates on-link support entirely,
/// so every route it names was installed through a real gateway — teardown
/// must pick the gateway delete form, never default to (or panic on) the
/// interface-scoped form it never used.
#[skuld::test]
fn a_record_without_a_form_field_migrates_to_via() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": 3,
        "tun_name": "hole-tun",
        "server_ip": "203.0.113.1",
        "interface_name": "en0",
        "original_gateway": "203.0.113.254",
        "installed": ["server-bypass"],
        "stale": [],
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();

    let loaded = load_record(dir.path()).expect("a v3 file must still drive recovery, not be discarded");
    assert_eq!(
        loaded.route_form,
        RouteForm::Via,
        "a v3 record never had an on-link bypass"
    );
    assert_eq!(loaded.original_gateway, Some("203.0.113.254".parse().unwrap()));
}

/// The same migration, exercised on a carried-forward `stale` group nested
/// inside the v3 record — `StaleRecordV3` must migrate too, not just the
/// top-level fields.
#[skuld::test]
fn a_stale_group_without_a_form_field_migrates_to_via() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": 3,
        "tun_name": "hole-tun",
        "server_ip": "203.0.113.1",
        "interface_name": "en0",
        "original_gateway": null,
        "installed": [],
        "stale": [{
            "tun_name": "hole-tun",
            "server_ip": "9.9.9.9",
            "interface_name": "en1",
            "original_gateway": "9.9.9.1",
            "installed": ["server-bypass"],
        }],
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();

    let loaded = load_record(dir.path()).expect("a v3 file must still drive recovery, not be discarded");
    assert_eq!(loaded.stale.len(), 1);
    assert_eq!(loaded.stale[0].route_form, RouteForm::Via);
}

#[skuld::test]
fn load_v1_loopback_migrates_without_the_bypass() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": 1,
        "tun_name": "hole-tun",
        "server_ip": "127.0.0.1",
        "interface_name": "en0",
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();

    let loaded = load_record(dir.path()).unwrap();
    assert!(
        !loaded.installed.contains(&RouteId::ServerBypass),
        "a loopback server never installs a bypass, got {:?}",
        loaded.installed
    );
}

// Canonical form ======================================================================================================
//
// `coalesce` is the shared primitive every group-consuming path (sweep,
// crash recovery) must route through: groups sharing an identity — the
// tuple that determines the teardown argv they'd each emit — merge into one,
// each survivor is sanitized against `planned_routes(server_ip)`, and an
// empty survivor is dropped. See CONTRIBUTING's Route ownership section.

fn group(server_ip: IpAddr, installed: Vec<RouteId>) -> StaleRecord {
    StaleRecord {
        tun_name: "hole-tun".into(),
        server_ip,
        interface_name: "en0".into(),
        original_gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        route_form: RouteForm::Via,
        installed,
    }
}

#[skuld::test]
fn coalesce_merges_two_groups_with_identical_identity() {
    let server_ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
    let a = group(server_ip, vec![RouteId::SplitV4Low]);
    let b = group(server_ip, vec![RouteId::SplitV4High]);

    let merged = coalesce(vec![a, b]);

    assert_eq!(merged.len(), 1, "identical-identity groups must become one: {merged:?}");
    assert_eq!(merged[0].installed, vec![RouteId::SplitV4Low, RouteId::SplitV4High]);
}

#[skuld::test]
fn coalesce_merges_more_than_two_duplicate_entries() {
    // Simulates N consecutive failed install attempts to the same server,
    // each leaving its own unconfirmed leftover — they must fold into one
    // retried entry, not accumulate one per attempt.
    let server_ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
    let groups = vec![
        group(server_ip, vec![RouteId::ServerBypass]),
        group(server_ip, vec![RouteId::ServerBypass]),
        group(server_ip, vec![RouteId::ServerBypass]),
    ];

    let merged = coalesce(groups);

    assert_eq!(
        merged.len(),
        1,
        "repeated failed attempts must not each grow the stale list: {merged:?}"
    );
    assert_eq!(merged[0].installed, vec![RouteId::ServerBypass]);
}

#[skuld::test]
fn coalesce_keeps_distinct_identities_separate() {
    let a = group(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), vec![RouteId::SplitV4Low]);
    let b = group(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), vec![RouteId::SplitV4Low]);

    let merged = coalesce(vec![a.clone(), b.clone()]);

    assert_eq!(
        merged.len(),
        2,
        "different server_ip means different identity: {merged:?}"
    );
    assert!(merged.contains(&a));
    assert!(merged.contains(&b));
}

#[skuld::test]
fn coalesce_drops_an_id_with_no_possible_teardown_command() {
    let loopback = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // ServerBypass against a loopback server_ip can never produce a
    // teardown command (see `platform_bypass_teardown_command`), so it can
    // never drain from `still_installed` — must be sanitized away here,
    // the same defense `recover_routes_with` already applies to its own
    // two record kinds.
    let unplannable = group(loopback, vec![RouteId::ServerBypass]);

    let merged = coalesce(vec![unplannable]);

    assert!(
        merged.is_empty(),
        "an unplannable-only group must be dropped, not pin stale open forever: {merged:?}"
    );
}

#[skuld::test]
fn coalesce_sanitizes_a_plannable_id_alongside_an_unplannable_one() {
    let loopback = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let mixed = group(loopback, vec![RouteId::SplitV4Low, RouteId::ServerBypass]);

    let merged = coalesce(vec![mixed]);

    assert_eq!(merged.len(), 1);
    assert_eq!(
        merged[0].installed,
        vec![RouteId::SplitV4Low],
        "the plannable id must survive even though its sibling was dropped"
    );
}

/// Pin `installed`'s wire names: they are the persisted schema-2 format a
/// newer binary must read back from an older run's crash-leftover file, so
/// renaming a `RouteId` variant is a schema break needing a version
/// bump and a migration arm, same as the v1 migration below.
#[skuld::test]
fn installed_routes_serialize_as_kebab_case() {
    let dir = tempfile::tempdir().unwrap();
    save(dir.path(), &sample_ipv4(), None).unwrap();
    let raw = std::fs::read_to_string(dir.path().join(STATE_FILE_NAME)).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        parsed["installed"],
        serde_json::json!([
            "split-v4-low",
            "split-v4-high",
            "split-v6-low",
            "split-v6-high",
            "server-bypass"
        ]),
        "in:\n{raw}"
    );
}

// Parse-failure reporting ---------------------------------------------------------------------------------------------
//
// `bridge-routes.json` records `server_ip` — a protected value — on the
// record itself and once per `StaleRecord`. `serde_json::Error`'s `Display`
// quotes the offending bytes back, and nothing arms redaction on the
// recovery path, so the classification in `load` is the only thing between a
// skewed file and `bridge.log`.

/// Capture this crate's records at `WARN` and above for the duration of `body`.
fn captured(body: impl FnOnce()) -> String {
    use tracing_subscriber::layer::{Layer, SubscriberExt};
    let writer = garter::test_utils::WaitableWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
    );
    {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        body();
    }
    writer.snapshot()
}

/// The version is read first, so a file skewed badly enough to put an address
/// where the schema version belongs fails here.
#[skuld::test]
fn a_corrupt_route_state_never_echoes_its_contents_into_the_log() {
    const SECRET_ADDR: &str = "203.0.113.42";
    let json = format!(r#"{{"version":"{SECRET_ADDR}"}}"#);

    // Guard: without it this passes against a serde_json that stopped echoing.
    #[derive(Debug, Deserialize)]
    struct Probe {
        #[allow(dead_code)]
        version: u32,
    }
    let raw = serde_json::from_str::<Probe>(&json)
        .expect_err("must not parse")
        .to_string();
    assert!(raw.contains(SECRET_ADDR), "guard: serde_json echoes the value: {raw}");

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(state_file(dir.path()), &json).unwrap();

    let mut loaded = Some(sample_ipv4());
    let logs = captured(|| loaded = load_record(dir.path()));
    assert!(loaded.is_none(), "a corrupt record must not be acted on");
    assert!(!logs.contains(SECRET_ADDR), "the address reached bridge.log: {logs}");
    assert!(
        logs.contains("version is not a positive integer"),
        "the cause must survive so the warning stays actionable: {logs}"
    );
}

/// The second parse: the version is readable and current, so the record
/// itself is decoded — and a bad *variant tag* makes serde quote an
/// arbitrary caller-supplied string verbatim.
#[skuld::test]
fn a_corrupt_route_state_body_never_echoes_its_contents_into_the_log() {
    const SECRET_ADDR: &str = "203.0.113.42";
    let json = V4_ON_DISK.replacen(
        r#""route_form": "via""#,
        &format!(r#""route_form": "{SECRET_ADDR}""#),
        1,
    );
    assert!(json.contains(SECRET_ADDR), "the fixture must carry the address: {json}");

    let raw = serde_json::from_str::<RouteState>(&json)
        .expect_err("must not parse")
        .to_string();
    assert!(raw.contains(SECRET_ADDR), "guard: serde_json echoes the value: {raw}");

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(state_file(dir.path()), &json).unwrap();

    let mut loaded = Some(sample_ipv4());
    let logs = captured(|| loaded = load_record(dir.path()));
    assert!(loaded.is_none(), "a corrupt record must not be acted on");
    assert!(!logs.contains(SECRET_ADDR), "the address reached bridge.log: {logs}");
    assert!(
        logs.contains("line 7"),
        "position must survive so the warning stays actionable: {logs}"
    );
}
