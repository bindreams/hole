use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;
use util::versioned_file::{Change, DefaultPlacement};

/// Write `state` to `<dir>/bridge-dns.json` through the versioned file. The only place besides
/// `crate::dns::recovery_tests` that constructs a `bridge-dns.json` on disk.
fn write_state(dir: &std::path::Path, state: &DnsState) {
    file(dir)
        .update(&DefaultPlacement::default(), |_| (Change::Store(state.clone()), ()))
        .unwrap();
}

fn sample_windows_state() -> DnsState {
    DnsState {
        advertised: vec![
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        ],
        adapters: vec![
            DnsPriorAdapter {
                id: AdapterId::WindowsAlias {
                    value: "Ethernet".into(),
                },
                name_at_capture: "Ethernet".into(),
                v4: DnsPrior::Static {
                    servers: vec![
                        IpAddr::V4(Ipv4Addr::new(89, 216, 1, 40)),
                        IpAddr::V4(Ipv4Addr::new(89, 216, 1, 50)),
                    ],
                },
                v6: DnsPrior::None,
            },
            DnsPriorAdapter {
                id: AdapterId::WindowsAlias {
                    value: "hole-tun".into(),
                },
                name_at_capture: "hole-tun".into(),
                v4: DnsPrior::Dhcp,
                v6: DnsPrior::Static {
                    servers: vec![IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888))],
                },
            },
        ],
    }
}

fn sample_macos_state() -> DnsState {
    DnsState {
        advertised: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
        adapters: vec![DnsPriorAdapter {
            id: AdapterId::MacosServiceName { value: "Wi-Fi".into() },
            name_at_capture: "Wi-Fi".into(),
            v4: DnsPrior::Dhcp,
            v6: DnsPrior::None,
        }],
    }
}

#[skuld::test]
fn write_then_load_roundtrip_windows() {
    let dir = tempfile::tempdir().unwrap();
    let state = sample_windows_state();
    write_state(dir.path(), &state);
    let loaded = load(dir.path()).unwrap();
    assert_eq!(loaded, state);
}

#[skuld::test]
fn write_then_load_roundtrip_macos() {
    let dir = tempfile::tempdir().unwrap();
    let state = sample_macos_state();
    write_state(dir.path(), &state);
    let loaded = load(dir.path()).unwrap();
    assert_eq!(loaded, state);
}

#[skuld::test]
fn write_then_load_roundtrip_empty_advertised() {
    let dir = tempfile::tempdir().unwrap();
    let state = DnsState {
        advertised: vec![],
        adapters: vec![],
    };
    write_state(dir.path(), &state);
    let loaded = load(dir.path()).unwrap();
    assert_eq!(loaded, state);
}

#[skuld::test]
fn load_missing_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    assert!(load(dir.path()).is_none());
}

#[skuld::test]
fn load_corrupted_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(STATE_FILE_NAME), b"not valid json { .").unwrap();
    assert!(load(dir.path()).is_none());
}

#[skuld::test]
fn load_wrong_version_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": 99,
        "advertised": ["1.1.1.1"],
        "adapters": [],
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();
    assert!(load(dir.path()).is_none());
}

#[skuld::test]
fn a_v1_record_with_the_obsolete_chosen_loopback_key_still_loads() {
    // DnsState dropped `deny_unknown_fields` so a v1 file's obsolete
    // `chosen_loopback` key (and any future stray top-level key) is
    // ignored rather than failing recovery.
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": 1,
        "chosen_loopback": "127.0.0.1:53", // obsolete v1 key — ignored
        "adapters": [],
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();
    let loaded = load(dir.path()).expect("v1 file with obsolete key must still load");
    assert!(loaded.advertised.is_empty(), "advertised defaults to empty when absent");
    assert!(loaded.adapters.is_empty());
}

#[skuld::test]
fn load_tolerates_an_unknown_adapter_field() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": 1,
        "advertised": ["1.1.1.1"],
        "adapters": [{
            "id": { "kind": "windows_alias", "value": "Ethernet" },
            "name_at_capture": "Ethernet",
            "v4": { "kind": "none" },
            "v6": { "kind": "none" },
            "surprise": true,
        }],
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();
    assert!(load(dir.path()).is_some());
}

#[skuld::test]
fn load_unknown_dns_prior_variant_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": 1,
        "advertised": ["1.1.1.1"],
        "adapters": [{
            "id": { "kind": "windows_alias", "value": "Ethernet" },
            "name_at_capture": "Ethernet",
            "v4": { "kind": "mystery_mode" },
            "v6": { "kind": "none" },
        }],
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();
    assert!(load(dir.path()).is_none());
}

#[skuld::test]
fn dns_prior_variants_serialize_snake_case() {
    let none_json = serde_json::to_value(DnsPrior::None).unwrap();
    assert_eq!(none_json, serde_json::json!({ "kind": "none" }));

    let dhcp_json = serde_json::to_value(DnsPrior::Dhcp).unwrap();
    assert_eq!(dhcp_json, serde_json::json!({ "kind": "dhcp" }));

    let static_json = serde_json::to_value(DnsPrior::Static {
        servers: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
    })
    .unwrap();
    assert_eq!(
        static_json,
        serde_json::json!({ "kind": "static", "servers": ["1.1.1.1"] })
    );
}

#[skuld::test]
fn adapter_id_variants_serialize_snake_case() {
    let win = serde_json::to_value(AdapterId::WindowsAlias {
        value: "Ethernet".into(),
    })
    .unwrap();
    assert_eq!(win, serde_json::json!({ "kind": "windows_alias", "value": "Ethernet" }));

    let mac = serde_json::to_value(AdapterId::MacosServiceName { value: "abc".into() }).unwrap();
    assert_eq!(mac, serde_json::json!({ "kind": "macos_service_name", "value": "abc" }));
}

#[skuld::test]
fn load_tolerates_an_unknown_field_in_the_static_variant() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": 1,
        "advertised": ["1.1.1.1"],
        "adapters": [{
            "id": { "kind": "windows_alias", "value": "Ethernet" },
            "name_at_capture": "Ethernet",
            "v4": { "kind": "static", "servers": ["1.1.1.1"], "mystery": true },
            "v6": { "kind": "none" },
        }],
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();
    assert!(load(dir.path()).is_some());
}

#[skuld::test]
fn load_tolerates_an_unknown_field_in_macos_service_name() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": 1,
        "advertised": ["1.1.1.1"],
        "adapters": [{
            "id": { "kind": "macos_service_name", "value": "abc", "extra": 1 },
            "name_at_capture": "Wi-Fi",
            "v4": { "kind": "none" },
            "v6": { "kind": "none" },
        }],
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();
    assert!(load(dir.path()).is_some());
}

#[skuld::test]
fn load_rejects_missing_required_field() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": 1,
        "advertised": ["1.1.1.1"],
        // adapters missing — still required (no serde default)
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();
    assert!(load(dir.path()).is_none());
}

#[skuld::test]
fn write_then_load_roundtrip_ipv6_advertised() {
    let dir = tempfile::tempdir().unwrap();
    let state = DnsState {
        advertised: vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
        adapters: vec![],
    };
    write_state(dir.path(), &state);
    let loaded = load(dir.path()).unwrap();
    assert_eq!(loaded, state);
}

/// A record this release cannot read: newer, corrupt, and one whose read fails (a directory at the name).
/// What a record is called and how it is planted in a folder.
type Planting = (&'static str, fn(&std::path::Path));

fn plant_unreadable_records() -> [Planting; 3] {
    [
        ("newer", |dir| {
            std::fs::write(dir.join(STATE_FILE_NAME), br#"{"version":99,"adapters":[]}"#).unwrap()
        }),
        ("corrupt", |dir| {
            std::fs::write(dir.join(STATE_FILE_NAME), b"not valid json { .").unwrap()
        }),
        ("a failed read", |dir| {
            std::fs::create_dir_all(dir.join(STATE_FILE_NAME)).unwrap()
        }),
    ]
}

#[skuld::test]
fn a_dns_record_that_cannot_be_read_loads_as_none_and_is_kept() {
    for (what, plant) in plant_unreadable_records() {
        let dir = tempfile::tempdir().unwrap();
        plant(dir.path());

        assert!(load(dir.path()).is_none(), "{what}");
        assert_eq!(clear(dir.path()).unwrap(), UpdateOutcome::Kept, "{what}");
        assert!(
            dir.path().join(STATE_FILE_NAME).exists(),
            "{what}: the record was removed"
        );
    }
}

#[skuld::test]
fn clear_missing_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    clear(dir.path()).unwrap();
}

#[skuld::test]
fn clear_existing_removes_file() {
    let dir = tempfile::tempdir().unwrap();
    write_state(dir.path(), &sample_windows_state());
    assert!(dir.path().join(STATE_FILE_NAME).exists());
    clear(dir.path()).unwrap();
    assert!(!dir.path().join(STATE_FILE_NAME).exists());
}

#[skuld::test]
fn clear_refuses_a_state_dir_that_is_a_users_link_to_a_system_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let state = util::dir::testing::state_dir_linked_to_a_system_folder(tmp.path());

    let err = clear(&state).unwrap_err();

    let util::versioned_file::StoreError::Io(err) = err else {
        panic!("expected an I/O refusal, got {err:?}");
    };
    assert_eq!(util::dir::Refusal::from_error(&err), Some(&util::dir::Refusal::Symlink));
}

#[skuld::test]
fn state_file_name_is_bridge_dns_json() {
    assert_eq!(STATE_FILE_NAME, "bridge-dns.json");
}

#[skuld::test]
fn superseded_file_name_is_distinct() {
    assert_eq!(SUPERSEDED_FILE_NAME, "bridge-dns.superseded.json");
    assert_ne!(SUPERSEDED_FILE_NAME, STATE_FILE_NAME);
}

#[skuld::test]
fn supersede_missing_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    supersede(dir.path()).unwrap();
}

#[skuld::test]
fn supersede_renames_and_load_no_longer_sees_it() {
    let dir = tempfile::tempdir().unwrap();
    write_state(dir.path(), &sample_windows_state());
    supersede(dir.path()).unwrap();

    assert!(!dir.path().join(STATE_FILE_NAME).exists());
    assert!(dir.path().join(SUPERSEDED_FILE_NAME).exists());
    assert!(
        load(dir.path()).is_none(),
        "load must never read the superseded name — the bridge evaluates a file at most once"
    );
}

#[skuld::test]
fn supersede_refuses_a_state_dir_that_is_a_users_link_to_a_system_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let state = util::dir::testing::state_dir_linked_to_a_system_folder(tmp.path());

    let err = supersede(&state).unwrap_err();

    assert_eq!(util::dir::Refusal::from_error(&err), Some(&util::dir::Refusal::Symlink));
}

/// A name that is taken but that `Path::exists` does not see: a symlink to nothing. A check-then-rename takes it for
/// free and replaces it, so the user's planted name is what a probe cannot tell from a free one.
#[skuld::test]
fn supersede_does_not_replace_a_name_a_probe_would_call_free() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(STATE_FILE_NAME), b"state").unwrap();
    let superseded = dir.path().join(SUPERSEDED_FILE_NAME);
    let nothing = dir.path().join("no-such-file");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&nothing, &superseded).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&nothing, &superseded).unwrap();
    assert!(!superseded.exists(), "the fixture must look free to a probe");

    supersede(dir.path()).unwrap();

    assert!(
        std::fs::symlink_metadata(&superseded).unwrap().is_symlink(),
        "the name that was taken was replaced"
    );
    assert_eq!(
        std::fs::read(dir.path().join("bridge-dns.superseded.2.json")).unwrap(),
        b"state"
    );
}

#[skuld::test]
fn supersede_takes_the_first_free_archive_name() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(SUPERSEDED_FILE_NAME), b"oldest").unwrap();
    std::fs::write(dir.path().join("bridge-dns.superseded.2.json"), b"older").unwrap();
    std::fs::write(dir.path().join(STATE_FILE_NAME), b"newest").unwrap();

    supersede(dir.path()).unwrap();

    assert_eq!(std::fs::read(dir.path().join(SUPERSEDED_FILE_NAME)).unwrap(), b"oldest");
    assert_eq!(
        std::fs::read(dir.path().join("bridge-dns.superseded.2.json")).unwrap(),
        b"older"
    );
    assert_eq!(
        std::fs::read(dir.path().join("bridge-dns.superseded.3.json")).unwrap(),
        b"newest"
    );
}

#[skuld::test]
fn supersede_with_no_state_file_leaves_an_existing_superseded_file_alone() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(SUPERSEDED_FILE_NAME), b"oldest").unwrap();

    supersede(dir.path()).unwrap();

    assert_eq!(std::fs::read(dir.path().join(SUPERSEDED_FILE_NAME)).unwrap(), b"oldest");
    assert!(!dir.path().join("bridge-dns.superseded.2.json").exists());
}

/// A second `supersede` call (reinstall, rollback, or a second crash before
/// the first superseded file was ever inspected) must not destroy the
/// first one — `fs::rename` replaces an existing destination on both POSIX
/// and Windows, so `supersede` cannot be a bare rename once a superseded
/// file already exists. The older file wins the canonical name and the
/// newer one is archived under a fresh name instead; nothing is lost.
#[skuld::test]
fn supersede_twice_archives_the_newer_file_instead_of_clobbering_the_older_one() {
    let dir = tempfile::tempdir().unwrap();

    std::fs::write(dir.path().join(STATE_FILE_NAME), b"first").unwrap();
    supersede(dir.path()).unwrap();
    assert!(!dir.path().join(STATE_FILE_NAME).exists());
    let superseded_path = dir.path().join(SUPERSEDED_FILE_NAME);
    assert_eq!(
        std::fs::read(&superseded_path).unwrap(),
        b"first",
        "first supersede must land the canonical name"
    );

    std::fs::write(dir.path().join(STATE_FILE_NAME), b"second").unwrap();
    supersede(dir.path()).unwrap();
    assert!(
        !dir.path().join(STATE_FILE_NAME).exists(),
        "the un-suffixed name must be gone after the second supersede too"
    );
    assert_eq!(
        std::fs::read(&superseded_path).unwrap(),
        b"first",
        "the older, already-superseded file must survive untouched — it is the evidence closer to          the user's true original DNS"
    );
    let archive_path = dir.path().join("bridge-dns.superseded.2.json");
    assert_eq!(
        std::fs::read(&archive_path).unwrap(),
        b"second",
        "the newer file's content must survive under a non-colliding archive name, not be lost"
    );
}
