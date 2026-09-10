use super::*;
use hole_common::config::ServerEntry;
use hole_common::protocol::TunnelMode;
use std::sync::mpsc;

fn test_config() -> ProxyConfig {
    ProxyConfig {
        server: ServerEntry {
            id: "test-id".into(),
            name: "test-server".into(),
            server: "example.invalid".into(),
            server_port: 8388,
            password: "super-secret-password".into(),
            method: "aes-256-gcm".into(),
            plugin: None,
            plugin_opts: None,
            validation: None,
        },
        local_port: 1080,
        tunnel_mode: TunnelMode::Full,
        filters: Vec::new(),
        dns: hole_common::config::DnsConfig {
            enabled: false,
            ..hole_common::config::DnsConfig::default()
        },
        proxy_socks5: true,
        proxy_http: false,
        local_port_http: 4074,
        diagnostic_plugin_tap: false,
    }
}

// Task 1: persistence =================================================================================================

#[skuld::test]
fn an_absent_target_file_reads_off() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(load(tmp.path()), Target::Off);
}

#[skuld::test]
fn a_corrupt_target_file_reads_unreadable_and_warns() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path()).unwrap();
    std::fs::write(tmp.path().join(STATE_FILE_NAME), b"not json").unwrap();
    assert_eq!(
        load(tmp.path()),
        Target::Unreadable,
        "a corrupt file must not be silently treated as a decided target"
    );
}

#[skuld::test]
fn a_saved_connected_target_round_trips() {
    let tmp = tempfile::tempdir().unwrap();
    let config = test_config();
    let target = Target::Connected {
        config: Box::new(config.clone()),
    };
    save(tmp.path(), &target, None).unwrap();
    assert_eq!(
        load(tmp.path()),
        Target::Connected {
            config: Box::new(config)
        }
    );
}

#[skuld::test]
fn the_target_file_never_carries_the_server_address() {
    use dump::Dump;
    let config = test_config();
    let target = Target::Connected {
        config: Box::new(config),
    };
    // Render through the actual redacting formatter (default
    // `redact_secrets: true`) rather than inspecting the raw `DumpValue`
    // tree, whose `Tagged("secret", ...)` node still carries the plaintext
    // value — redaction is a rendering-time property, not a `dump()`-time
    // one. This is the artifact that actually reaches a log or bundle.
    let rendered = dump::YamlFormatter::default().to_string(&target.dump());
    assert!(
        !rendered.contains("example.invalid"),
        "rendered dump must not carry the configured host in clear, got: {rendered}"
    );
    assert!(
        !rendered.contains("super-secret-password"),
        "rendered dump must not carry the password in clear, got: {rendered}"
    );
    assert!(
        rendered.contains("REDACTED"),
        "rendered dump must show a redaction marker, got: {rendered}"
    );
}

#[skuld::test]
fn a_saved_target_file_is_owner_only_in_an_owner_only_directory() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let target = Target::Connected {
            config: Box::new(test_config()),
        };
        save(tmp.path(), &target, None).unwrap();

        let dir_mode = std::fs::metadata(tmp.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "state dir must be 0700, got {dir_mode:o}");

        let file_mode = std::fs::metadata(tmp.path().join(STATE_FILE_NAME))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600, "target file must be 0600, got {file_mode:o}");
    }
}

// Task 2: target_after ================================================================================================

#[skuld::test]
fn a_cutover_leaves_the_target_connected() {
    let config = test_config();
    let current = Target::Connected {
        config: Box::new(config.clone()),
    };
    assert_eq!(
        target_after(current, SessionEvent::CutoverRestart),
        Target::Connected {
            config: Box::new(config)
        }
    );
}

#[skuld::test]
fn a_blip_leaves_the_target_connected() {
    let config = test_config();
    let current = Target::Connected {
        config: Box::new(config.clone()),
    };
    assert_eq!(
        target_after(current, SessionEvent::Blipped),
        Target::Connected {
            config: Box::new(config)
        }
    );
}

#[skuld::test]
fn giving_up_moves_the_target_off() {
    let current = Target::Connected {
        config: Box::new(test_config()),
    };
    assert_eq!(target_after(current, SessionEvent::GaveUp), Target::Off);
}

#[skuld::test]
fn a_user_stop_moves_the_target_off() {
    let current = Target::Connected {
        config: Box::new(test_config()),
    };
    assert_eq!(target_after(current, SessionEvent::UserStopped), Target::Off);
}

#[skuld::test]
fn no_event_revives_an_off_target() {
    for ev in [
        SessionEvent::UserStopped,
        SessionEvent::GaveUp,
        SessionEvent::CutoverRestart,
        SessionEvent::Blipped,
        SessionEvent::ProcessExiting,
    ] {
        assert_eq!(
            target_after(Target::Off, ev),
            Target::Off,
            "event {ev:?} must not revive Off"
        );
    }
}

#[skuld::test]
fn a_clean_machine_shutdown_leaves_the_target_connected() {
    let config = test_config();
    let current = Target::Connected {
        config: Box::new(config.clone()),
    };
    assert_eq!(
        target_after(current, SessionEvent::ProcessExiting),
        Target::Connected {
            config: Box::new(config)
        },
        "a clean machine shutdown must not clear reconnect-on-boot"
    );
}

// Task 4: startup preference / apply ==================================================================================

#[skuld::test]
fn the_bridge_owns_the_startup_connect_decision() {
    // The full truth table, relocated verbatim from `crates/hole/src/tray.rs`
    // (#979) — see `the_gui_no_longer_decides` for the structural half of
    // this guarantee.
    assert!(!startup_should_connect(StartupBehavior::DoNotConnect, true));
    assert!(!startup_should_connect(StartupBehavior::DoNotConnect, false));
    assert!(startup_should_connect(StartupBehavior::RestoreLastState, true));
    assert!(!startup_should_connect(StartupBehavior::RestoreLastState, false));
    assert!(startup_should_connect(StartupBehavior::AlwaysConnect, true));
    assert!(startup_should_connect(StartupBehavior::AlwaysConnect, false));
}

#[skuld::test]
fn always_connect_overrides_a_persisted_off_target() {
    let config = test_config();
    let candidate = Some(Box::new(config.clone()));
    assert_eq!(
        resolve_startup_target(Target::Off, StartupBehavior::AlwaysConnect, candidate),
        Target::Connected {
            config: Box::new(config)
        },
        "AlwaysConnect must write Connected before the first reconcile"
    );
}

#[skuld::test]
fn restore_last_state_leaves_the_persisted_target_unchanged() {
    let config = test_config();
    for persisted in [
        Target::Off,
        Target::Connected {
            config: Box::new(config.clone()),
        },
        Target::Unreadable,
    ] {
        assert_eq!(
            resolve_startup_target(persisted.clone(), StartupBehavior::RestoreLastState, None),
            persisted,
            "RestoreLastState must leave the persisted target as-is"
        );
    }
}

#[skuld::test]
fn do_not_connect_always_writes_off() {
    let config = test_config();
    for persisted in [
        Target::Off,
        Target::Connected {
            config: Box::new(config.clone()),
        },
        Target::Unreadable,
    ] {
        assert_eq!(
            resolve_startup_target(persisted, StartupBehavior::DoNotConnect, Some(Box::new(config.clone()))),
            Target::Off,
            "DoNotConnect must write Off regardless of what was persisted"
        );
    }
}

#[skuld::test]
fn always_connect_keeps_an_already_connected_target_over_the_candidate() {
    let persisted_config = test_config();
    let mut candidate_config = test_config();
    candidate_config.local_port = 9999;
    let persisted = Target::Connected {
        config: Box::new(persisted_config.clone()),
    };
    assert_eq!(
        resolve_startup_target(
            persisted,
            StartupBehavior::AlwaysConnect,
            Some(Box::new(candidate_config))
        ),
        Target::Connected {
            config: Box::new(persisted_config)
        },
        "an already-Connected target is already fully specified; the candidate must not override it"
    );
}

#[skuld::test]
fn always_connect_with_no_candidate_and_no_persisted_target_stays_unchanged() {
    assert_eq!(
        resolve_startup_target(Target::Off, StartupBehavior::AlwaysConnect, None),
        Target::Off,
        "there is nothing to fabricate a connection from"
    );
    assert_eq!(
        resolve_startup_target(Target::Unreadable, StartupBehavior::AlwaysConnect, None),
        Target::Unreadable,
        "there is nothing to fabricate a connection from"
    );
}

#[skuld::test]
fn setting_the_target_persists_the_startup_preference() {
    let tmp = tempfile::tempdir().unwrap();
    let config = test_config();
    let pref = StartupPreference {
        on_startup: StartupBehavior::AlwaysConnect,
        candidate: Some(Box::new(config.clone())),
    };
    save_startup_preference(tmp.path(), &pref, None).unwrap();

    // A fresh load (no in-memory state carried over) reads the same value
    // back — the property the IPC target-set handler relies on to survive a
    // bridge restart between "user connected" and "machine reboots".
    assert_eq!(load_startup_preference(tmp.path()), pref);
}

#[skuld::test]
fn an_absent_startup_preference_defaults_to_restore_last_state_with_no_candidate() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(load_startup_preference(tmp.path()), StartupPreference::default());
    assert_eq!(
        load_startup_preference(tmp.path()).on_startup,
        StartupBehavior::RestoreLastState
    );
}

#[skuld::test]
fn a_corrupt_startup_preference_file_reads_as_default() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path()).unwrap();
    std::fs::write(tmp.path().join(STARTUP_PREFERENCE_FILE_NAME), b"not json").unwrap();
    assert_eq!(
        load_startup_preference(tmp.path()),
        StartupPreference::default(),
        "a corrupt startup-preference file must not be treated as an always-connect authorization"
    );
}

#[skuld::test]
fn apply_round_trips_through_load_and_save() {
    let tmp = tempfile::tempdir().unwrap();
    let config = test_config();
    let next = apply(tmp.path(), None, |_current| Target::Connected {
        config: Box::new(config.clone()),
    })
    .unwrap();
    assert_eq!(
        next,
        Target::Connected {
            config: Box::new(config.clone())
        }
    );
    assert_eq!(
        load(tmp.path()),
        Target::Connected {
            config: Box::new(config)
        },
        "apply must have saved before returning"
    );
}

#[skuld::test]
fn a_second_apply_call_sees_the_first_ones_write_not_a_value_captured_before_acquiring() {
    // Genuine two-thread race, real rendezvous (channels, no sleep/poll) —
    // same shape as `tun_engine::exclusive`'s
    // `acquire_blocks_until_the_holder_releases`. Thread A holds `apply`'s
    // lock open (via a closure that blocks on a channel) while thread B's
    // `apply` call is issued; B must block until A's whole load-apply-save
    // section has completed, and then must observe A's write as `current`
    // — proving `apply` loads fresh under the lock rather than composing
    // from a value read before acquiring it, which is exactly what would let
    // a session-event write and the `unlock` escape's write race instead of
    // serializing.
    let tmp = tempfile::tempdir().unwrap();
    let state_dir = tmp.path().to_path_buf();
    let config = test_config();
    let connected = Target::Connected {
        config: Box::new(config.clone()),
    };

    let (a_holding_tx, a_holding_rx) = mpsc::channel::<()>();
    let (release_a_tx, release_a_rx) = mpsc::channel::<()>();
    let a_dir = state_dir.clone();
    let a_target = connected.clone();
    let a = std::thread::spawn(move || {
        apply(&a_dir, None, move |_current| {
            a_holding_tx.send(()).unwrap();
            // Real rendezvous: block inside the critical section until the
            // main thread confirms B's `apply` call has been issued.
            release_a_rx.recv().unwrap();
            a_target
        })
        .unwrap();
    });
    // Blocks until A is actually inside the critical section — no poll.
    a_holding_rx.recv().unwrap();

    let (b_saw_tx, b_saw_rx) = mpsc::channel::<Target>();
    let b_dir = state_dir.clone();
    let b = std::thread::spawn(move || {
        let next = apply(&b_dir, None, |current| {
            b_saw_tx.send(current).unwrap();
            Target::Off
        })
        .unwrap();
        assert_eq!(next, Target::Off);
    });

    // Let A finish (save, release the lock), then wait for B to report what
    // it observed as `current`.
    release_a_tx.send(()).unwrap();
    let seen_by_b = b_saw_rx.recv().unwrap();

    a.join().unwrap();
    b.join().unwrap();

    assert_eq!(
        seen_by_b, connected,
        "B's apply must load A's write fresh, not a value captured before B acquired the lock"
    );
    assert_eq!(
        load(&state_dir),
        Target::Off,
        "B's save must be the final state on disk"
    );
}

#[skuld::test]
fn every_session_event_over_an_unreadable_target_is_defined() {
    // Exhaustiveness documentation: an Unreadable current target has no
    // config to preserve, so an event that would otherwise "leave it
    // unchanged" leaves it Unreadable (nothing to lose), and an event that
    // decides a definite outcome (give-up, user-stop) still lands on the
    // same definite Off it would from a known Connected target.
    assert_eq!(target_after(Target::Unreadable, SessionEvent::GaveUp), Target::Off);
    assert_eq!(target_after(Target::Unreadable, SessionEvent::UserStopped), Target::Off);
    assert_eq!(
        target_after(Target::Unreadable, SessionEvent::ProcessExiting),
        Target::Unreadable
    );
    assert_eq!(
        target_after(Target::Unreadable, SessionEvent::CutoverRestart),
        Target::Unreadable
    );
    assert_eq!(
        target_after(Target::Unreadable, SessionEvent::Blipped),
        Target::Unreadable
    );
}

#[skuld::test]
fn apply_leaves_an_unreadable_target_file_untouched_when_f_declines() {
    // `target_after`'s `ProcessExiting`/`CutoverRestart`/`Blipped` arms pass
    // an `Unreadable` current target straight through — a real, reachable
    // case, not a caller error — so `apply` must not hand that value to
    // `save`, which has no on-disk form for it and would otherwise silently
    // downgrade the file to `Off`, destroying the "not authority to disarm"
    // property `Unreadable` exists for.
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path()).unwrap();
    let corrupt: &[u8] = b"not json";
    std::fs::write(tmp.path().join(STATE_FILE_NAME), corrupt).unwrap();

    let next = apply(tmp.path(), None, |current| {
        target_after(current, SessionEvent::ProcessExiting)
    })
    .unwrap();

    assert_eq!(next, Target::Unreadable);
    let on_disk = std::fs::read(tmp.path().join(STATE_FILE_NAME)).unwrap();
    assert_eq!(
        on_disk, corrupt,
        "apply must leave an unreadable target file untouched when f declines to decide, not overwrite it with Off"
    );
}

// Windows DACL ========================================================================================================

/// Read `path`'s DACL back as an SDDL string. Round-tripping through SDDL
/// rather than walking ACEs with `GetAce` keeps the unsafe surface to two
/// calls and makes the assertion readable: the protected flag shows up as
/// `D:P` and each ACE as a `(A;;...;SID)` clause.
#[cfg(target_os = "windows")]
fn dacl_sddl(path: &std::path::Path) -> String {
    use windows::core::{HSTRING, PWSTR};
    use windows::Win32::Foundation::LocalFree;
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

    let wide = HSTRING::from(path.as_os_str());
    let mut psd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `wide` outlives the call; `psd` is an out-param Windows fills
    // with a LocalAlloc'd descriptor that we free below. The two None
    // out-params are documented as optional.
    unsafe {
        GetNamedSecurityInfoW(
            &wide,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut psd,
        )
        // Returns WIN32_ERROR, not Result — `.ok()` converts it.
        .ok()
        .expect("GetNamedSecurityInfoW failed");
    }

    let mut out = PWSTR::null();
    // SAFETY: `psd` is a valid descriptor from the call above; `out` receives
    // a LocalAlloc'd string freed below.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            psd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut out,
            None,
        )
        .expect("ConvertSecurityDescriptorToStringSecurityDescriptorW failed");
    }
    // SAFETY: `out` is a NUL-terminated wide string owned by us until LocalFree.
    let sddl = unsafe { out.to_string().expect("SDDL string was not valid UTF-16") };
    // SAFETY: both pointers came from LocalAlloc inside the calls above.
    unsafe {
        let _ = LocalFree(Some(std::mem::transmute::<PWSTR, windows::Win32::Foundation::HLOCAL>(
            out,
        )));
        let _ = LocalFree(Some(std::mem::transmute::<
            PSECURITY_DESCRIPTOR,
            windows::Win32::Foundation::HLOCAL,
        >(psd)));
    }
    sddl
}

/// The state directory and the target file hold a `ProxyConfig`, i.e. the
/// shadowsocks password. Under `C:\ProgramData` the inherited ACL grants
/// `BUILTIN\Users` read, so both objects must carry a PROTECTED DACL (which
/// is what drops the inherited ACE) naming only SYSTEM, Administrators and
/// the current token's user.
#[cfg(target_os = "windows")]
#[skuld::test]
fn windows_state_dir_and_files_are_not_readable_by_users() {
    let tmp = tempfile::tempdir().unwrap();
    let state_dir = tmp.path().join("state");
    let target = Target::Connected {
        config: Box::new(test_config()),
    };
    save(&state_dir, &target, None).unwrap();

    let dir_sddl = dacl_sddl(&state_dir);
    let file_sddl = dacl_sddl(&state_dir.join(STATE_FILE_NAME));

    for (what, sddl) in [("state dir", &dir_sddl), ("target file", &file_sddl)] {
        assert!(
            sddl.starts_with("D:P"),
            "{what} DACL is not protected, so C:\\ProgramData's inherited \
             BUILTIN\\Users ACE would survive: {sddl}"
        );
        assert!(
            !sddl.contains("S-1-5-32-545") && !sddl.contains(";BU)"),
            "{what} DACL still grants BUILTIN\\Users: {sddl}"
        );
        let me = crate::target::current_user_sid().expect("current token user SID");
        // Windows renders well-known SIDs as SDDL ABBREVIATIONS, so the raw
        // string need not appear even when the ACE is there. Observed on CI:
        // the token user `S-1-5-21-...-500` (the built-in Administrator) comes
        // back as `LA`, in
        // `D:PAI(A;;FA;;;SY)(A;OICIIO;GA;;;SY)...(A;;FA;;;LA)(A;OICIIO;GA;;;LA)`.
        //
        // Every abbreviation below names a principal that ALREADY has access
        // through `SDDL_BASE` (SYSTEM, Administrators) or is an administrator
        // account, so accepting them cannot mask the case this guards: a
        // genuinely non-privileged elevation-mode owner has no abbreviation
        // and must appear verbatim.
        let renders_as_abbreviation = me == "S-1-5-18" // SY, SYSTEM
            || me == "S-1-5-32-544" // BA, BUILTIN\Administrators
            || (me.starts_with("S-1-5-21-") && me.ends_with("-500")); // LA, built-in Administrator
        assert!(
            sddl.contains(&me) || renders_as_abbreviation,
            "{what} DACL does not grant the current user ({me}), which would \
             lock the elevation-mode owner out of their own state dir: {sddl}"
        );
    }
}

/// The on-disk shapes are the same ladder as [`Target`]'s, and unlike
/// `Target` they *do* derive `Serialize` — so a `dump!` on one renders the
/// serde tree and never reaches `ProxyConfig::dump`. Private to this module
/// today; visibility is not what makes a secret safe.
#[skuld::test]
fn the_persisted_file_shapes_never_carry_the_secrets() {
    use dump::Dump;
    let config = Box::new(test_config());
    let rendered = [
        TargetFile {
            version: 1,
            target: PersistedTarget::Connected { config: config.clone() },
        }
        .dump(),
        PersistedTarget::Connected { config: config.clone() }.dump(),
        StartupPreferenceFile {
            version: 1,
            on_startup: hole_common::config::StartupBehavior::default(),
            candidate: Some(config),
        }
        .dump(),
    ];
    for value in rendered {
        let text = dump::YamlFormatter::default().to_string(&value);
        assert!(
            !text.contains("example.invalid"),
            "rendered dump must not carry the configured host in clear, got: {text}"
        );
        assert!(
            !text.contains("super-secret-password"),
            "rendered dump must not carry the password in clear, got: {text}"
        );
    }
}

/// The paired positive. Without it, a `Dump` impl that rendered `Null` for
/// every secret-bearing arm would satisfy the negative above and destroy the
/// diagnostic instead of redacting it — so the assertion has to land on the
/// `Connected` / `Some(candidate)` arms specifically, not just on `Off`.
#[skuld::test]
fn the_persisted_file_shapes_still_carry_their_non_secret_payload() {
    use dump::Dump;
    let config = Box::new(test_config()); // local_port 1080, not a secret
    let yaml = |v: dump::DumpValue| dump::YamlFormatter::default().to_string(&v);

    let text = yaml(
        TargetFile {
            version: 7,
            target: PersistedTarget::Connected { config: config.clone() },
        }
        .dump(),
    );
    assert!(text.contains('7'), "the schema version: {text}");
    assert!(text.contains("1080"), "and the config's non-secret fields: {text}");

    let text = yaml(
        StartupPreferenceFile {
            version: 9,
            on_startup: hole_common::config::StartupBehavior::AlwaysConnect,
            candidate: Some(config),
        }
        .dump(),
    );
    assert!(text.contains('9'), "the schema version: {text}");
    assert!(text.contains("always_connect"), "the startup preference: {text}");
    assert!(text.contains("1080"), "and the candidate's non-secret fields: {text}");
}
