#![allow(clippy::disallowed_methods)] // attended test: bare-name host tools
use super::*;

// CommandLineToArgvW roundtrip ========================================================================================

// The `build_cmdline` function has a `#[debug_ensures]` contract that roundtrips through the
// real `CommandLineToArgvW` API on every call. These tests exercise it with various edge cases.

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_simple_args() {
    build_cmdline(&["bridge", "install"]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_space() {
    build_cmdline(&["hello world"]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_tab() {
    build_cmdline(&["foo\tbar"]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_embedded_quotes() {
    build_cmdline(&[r#"say "hi""#]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_trailing_backslash_with_spaces() {
    build_cmdline(&[r"C:\path to\dir\"]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_backslash_before_quote() {
    build_cmdline(&[r#"a\"b"#]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_empty_string() {
    build_cmdline(&[""]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_realistic_msi_path() {
    build_cmdline(&[r"C:\Users\John Doe\AppData\Local\Temp\hole-update\hole.msi"]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_path_no_spaces() {
    build_cmdline(&[r"C:\tmp\hole.msi"]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_trailing_backslash_no_spaces() {
    build_cmdline(&[r"C:\tmp\"]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_mixed_realistic() {
    build_cmdline(&["/i", r"C:\Users\John Doe\tmp\hole.msi", "/quiet", "/norestart"]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_whitespace_only() {
    build_cmdline(&[" "]);
    build_cmdline(&["\t"]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_newline() {
    build_cmdline(&["foo\nbar"]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_multiple_backslashes_before_quote() {
    build_cmdline(&[r#"a\\\\"b"#]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_multiple_empty_args() {
    build_cmdline(&["", ""]);
}

// Status detection ====================================================================================================

#[skuld::test]
fn bridge_install_status_returns_a_value() {
    // On a dev machine the bridge is typically not installed,
    // but we just verify the function runs without panicking.
    let status = bridge_install_status();
    // Should be one of the three variants
    assert!(matches!(
        status,
        BridgeInstallStatus::Running | BridgeInstallStatus::Installed | BridgeInstallStatus::NotInstalled
    ));
}

#[skuld::test]
fn bridge_binary_path_resolves() {
    let path = bridge_binary_path().expect("should resolve current exe");
    assert!(path.exists(), "resolved path should exist: {path:?}");
}

// truncate_for_dialog =================================================================================================

#[skuld::test]
fn truncate_for_dialog_empty_input() {
    assert_eq!(truncate_for_dialog(""), "");
}

#[skuld::test]
fn truncate_for_dialog_under_limit_passthrough() {
    let s = "one\ntwo\nthree\n";
    assert_eq!(truncate_for_dialog(s), s);
}

#[skuld::test]
fn truncate_for_dialog_under_limit_no_trailing_newline() {
    let s = "single line no newline";
    assert_eq!(truncate_for_dialog(s), s);
}

#[skuld::test]
fn truncate_for_dialog_over_limit_cuts_at_line_boundary() {
    // Build a big repeating line, well over DIALOG_OUTPUT_BUDGET (3 KiB).
    let line = "AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA";
    let big = std::iter::repeat_n(line, 100).collect::<Vec<_>>().join("\n");
    let truncated = truncate_for_dialog(&big);
    assert!(truncated.starts_with("...\n"), "ellipsis prefix expected");
    assert!(truncated.len() < big.len(), "should be shorter");
    // The body after the ellipsis prefix should start at a line boundary
    // (no leading partial line).
    let body = truncated.strip_prefix("...\n").unwrap();
    assert!(body.starts_with("AAAA"), "body should start at a clean line boundary");
}

#[skuld::test]
fn truncate_for_dialog_over_limit_no_newline_falls_back_to_byte_cut() {
    // Single line that exceeds the budget — there's no newline within the
    // budget, so the function must fall back to a byte-aligned cut.
    let big = "x".repeat(DIALOG_OUTPUT_BUDGET + 500);
    let truncated = truncate_for_dialog(&big);
    assert!(truncated.starts_with("...\n"));
    let body = truncated.strip_prefix("...\n").unwrap();
    assert!(body.chars().all(|c| c == 'x'));
}

#[skuld::test]
fn truncate_for_dialog_never_splits_utf8() {
    // Build a string with a multi-byte char placed exactly at the
    // tentative byte-cut. Function must advance the cut to the next char
    // boundary — checked indirectly by asserting the output is valid UTF-8
    // and contains the cyrillic byte sequence intact.
    let lead = "x".repeat(DIALOG_OUTPUT_BUDGET);
    let trail = "Привет\n".repeat(10);
    let big = format!("{lead}{trail}");
    let truncated = truncate_for_dialog(&big);
    // No assertion required beyond "doesn't panic" — slicing on a non-char
    // boundary in `is_char_boundary`-loop code path is the bug we're
    // guarding against. Additionally check the trailing chars are intact.
    assert!(truncated.contains("Привет"));
}

// SetupError::ExitCode Display ========================================================================================

#[skuld::test]
fn exit_code_display_with_empty_output_no_log() {
    let e = SetupError::ExitCode {
        code: 1,
        output: String::new(),
        log_path: None,
    };
    let rendered = e.to_string();
    assert_eq!(rendered, "elevated process exited with code 1");
}

#[skuld::test]
fn exit_code_display_with_output_no_log() {
    let e = SetupError::ExitCode {
        code: 2,
        output: "first line\nsecond line".into(),
        log_path: None,
    };
    let rendered = e.to_string();
    assert_eq!(
        rendered,
        "elevated process exited with code 2\n\nfirst line\nsecond line"
    );
}

#[skuld::test]
fn exit_code_display_with_log_no_output() {
    let e = SetupError::ExitCode {
        code: 3,
        output: String::new(),
        log_path: Some(PathBuf::from("/tmp/hole-install-XXXX/gui-cli.log")),
    };
    let rendered = e.to_string();
    assert!(
        rendered.contains("elevated process exited with code 3"),
        "got: {rendered}"
    );
    assert!(
        rendered.contains("Full log: /tmp/hole-install-XXXX/gui-cli.log"),
        "got: {rendered}"
    );
}

#[skuld::test]
fn exit_code_display_with_output_and_log() {
    let e = SetupError::ExitCode {
        code: 4,
        output: "some error".into(),
        log_path: Some(PathBuf::from("/tmp/hole-install-XXXX/gui-cli.log")),
    };
    let rendered = e.to_string();
    assert!(rendered.contains("some error"));
    assert!(rendered.contains("Full log: /tmp/hole-install-XXXX/gui-cli.log"));
    // Sanity: no stray double-blank-then-blank artifacts.
    assert!(!rendered.contains("\n\n\n"));
}

#[skuld::test]
fn exit_code_display_with_unicode_output() {
    let e = SetupError::ExitCode {
        code: 5,
        output: "Привет\n世界".into(),
        log_path: None,
    };
    let rendered = e.to_string();
    assert!(rendered.contains("Привет"));
    assert!(rendered.contains("世界"));
}

// macOS AppleScript elevation quoting =================================================================================

#[cfg(target_os = "macos")]
#[skuld::test]
fn applescript_quote_wraps_and_escapes() {
    assert_eq!(applescript_quote("plain"), "\"plain\"");
    assert_eq!(applescript_quote(r#"a"b"#), r#""a\"b""#);
    assert_eq!(applescript_quote(r"a\b"), r#""a\\b""#);
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn build_elevation_script_uses_double_quoted_applescript_literal() {
    let script = build_elevation_script(
        Path::new("/Applications/Hole.app/Contents/MacOS/hole"),
        &["bridge", "install"],
    );
    // A single quote after `do shell script ` is the -2741 "unknown token".
    assert!(
        script.starts_with("do shell script \""),
        "outer literal must be double-quoted, got: {script}"
    );
    assert!(script.ends_with(" with administrator privileges"), "got: {script}");
    assert!(script.contains("'bridge' 'install'"), "got: {script}");
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn build_elevation_script_output_compiles_and_roundtrips_via_osascript() {
    // Feed the shipped function's own output to the real AppleScript compiler,
    // minus the admin suffix so no password prompt appears. /bin/echo + argv
    // with quotes, backslash, and spaces proves both compile and round-trip.
    // The single quote in `a'b` makes shell_escape emit its own `'\''`
    // backslash, so applescript_quote's backslash-doubling is exercised too.
    let args = ["a\"b", "c\\d", "e f", "a'b"];
    let full = build_elevation_script(Path::new("/bin/echo"), &args);
    let script = full
        .strip_suffix(" with administrator privileges")
        .expect("script ends with the admin suffix");
    let out = std::process::Command::new("osascript")
        .args(["-e", script])
        .output()
        .expect("osascript is present on macOS");
    assert!(
        out.status.success(),
        "osascript rejected build_elevation_script output: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim_end_matches('\n'),
        "a\"b c\\d e f a'b"
    );
}

// `bridge uninstall` orchestration ====================================================================================

// bindreams/hole#1003: uninstalling with a fail-closed cover engaged left the
// host blocked with no binary left to release it. The release must therefore
// run after the bridge is dead, run regardless of the teardown's outcome or the
// service registration, and be the failure that aborts.

struct UninstallOutcome {
    result: Result<(), Box<dyn std::error::Error>>,
    steps: Vec<&'static str>,
}

/// The scripted outcome of each injected effect. `installed` is what
/// `is_installed` reports; every other field is the `Result` its step returns.
struct UninstallScript {
    keep_covers: bool,
    stopped: Result<(), Box<dyn std::error::Error>>,
    installed: bool,
    deregister: Result<(), Box<dyn std::error::Error>>,
    release: Result<(), Box<dyn std::error::Error>>,
}

impl Default for UninstallScript {
    /// The nominal uninstall: a registered service that stops, deregisters and
    /// releases cleanly. Tests override the one field they are about.
    fn default() -> Self {
        Self {
            keep_covers: false,
            stopped: Ok(()),
            installed: true,
            deregister: Ok(()),
            release: Ok(()),
        }
    }
}

fn uninstall_probe(script: UninstallScript) -> UninstallOutcome {
    let steps = std::cell::RefCell::new(Vec::new());
    let result = uninstall_bridge_with(
        script.keep_covers,
        || {
            steps.borrow_mut().push("stop");
            script.stopped
        },
        || script.installed,
        || {
            steps.borrow_mut().push("deregister");
            script.deregister
        },
        || {
            steps.borrow_mut().push("release");
            script.release
        },
    );
    UninstallOutcome {
        result,
        steps: steps.into_inner(),
    }
}

#[skuld::test]
fn uninstall_stops_then_deregisters_then_releases_covers() {
    let out = uninstall_probe(UninstallScript::default());

    assert!(out.result.is_ok());
    assert_eq!(
        out.steps,
        vec!["stop", "deregister", "release"],
        "an out-of-process release under a live bridge desyncs its cover posture"
    );
}

#[skuld::test]
fn uninstall_stops_the_bridge_even_when_the_service_is_not_registered() {
    let out = uninstall_probe(UninstallScript {
        installed: false,
        deregister: Err("must never be called".into()),
        ..Default::default()
    });

    assert!(out.result.is_ok(), "an absent service is not an uninstall failure");
    assert_eq!(
        out.steps,
        vec!["stop", "release"],
        "a running bridge and a registration record are independent: a lost record must not \
         skip the stop, or nothing ever stops the bridge again (#1003)"
    );
}

/// `DeleteService` against a live service succeeds by marking the row for
/// deletion, and the bridge keeps the liveness lock the release needs. Keeping
/// the registration over an unconfirmed stop is what leaves a retry something
/// to work with.
#[skuld::test]
fn uninstall_never_deregisters_over_an_unconfirmed_stop() {
    let out = uninstall_probe(UninstallScript {
        stopped: Err("service is still STOP_PENDING".into()),
        deregister: Err("must never be called: deleting the registration strands the bridge".into()),
        ..Default::default()
    });

    assert!(out.result.is_err(), "the stop failure still surfaces");
    assert_eq!(
        out.steps,
        vec!["stop", "release"],
        "the registration is the only handle a retry has"
    );
}

#[skuld::test]
fn uninstall_releases_covers_even_when_the_deregister_fails() {
    let out = uninstall_probe(UninstallScript {
        deregister: Err("service delete failed".into()),
        ..Default::default()
    });

    assert!(out.result.is_err(), "the deregister failure still surfaces");
    assert_eq!(
        out.steps,
        vec!["stop", "deregister", "release"],
        "an undeletable service must not strand the firewall behind it"
    );
}

#[skuld::test]
fn uninstall_fails_loud_when_the_release_fails() {
    let out = uninstall_probe(UninstallScript {
        release: Err("cannot release".into()),
        ..Default::default()
    });

    assert!(
        out.result.is_err(),
        "a failed release must abort before RemoveFiles deletes the only binary that could retry it"
    );
}

/// An early `?` on the release swallowed whatever went wrong before it, which
/// is exactly the context needed to explain why the release refused.
#[skuld::test]
fn uninstall_reports_every_failed_step_not_just_the_last() {
    let out = uninstall_probe(UninstallScript {
        stopped: Err("bootout refused".into()),
        release: Err("a bridge instance is running".into()),
        ..Default::default()
    });

    let report = out.result.expect_err("both steps failed").to_string();
    assert!(report.contains("bootout refused"), "{report}");
    assert!(report.contains("a bridge instance is running"), "{report}");
}

#[skuld::test]
fn uninstall_keep_covers_tears_down_without_releasing() {
    let out = uninstall_probe(UninstallScript {
        keep_covers: true,
        release: Err("must never be called".into()),
        ..Default::default()
    });

    assert!(out.result.is_ok());
    assert_eq!(
        out.steps,
        vec!["stop", "deregister"],
        "the MSI's major-upgrade path replaces the service image but must not disarm the kill switch"
    );
}

// Bridge status and what the GUI offers ===============================================================================

const DISABLED_BYS: [Option<DisabledBy>; 3] = [
    None,
    Some(DisabledBy::InterruptedUninstall),
    Some(DisabledBy::Elsewhere),
];

#[skuld::test]
fn status_precedence_is_not_installed_then_running_then_disabled_then_installed() {
    for installed in [false, true] {
        for running in [false, true] {
            for disabled in DISABLED_BYS {
                let status = bridge_install_status_with(|| installed, || running, || disabled);
                // Written out from the rule, not from the code: a service that is not
                // registered is not running or disabled; a running one works, whatever its
                // start type says; a stopped one is disabled only if it says so.
                let expected = if !installed {
                    BridgeInstallStatus::NotInstalled
                } else if running {
                    BridgeInstallStatus::Running
                } else if let Some(by) = disabled {
                    BridgeInstallStatus::Disabled(by)
                } else {
                    BridgeInstallStatus::Installed
                };
                assert_eq!(
                    status, expected,
                    "installed={installed} running={running} disabled={disabled:?}"
                );
            }
        }
    }
}

#[skuld::test]
fn status_probes_only_what_the_answer_before_leaves_open() {
    use std::cell::Cell;
    let (ran, disabled_read) = (Cell::new(false), Cell::new(false));
    bridge_install_status_with(
        || false,
        || {
            ran.set(true);
            false
        },
        || {
            disabled_read.set(true);
            None
        },
    );
    assert!(
        !ran.get() && !disabled_read.get(),
        "nothing is asked about a service that is not there"
    );

    bridge_install_status_with(
        || true,
        || true,
        || {
            disabled_read.set(true);
            None
        },
    );
    assert!(!disabled_read.get(), "a running service's start type is never read");
}

#[skuld::test]
fn install_prompt_per_variant() {
    use BridgeInstallStatus::*;
    assert_eq!(NotInstalled.install_prompt(), Some(InstallPrompt::Install));
    assert_eq!(
        Disabled(DisabledBy::InterruptedUninstall).install_prompt(),
        Some(InstallPrompt::Repair)
    );
    assert_eq!(
        Disabled(DisabledBy::Elsewhere).install_prompt(),
        Some(InstallPrompt::Enable)
    );
    assert_eq!(Installed.install_prompt(), None);
    assert_eq!(Running.install_prompt(), None);
}

#[skuld::test]
fn each_prompt_text_carries_its_own_words() {
    let repair = "an interrupted uninstall left hole's service disabled";
    let enable = "the hole service is disabled on this computer";
    for (prompt, own, other) in [
        (InstallPrompt::Repair, repair, enable),
        (InstallPrompt::Enable, enable, repair),
    ] {
        for text in [prompt.body(), prompt.unattended_error(), prompt.declined_error()] {
            assert!(text.to_lowercase().contains(own), "{prompt:?}: {text}");
            assert!(!text.to_lowercase().contains(other), "{prompt:?}: {text}");
        }
    }
    // The install's words are the ones the gate always had.
    assert!(InstallPrompt::Install.body().contains("not installed"));
    assert!(InstallPrompt::Install.unattended_error().contains("not installed"));
    // Three prompts, three buttons, three titles: none shows another's.
    let all = [InstallPrompt::Install, InstallPrompt::Repair, InstallPrompt::Enable];
    let confirms: std::collections::BTreeSet<_> = all.map(InstallPrompt::confirm_label).into();
    assert_eq!(confirms, ["Enable", "Install", "Repair"].into());
    let titles: std::collections::BTreeSet<_> = all.map(InstallPrompt::title).into();
    assert_eq!(titles.len(), 3);
}

#[skuld::test]
fn every_prompt_has_a_failure_headline_naming_what_failed() {
    assert!(InstallPrompt::Install
        .failure_headline()
        .to_lowercase()
        .contains("install"));
    assert!(InstallPrompt::Repair
        .failure_headline()
        .to_lowercase()
        .contains("repair"));
    assert!(InstallPrompt::Enable
        .failure_headline()
        .to_lowercase()
        .contains("enable"));
}

#[skuld::test]
fn the_elevated_run_per_prompt_is_install_install_enable_and_only_install_reclaims_the_data_dir() {
    let args = |prompt, repair| elevated_bridge_args(prompt, "LOG", repair);
    let install = [
        "bridge",
        "install",
        "--log-dir",
        "LOG",
        "--repair-user-data-dir",
        "DATA",
    ];
    assert_eq!(args(InstallPrompt::Install, Some("DATA")), install);
    assert_eq!(
        args(InstallPrompt::Install, None),
        ["bridge", "install", "--log-dir", "LOG"]
    );
    // A repair re-registers the service: the same run as the install.
    assert_eq!(args(InstallPrompt::Repair, Some("DATA")), install);
    // Enable edits the one registration it finds; the data dir is not its business.
    assert_eq!(
        args(InstallPrompt::Enable, Some("DATA")),
        ["bridge", "enable", "--log-dir", "LOG"]
    );
}

// `bridge install` orchestration ======================================================================================

// An administrator's Disabled start type survives a reinstall (the service is
// deleted and recreated, so it is read first), an interrupted uninstall's does
// not, and an install over the first still succeeds so the MSI's custom action
// does not fail on it.

type StepLog = std::cell::RefCell<Vec<String>>;

/// The scripted outcome of each injected effect of `install_bridge_with`.
struct InstallScript {
    disabled_by: std::io::Result<Option<DisabledBy>>,
    installed: bool,
    repair: std::io::Result<RepairStep>,
    register: Result<(), &'static str>,
    start: Result<(), &'static str>,
}

impl Default for InstallScript {
    /// A first install: nothing registered, nothing to repair.
    fn default() -> Self {
        Self {
            disabled_by: Ok(None),
            installed: false,
            repair: Ok(RepairStep::Nothing),
            register: Ok(()),
            start: Ok(()),
        }
    }
}

fn install_probe(script: InstallScript) -> (Result<(), Box<dyn std::error::Error>>, Vec<String>) {
    let steps: StepLog = std::cell::RefCell::new(Vec::new());
    let note = |step: &str| steps.borrow_mut().push(step.to_string());
    let result = install_bridge_with(
        || {
            note("disabled_by");
            script.disabled_by
        },
        || {
            note("is_installed");
            script.installed
        },
        || {
            note("stop");
            Ok(())
        },
        || {
            note("deregister");
            Ok(())
        },
        |start| {
            note(&format!("register({start:?})"));
            script.register.map_err(Into::into)
        },
        || {
            note("repair");
            script.repair
        },
        || {
            note("start");
            script.start.map_err(Into::into)
        },
    );
    (result, steps.into_inner())
}

#[skuld::test]
fn a_first_install_registers_automatic_repairs_and_starts() {
    let (result, steps) = install_probe(InstallScript::default());
    assert!(result.is_ok());
    assert_eq!(
        steps,
        ["disabled_by", "is_installed", "register(Automatic)", "repair", "start"]
    );
}

#[skuld::test]
fn a_reinstall_stops_and_deregisters_first_and_repairs_between_the_registration_and_the_start() {
    let (result, steps) = install_probe(InstallScript {
        installed: true,
        ..InstallScript::default()
    });
    assert!(result.is_ok());
    assert_eq!(
        steps,
        [
            "disabled_by",
            "is_installed",
            "stop",
            "deregister",
            "register(Automatic)",
            "repair",
            "start"
        ]
    );
}

#[skuld::test]
fn a_service_an_administrator_disabled_is_registered_disabled_not_started_and_the_install_succeeds() {
    let (result, steps) = install_probe(InstallScript {
        disabled_by: Ok(Some(DisabledBy::Elsewhere)),
        installed: true,
        repair: Ok(RepairStep::LeaveDisabled),
        ..InstallScript::default()
    });
    // Ok: the MSI's custom action fails the install on a nonzero exit.
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        steps,
        [
            "disabled_by",
            "is_installed",
            "stop",
            "deregister",
            "register(LeaveDisabled)",
            "repair",
        ],
        "the Disabled start type is read before the delete, and the service is never started"
    );
}

#[skuld::test]
fn a_service_an_interrupted_uninstall_disabled_is_registered_automatic_and_started() {
    let (result, steps) = install_probe(InstallScript {
        disabled_by: Ok(Some(DisabledBy::InterruptedUninstall)),
        installed: true,
        ..InstallScript::default()
    });
    assert!(result.is_ok());
    assert!(steps.contains(&"register(Automatic)".to_string()), "{steps:?}");
    assert_eq!(steps.last().map(String::as_str), Some("start"));
}

#[skuld::test]
fn a_start_type_that_cannot_be_read_fails_the_install_before_the_service_changes() {
    let (result, steps) = install_probe(InstallScript {
        disabled_by: Err(std::io::Error::other("injected")),
        installed: true,
        ..InstallScript::default()
    });
    let message = result
        .expect_err("guessing not-disabled would re-enable an administrator's choice")
        .to_string();
    assert!(message.contains("injected"), "{message}");
    // The service is what the install leaves alone; `prepare_ipc_access` has
    // already run, so the message must not claim the install changed nothing.
    assert!(message.contains("the service was not changed"), "{message}");
    assert_eq!(steps, ["disabled_by"]);
}

#[skuld::test]
fn a_failed_registration_or_repair_or_start_is_the_installs_failure() {
    let (result, steps) = install_probe(InstallScript {
        register: Err("registration failed"),
        ..InstallScript::default()
    });
    assert!(result.is_err());
    assert_eq!(steps.last().map(String::as_str), Some("register(Automatic)"));

    let (result, steps) = install_probe(InstallScript {
        repair: Err(std::io::Error::other("repair failed")),
        ..InstallScript::default()
    });
    assert!(result.is_err());
    assert_eq!(steps.last().map(String::as_str), Some("repair"));

    let (result, _) = install_probe(InstallScript {
        start: Err("start failed"),
        ..InstallScript::default()
    });
    assert!(result.is_err());
}

#[skuld::test]
fn the_service_is_started_exactly_when_the_repair_says_it_may_be() {
    for step in [
        RepairStep::Nothing,
        RepairStep::ClearRecordOnly,
        RepairStep::ResetThenClear,
        RepairStep::LeaveDisabled,
    ] {
        let (result, steps) = install_probe(InstallScript {
            repair: Ok(step),
            ..InstallScript::default()
        });
        assert!(result.is_ok(), "{step:?}");
        assert_eq!(steps.contains(&"start".to_string()), step.starts_service(), "{step:?}");
    }
}

// Uninstall wiring ====================================================================================================
//
// Everything above drives `uninstall_bridge_with` through injected closures, so
// all of it stays green if the production wiring is severed — the release
// replaced by `Ok(())`, the CLI arm returning `0` without dispatching. That is
// the whole failure this change is about: the path where severing it leaves a
// machine fail-closed with its only escape binary deleted (#1003).
//
// So walk the sources and pin WHO calls the real effects, the same instrument
// `crates/bridge/src/reconciler_tests.rs` uses for the cover-release callers.
// Set equality, keyed on the enclosing `fn`: a call that disappears fails the
// guard just as loudly as one that appears.

/// A walked call site as (path relative to `src/`, enclosing function name).
type CallSite = (String, String);

/// Every `pattern` match under `crates/hole/src`, attributed to the function
/// that lexically encloses it. Skips `*_tests.rs` — the injected-closure tests
/// are exactly what this guard exists to look past.
fn production_call_sites(pattern: &regex::Regex) -> std::collections::BTreeSet<CallSite> {
    let decl = regex::Regex::new(
        r#"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:default\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+"[^"]*"\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)"#,
    )
    .expect("fn-declaration regex must compile");
    let src_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    let mut found = std::collections::BTreeSet::new();
    for entry in walkdir::WalkDir::new(&src_root) {
        let entry = entry.expect("failed to walk crates/hole/src");
        let path = entry.path();
        if !entry.file_type().is_file() || path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if file_name.ends_with("_tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(path).expect("failed to read a walked source file");
        let lines: Vec<&str> = text.lines().collect();
        let rel = path
            .strip_prefix(&src_root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        for (idx, line) in lines.iter().enumerate() {
            if !pattern.is_match(line) {
                continue;
            }
            let func = (0..=idx)
                .rev()
                .find_map(|i| decl.captures(lines[i]).map(|c| c[1].to_string()))
                .unwrap_or_else(|| "<no enclosing fn>".to_string());
            found.insert((rel.clone(), func));
        }
    }
    found
}

fn expected_sites(sites: &[(&str, &str)]) -> std::collections::BTreeSet<CallSite> {
    sites
        .iter()
        .map(|(f, n)| ((*f).to_string(), (*n).to_string()))
        .collect()
}

/// The seam the injected-closure tests cannot see: `uninstall_bridge` must hand
/// `uninstall_bridge_with` the REAL cover release, and `bridge release-covers`
/// must actually dispatch to it. `cli_tests.rs` asserts the flag parses; only
/// this asserts the parsed command reaches the release.
#[skuld::test]
fn the_cover_release_is_wired_to_both_of_its_entry_points() {
    let pattern = regex::Regex::new(r"\brelease_covers\s*\(").expect("regex must compile");

    assert_eq!(
        production_call_sites(&pattern),
        expected_sites(&[
            ("setup.rs", "uninstall_bridge"), // `hole bridge uninstall`, and the tray's Uninstall Helper.
            ("cli.rs", "handle_bridge"),      // `hole bridge release-covers`, the MSI's BridgeRelease CA.
        ]),
        "`cutover::release_covers` is the only thing that can clear a persistent WFP filter before \
         the binary is deleted (#1003). A call site that vanished here is a silent no-op on a \
         fail-closed host; a new one is an unreviewed release path."
    );
}

/// The other half of #1003's dead end: the stop must not be conditional on a
/// registration record. A severed `ensure_stopped` leaves nothing stopping the
/// bridge, and the release then refuses forever.
#[skuld::test]
fn the_bridge_stop_is_wired_ahead_of_every_deregistration() {
    let pattern = regex::Regex::new(r"\bensure_stopped\s*\(").expect("regex must compile");

    assert_eq!(
        production_call_sites(&pattern),
        expected_sites(&[
            ("setup.rs", "install_bridge"),      // reinstall: stop before replacing the image.
            ("setup.rs", "install_bridge_with"), // the injected effect's own invocation, as below.
            ("setup.rs", "uninstall_bridge"),    // uninstall: stop before deregistering.
            // The injected effect's own invocation, which shares the name. Worth
            // pinning rather than pattern-matching away: a body that stopped
            // calling it would leave `uninstall_bridge`'s wiring intact and dead.
            ("setup.rs", "uninstall_bridge_with"),
        ]),
        "`platform::os::ensure_stopped` is what makes the stop independent of `is_installed`"
    );
}
