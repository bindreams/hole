use super::*;
use std::sync::Arc;

// ImportFlow ==========================================================================================================

#[skuld::test]
fn picker_is_claimable_when_no_dialog_is_open() {
    let picker = Arc::new(ImportFlow::default());
    assert!(picker.claim_picker().is_some());
}

#[skuld::test]
fn picker_refuses_a_second_claim_while_one_is_held() {
    // Clicking Import again while the file picker is up must not stack a
    // second picker on top of it.
    let picker = Arc::new(ImportFlow::default());
    let _open = picker.claim_picker().expect("a free picker can be claimed");
    assert!(picker.claim_picker().is_none());
}

#[skuld::test]
fn picker_is_reclaimable_once_the_dialog_closes() {
    // Whatever ended the dialog — a file, a cancel, or a panic on the way
    // out — dropping the claim is what frees it, so no exit path can wedge
    // Import.
    let picker = Arc::new(ImportFlow::default());
    let open = picker.claim_picker().expect("a free picker can be claimed");
    drop(open);
    assert!(picker.claim_picker().is_some());
}

#[skuld::test]
fn a_second_import_waits_for_the_running_one() {
    // Unlike the picker, this one queues rather than refuses: a drop that
    // lands mid-import is a request the user still wants honoured, it just
    // must not raise its dialogs over the running import's.
    let flow = Arc::new(ImportFlow::default());
    let running = flow.running.lock().expect("uncontended");
    assert!(flow.running.try_lock().is_err());
    drop(running);
    assert!(flow.running.try_lock().is_ok());
}

#[skuld::test]
fn a_panic_mid_import_does_not_wedge_the_next_one() {
    // The guard sequences dialogs; it protects no data, so a panic in a
    // previous import must not make every later one unreachable.
    let flow = Arc::new(ImportFlow::default());
    let poisoner = Arc::clone(&flow);
    let _ = std::thread::spawn(move || {
        let _held = poisoner.running.lock().expect("uncontended");
        panic!("import panicked mid-dialog");
    })
    .join();

    assert!(flow.running.is_poisoned(), "the panic must have poisoned it");
    let recovered = flow.running.lock().unwrap_or_else(|e| e.into_inner());
    drop(recovered);
}

// describe_failure ====================================================================================================
//
// Rendering the failure where it happens is what lets the dialog be shown
// at all when no window is listening — and the `match` below is
// exhaustive, so a new `ImportFailure` variant is a compile error rather
// than a silent fallback string.

#[skuld::test]
fn corrupted_json_says_the_file_is_not_valid_json() {
    let m = describe_failure(&ImportFailure::CorruptedJson);
    assert!(m.title.to_lowercase().contains("import"), "{}", m.title);
    assert!(m.body.to_lowercase().contains("not valid json"), "{}", m.body);
}

#[skuld::test]
fn unrecognized_format_names_the_field_hole_looked_for() {
    let m = describe_failure(&ImportFailure::UnrecognizedFormat {
        missing_field: "server (or 'address')".into(),
    });
    assert!(m.title.to_lowercase().contains("import"), "{}", m.title);
    assert!(m.body.to_lowercase().contains("shadowsocks"), "{}", m.body);
    assert!(m.body.contains("server (or 'address')"), "{}", m.body);
}

#[skuld::test]
fn unsupported_plugin_names_the_plugin_and_what_is_bundled() {
    let m = describe_failure(&ImportFailure::UnsupportedPlugin {
        plugin: "kcptun".into(),
        supported: vec!["v2ray-plugin".into(), "galoshes".into()],
    });
    assert!(m.title.to_lowercase().contains("plugin"), "{}", m.title);
    assert!(m.body.contains("kcptun"), "{}", m.body);
    assert!(m.body.contains("v2ray-plugin"), "{}", m.body);
    assert!(m.body.contains("galoshes"), "{}", m.body);
}

#[skuld::test]
fn file_error_surfaces_the_prescrubbed_detail() {
    let m = describe_failure(&ImportFailure::FileError {
        detail: "file not found or not accessible".into(),
    });
    assert!(m.body.contains("file not found or not accessible"), "{}", m.body);
}

#[skuld::test]
fn invalid_value_surfaces_the_detail() {
    let m = describe_failure(&ImportFailure::InvalidValue {
        detail: "server_port 99999 out of range".into(),
    });
    assert!(m.title.to_lowercase().contains("import"), "{}", m.title);
    assert!(m.body.contains("99999"), "{}", m.body);
}

#[skuld::test]
fn save_failed_points_at_gui_log() {
    let m = describe_failure(&ImportFailure::SaveFailed);
    let title = m.title.to_lowercase();
    assert!(title.contains("save") || title.contains("import"), "{}", m.title);
    assert!(m.body.to_lowercase().contains("gui.log"), "{}", m.body);
}

#[skuld::test]
fn a_described_failure_carries_no_path_or_file_content() {
    // The body is what the user sees, and what lands in a screenshot or a
    // support thread. Only pre-scrubbed `detail` fields reach it; the
    // variants that could have carried the file's path or its contents
    // carry neither, so there is nothing for the wording to leak.
    for failure in [
        ImportFailure::CorruptedJson,
        ImportFailure::SaveFailed,
        ImportFailure::UnrecognizedFormat {
            missing_field: "server".into(),
        },
    ] {
        let m = describe_failure(&failure);
        assert!(!m.body.contains('/'), "a path separator reached the dialog: {}", m.body);
        assert!(
            !m.body.to_lowercase().contains("secret") && !m.body.contains("password"),
            "{}",
            m.body
        );
    }
}

// aggregate ===========================================================================================================

#[skuld::test]
fn aggregate_accumulates_servers_across_files() {
    // Two files, both fine: every server from both must reach the outcome,
    // not just the last file's.
    let outcome = aggregate([Ok(vec![entry("a")]), Ok(vec![entry("b"), entry("c")])], |_| {
        panic!("no failures expected")
    });
    assert_eq!(ids(&outcome), ["a", "b", "c"]);
    assert_eq!(outcome.failed, 0);
}

#[skuld::test]
fn aggregate_counts_every_failure_and_keeps_the_successes() {
    // A failing file must not cost the servers imported either side of it.
    let mut reported = Vec::new();
    let outcome = aggregate(
        [
            Ok(vec![entry("a")]),
            Err(ImportFailure::CorruptedJson),
            Ok(vec![entry("b")]),
            Err(ImportFailure::SaveFailed),
        ],
        |failure| reported.push(format!("{failure:?}")),
    );
    assert_eq!(ids(&outcome), ["a", "b"]);
    assert_eq!(outcome.failed, 2);
    assert_eq!(reported.len(), 2, "each failure is reported once, as it happens");
}

#[skuld::test]
fn aggregate_of_nothing_is_empty() {
    let outcome = aggregate(Vec::new(), |_| panic!("no failures expected"));
    assert!(outcome.appended.is_empty());
    assert_eq!(outcome.failed, 0);
}

// ImportOutcome =======================================================================================================

#[skuld::test]
fn outcome_serializes_to_the_shape_the_dashboard_reads() {
    let json = serde_json::to_value(ImportOutcome {
        appended: Vec::new(),
        failed: 2,
    })
    .expect("outcome serializes");
    assert_eq!(json["appended"], serde_json::json!([]));
    assert_eq!(json["failed"], 2);
}

#[skuld::test]
fn servers_imported_event_name_matches_the_frontend() {
    // The emit and the `listen()` sit on opposite sides of the IPC boundary
    // with no shared definition. Losing it costs only a stale list until the
    // next config load — but a rename would still silently stop the
    // dashboard refreshing.
    let main_ts = include_str!("../../../ui/main.ts");
    assert!(
        main_ts.contains(&format!("\"{EVENT_SERVERS_IMPORTED}\"")),
        "ui/main.ts must listen for {EVENT_SERVERS_IMPORTED:?}"
    );
}

/// A minimal server entry — `aggregate` only ever moves these around.
fn entry(id: &str) -> ServerEntry {
    ServerEntry {
        id: id.to_string(),
        ..ServerEntry::default_placeholder()
    }
}

fn ids(outcome: &ImportOutcome) -> Vec<&str> {
    outcome.appended.iter().map(|s| s.id.as_str()).collect()
}
