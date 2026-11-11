use super::layout_stamp::StampState;
use super::*;
use util::versioned_file::{CannotRead, WhyUnreadable};

const EX_RAY: [u8; 32] = [1; 32];
const GALOSHES: [u8; 32] = [2; 32];

fn carried() -> Vec<Carried<'static>> {
    vec![
        Carried {
            name: "ex-ray",
            sha256: Some(EX_RAY),
        },
        Carried {
            name: "galoshes",
            sha256: Some(GALOSHES),
        },
    ]
}

fn without_payload(name: &str) -> Vec<Carried<'static>> {
    carried()
        .into_iter()
        .map(|c| Carried {
            sha256: if c.name == name { None } else { c.sha256 },
            ..c
        })
        .collect()
}

fn entry(name: &str, found: Found) -> (String, Found) {
    (name.to_owned(), found)
}

fn sound(record: StampState, entries: Vec<(String, Found)>) -> Survey {
    Survey::SoundDir {
        record,
        mode_right: true,
        entries,
    }
}

fn both(ex_ray: Found, galoshes: Found) -> Vec<(String, Found)> {
    vec![entry("ex-ray", ex_ray), entry("galoshes", galoshes)]
}

fn write(name: &str) -> Step {
    Step::Write(name.to_owned())
}

fn remove(name: &str) -> Step {
    Step::Remove(name.to_owned())
}

#[skuld::test]
fn a_missing_folder_is_created_written_and_stamped_last() {
    let plan = decide_repair(&Survey::NoDir, &carried());

    assert_eq!(
        plan.steps,
        [Step::CreateDir, write("ex-ray"), write("galoshes"), Step::StoreRecord]
    );
    assert!(plan.notes.is_empty());
}

#[skuld::test]
fn a_missing_folder_with_a_payloadless_plugin_writes_the_other_and_says_so() {
    let plan = decide_repair(&Survey::NoDir, &without_payload("galoshes"));

    assert_eq!(plan.steps, [Step::CreateDir, write("ex-ray"), Step::StoreRecord]);
    assert_eq!(plan.notes, [Note::NoPayload("galoshes".to_owned())]);
}

#[skuld::test]
fn an_unsound_folder_is_rebuilt_then_written_then_stamped() {
    let plan = decide_repair(&Survey::UnsoundDir, &carried());

    assert_eq!(
        plan.steps,
        [Step::RebuildDir, write("ex-ray"), write("galoshes"), Step::StoreRecord]
    );
}

#[skuld::test]
fn an_unsound_folder_is_left_alone_when_any_plugin_has_no_payload() {
    let plan = decide_repair(&Survey::UnsoundDir, &without_payload("ex-ray"));

    assert!(plan.steps.is_empty(), "{:?}", plan.steps);
    assert_eq!(
        plan.notes,
        [Note::DirLeftAlone, Note::NoPayload("ex-ray".to_owned())],
        "a build with no payload never removes what is on disk"
    );
}

#[skuld::test]
fn a_sound_folder_each_found_by_payload_cell() {
    // (found, has a payload) -> steps for that one plugin and the notes it raises.
    let no_payload = || vec![Note::NoPayload("ex-ray".to_owned())];
    let rows: [(Found, bool, Vec<Step>, Vec<Note>); 7] = [
        (Found::Missing, true, vec![write("ex-ray")], vec![]),
        (Found::Missing, false, vec![], no_payload()),
        (Found::Matches, true, vec![], vec![]),
        (Found::Differs, true, vec![write("ex-ray")], vec![]),
        (Found::Differs, false, vec![], no_payload()),
        (Found::Blocked, true, vec![remove("ex-ray"), write("ex-ray")], vec![]),
        (Found::Blocked, false, vec![], no_payload()),
    ];
    for (found, has_payload, steps, notes) in rows {
        let carried = vec![Carried {
            name: "ex-ray",
            sha256: has_payload.then_some(EX_RAY),
        }];

        let plan = decide_repair(&sound(StampState::Current, vec![entry("ex-ray", found)]), &carried);

        assert_eq!(plan.steps, steps, "{found:?} payload={has_payload}");
        assert_eq!(plan.notes, notes, "{found:?} payload={has_payload}");
    }
}

#[skuld::test]
fn unexpected_entries_are_removed_after_the_writes_and_before_the_stamp() {
    let mut entries = both(Found::Differs, Found::Matches);
    entries.push(entry(".ex-ray.7.0.tmp", Found::Unexpected));

    let plan = decide_repair(&sound(StampState::Nothing, entries), &carried());

    assert_eq!(
        plan.steps,
        [write("ex-ray"), remove(".ex-ray.7.0.tmp"), Step::StoreRecord]
    );
}

#[skuld::test]
fn a_sound_folder_with_the_wrong_mode_is_secured_before_anything_else() {
    let mut entries = both(Found::Differs, Found::Matches);
    entries.push(entry("stray", Found::Unexpected));
    let survey = Survey::SoundDir {
        record: StampState::Nothing,
        mode_right: false,
        entries,
    };

    let plan = decide_repair(&survey, &carried());

    assert_eq!(
        plan.steps,
        [Step::SecureDir, write("ex-ray"), remove("stray"), Step::StoreRecord]
    );
}

#[skuld::test]
fn a_sound_folder_with_the_right_mode_is_not_secured() {
    let plan = decide_repair(
        &sound(StampState::Current, both(Found::Matches, Found::Matches)),
        &carried(),
    );

    assert!(plan.steps.is_empty(), "{:?}", plan.steps);
}

#[skuld::test]
fn a_record_this_release_cannot_read_leaves_even_the_folder_mode_alone() {
    let why = WhyUnreadable::CannotRead(CannotRead::Newer);
    let survey = Survey::SoundDir {
        record: StampState::Unreadable(why),
        mode_right: false,
        entries: both(Found::Matches, Found::Matches),
    };

    let plan = decide_repair(&survey, &carried());

    assert!(plan.steps.is_empty(), "{:?}", plan.steps);
}

#[skuld::test]
fn the_record_is_stored_for_nothing_and_not_for_a_current_one() {
    for (record, stores) in [(StampState::Nothing, true), (StampState::Current, false)] {
        let plan = decide_repair(&sound(record, both(Found::Matches, Found::Matches)), &carried());

        assert_eq!(plan.steps.contains(&Step::StoreRecord), stores, "{record:?}");
    }
}

#[skuld::test]
fn a_record_this_release_cannot_read_makes_the_whole_plan_empty() {
    for why in [
        WhyUnreadable::CannotRead(CannotRead::Newer),
        WhyUnreadable::CannotRead(CannotRead::Corrupt),
        WhyUnreadable::ReadFailed(std::io::ErrorKind::PermissionDenied),
    ] {
        // Everything else is wrong too: nothing is touched, whatever the files hold.
        let mut entries = both(Found::Differs, Found::Missing);
        entries.push(entry("stray", Found::Unexpected));

        let plan = decide_repair(&sound(StampState::Unreadable(why), entries), &carried());

        assert!(plan.steps.is_empty(), "{why:?}: {:?}", plan.steps);
        assert_eq!(plan.notes, [Note::RecordRefused(why)], "{why:?}");
    }
}

#[skuld::test]
fn embedded_plugin_carries_a_hash_only_when_it_has_bytes() {
    let with = EmbeddedPlugin {
        name: "ex-ray",
        bytes: b"abc",
        sha256: [9; 32],
    };
    let without = EmbeddedPlugin {
        name: "galoshes",
        bytes: b"",
        sha256: [0; 32],
    };

    assert_eq!(with.carried().sha256, Some([9; 32]));
    assert_eq!(without.carried().sha256, None);
}

#[skuld::test]
fn the_outcome_of_a_repair_logs_at_the_level_its_kind_decides() {
    use tracing::Level;
    let cases = [
        (RepairOutcome::Converged, Level::DEBUG),
        (RepairOutcome::Repaired { steps: 1 }, Level::INFO),
        (
            RepairOutcome::Degraded {
                notes: vec![],
                failures: vec!["x".to_owned()],
            },
            Level::ERROR,
        ),
        (
            RepairOutcome::Refused(WhyUnreadable::CannotRead(CannotRead::Newer)),
            Level::ERROR,
        ),
    ];
    for (outcome, level) in cases {
        assert_eq!(outcome.level(), level, "{outcome:?}");
    }
}

#[skuld::test]
fn the_outcome_of_a_plan_is_refused_before_degraded_before_repaired_before_converged() {
    let newer = WhyUnreadable::CannotRead(CannotRead::Newer);
    let plan = |steps: Vec<Step>, notes: Vec<Note>| RepairPlan { steps, notes };

    assert_eq!(
        RepairOutcome::of(&plan(vec![], vec![]), vec![]),
        RepairOutcome::Converged
    );
    assert_eq!(
        RepairOutcome::of(&plan(vec![Step::StoreRecord, write("a")], vec![]), vec![]),
        RepairOutcome::Repaired { steps: 2 }
    );
    assert!(matches!(
        RepairOutcome::of(&plan(vec![Step::StoreRecord], vec![]), vec!["boom".to_owned()]),
        RepairOutcome::Degraded { .. }
    ));
    assert!(matches!(
        RepairOutcome::of(&plan(vec![], vec![Note::NoPayload("a".to_owned())]), vec![]),
        RepairOutcome::Degraded { .. }
    ));
    assert_eq!(
        RepairOutcome::of(
            &plan(
                vec![],
                vec![Note::NoPayload("a".to_owned()), Note::RecordRefused(newer)]
            ),
            vec!["boom".to_owned()]
        ),
        RepairOutcome::Refused(newer)
    );
}

fn newer() -> WhyUnreadable {
    WhyUnreadable::CannotRead(CannotRead::Newer)
}

fn degraded() -> RepairOutcome {
    RepairOutcome::Degraded {
        notes: vec![],
        failures: vec!["write ex-ray: disk full".to_owned()],
    }
}

fn not_made() -> std::io::Result<()> {
    Err(std::io::Error::other("runtime boom"))
}

#[skuld::test]
fn only_a_folder_repaired_and_a_runtime_folder_made_let_plugins_run() {
    // Each cell of (how the folder repair went, whether the runtime folder was made) is its own expectation.
    assert_eq!(
        Prepared::new(RepairOutcome::Converged, Ok(())).standing(),
        Standing::Vouched
    );
    assert_eq!(
        Prepared::new(RepairOutcome::Repaired { steps: 3 }, Ok(())).standing(),
        Standing::Vouched
    );
    assert_eq!(
        Prepared::new(degraded(), Ok(())).standing(),
        Standing::FolderNotRepaired
    );
    assert_eq!(
        Prepared::new(RepairOutcome::Refused(newer()), Ok(())).standing(),
        Standing::StampUnreadable(newer())
    );
    assert_eq!(
        Prepared::new(RepairOutcome::Converged, not_made()).standing(),
        Standing::RuntimeDirNotMade
    );
    assert_eq!(
        Prepared::new(RepairOutcome::Repaired { steps: 3 }, not_made()).standing(),
        Standing::RuntimeDirNotMade
    );
    // Both failed: the folder is what is named, and the runtime folder's failure is still logged.
    assert_eq!(
        Prepared::new(degraded(), not_made()).standing(),
        Standing::FolderNotRepaired
    );
    assert_eq!(
        Prepared::new(RepairOutcome::Refused(newer()), not_made()).standing(),
        Standing::StampUnreadable(newer())
    );
}

#[skuld::test]
fn a_verdict_before_any_repair_refuses_and_a_recorded_one_answers_as_its_preparation() {
    let verdict = RepairVerdict::default();

    assert_eq!(verdict.standing(), Standing::NotPrepared);

    verdict.record(Prepared::new(RepairOutcome::Converged, Ok(())));

    assert_eq!(verdict.standing(), Standing::Vouched);
}

#[skuld::test]
fn a_verdict_is_shared_by_its_clones() {
    let verdict = RepairVerdict::default();
    let reader = verdict.clone();

    verdict.record(Prepared::new(RepairOutcome::Converged, Ok(())));

    assert_eq!(reader.standing(), Standing::Vouched);
}

#[skuld::test]
fn a_preparation_logs_the_folders_outcome_and_the_runtime_folders_failure_both() {
    use crate::test_support::log_capture::VecWriter;
    use tracing_subscriber::fmt;

    let cases = [RepairOutcome::Converged, degraded(), RepairOutcome::Refused(newer())];
    for folder in cases {
        let writer = VecWriter::new();
        let subscriber = fmt().with_writer(writer.clone()).with_ansi(false).finish();
        {
            let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
            Prepared::new(folder.clone(), not_made()).log();
        }

        let logged = writer.snapshot_string();
        assert!(logged.contains("runtime boom"), "{folder:?}: {logged}");
        match &folder {
            RepairOutcome::Converged => {}
            RepairOutcome::Degraded { .. } => assert!(logged.contains("disk full"), "{folder:?}: {logged}"),
            RepairOutcome::Refused(_) => assert!(logged.contains("layout file"), "{folder:?}: {logged}"),
            RepairOutcome::Repaired { .. } => unreachable!("not a case"),
        }
    }
}
