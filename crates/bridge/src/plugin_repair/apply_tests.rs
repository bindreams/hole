//! The apply half runs in a temp folder as the test user: `owner` is the folder's own, so nothing needs root.

use super::*;
use crate::plugin_repair::layout_stamp::{self, StampState};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use util::versioned_file::{CannotRead, WhyUnreadable};

const EX_RAY_BYTES: &[u8] = b"ex-ray fixture bytes";
const GALOSHES_BYTES: &[u8] = b"galoshes fixture bytes, a different length";

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    <sha2::Sha256 as sha2::Digest>::digest(bytes).into()
}

fn plugins() -> Vec<EmbeddedPlugin> {
    vec![
        EmbeddedPlugin {
            name: "ex-ray",
            bytes: EX_RAY_BYTES,
            sha256: sha256_of(EX_RAY_BYTES),
        },
        EmbeddedPlugin {
            name: "galoshes",
            bytes: GALOSHES_BYTES,
            sha256: sha256_of(GALOSHES_BYTES),
        },
    ]
}

/// The same two plugins with no payload, as a stub build carries them.
fn payloadless() -> Vec<EmbeddedPlugin> {
    plugins()
        .into_iter()
        .map(|p| EmbeddedPlugin { bytes: b"", ..p })
        .collect()
}

/// A temp folder holding the layout's parent; the plugin folder is `<tmp>/Hole`, not yet made.
struct Fixture {
    tmp: tempfile::TempDir,
    layout: PluginDirLayout,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let mut layout = PluginDirLayout::owned_by_this_process(tmp.path());
        layout.dir = tmp.path().join("Hole");
        Self { tmp, layout }
    }

    fn dir(&self) -> &Path {
        &self.layout.dir
    }

    fn listing(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn make_sound_dir(&self) {
        fs::create_dir(self.dir()).unwrap();
        fs::set_permissions(self.dir(), fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Whether the volume holding the plugin folder reads two names that differ only in case as one entry (macOS's
    /// default). Needs the folder to exist; a stat error panics rather than reading as "case-sensitive".
    fn volume_folds_case(&self) -> bool {
        let probe = self.dir().join("case-probe");
        fs::write(&probe, b"").unwrap();
        let folds = self.dir().join("CASE-PROBE").try_exists().unwrap();
        fs::remove_file(probe).unwrap();
        folds
    }

    fn put(&self, name: &str, bytes: &[u8], mode: u32) {
        fs::write(self.dir().join(name), bytes).unwrap();
        fs::set_permissions(self.dir().join(name), fs::Permissions::from_mode(mode)).unwrap();
    }
}

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).unwrap().mode() & 0o7777
}

#[skuld::test]
fn a_fresh_folder_gets_every_plugin_0755_and_the_stamp_and_nothing_else() {
    let fx = Fixture::new();

    let outcome = repair(&fx.layout, &plugins());

    assert!(matches!(outcome, RepairOutcome::Repaired { .. }), "{outcome:?}");
    assert_eq!(fx.listing(), ["ex-ray", "galoshes", "layout.json"]);
    assert_eq!(fs::read(fx.dir().join("ex-ray")).unwrap(), EX_RAY_BYTES);
    assert_eq!(fs::read(fx.dir().join("galoshes")).unwrap(), GALOSHES_BYTES);
    assert_eq!(mode_of(&fx.dir().join("ex-ray")), 0o755);
    assert_eq!(mode_of(&fx.dir().join("galoshes")), 0o755);
    assert_eq!(mode_of(fx.dir()), 0o755);
    assert_eq!(layout_stamp::state(fx.dir()), StampState::Current);
    assert_eq!(fs::metadata(fx.dir().join("ex-ray")).unwrap().uid(), fx.layout.owner.0);
}

#[skuld::test]
fn a_second_repair_changes_nothing_and_keeps_inode_and_mtime() {
    let fx = Fixture::new();
    repair(&fx.layout, &plugins());
    let before: Vec<_> = ["ex-ray", "galoshes", "layout.json"]
        .map(|n| fs::metadata(fx.dir().join(n)).unwrap())
        .into();

    let outcome = repair(&fx.layout, &plugins());

    assert!(matches!(outcome, RepairOutcome::Converged), "{outcome:?}");
    for (name, before) in ["ex-ray", "galoshes", "layout.json"].iter().zip(before) {
        let after = fs::metadata(fx.dir().join(name)).unwrap();
        assert_eq!(
            (after.ino(), after.mtime(), after.mtime_nsec()),
            (before.ino(), before.mtime(), before.mtime_nsec()),
            "{name}"
        );
    }
}

#[skuld::test]
fn a_stale_plugin_is_replaced_and_a_reader_of_the_old_one_still_reads_the_old_bytes() {
    let fx = Fixture::new();
    repair(&fx.layout, &plugins());
    fx.put("ex-ray", b"an older ex-ray", 0o755);
    let mut old = fs::File::open(fx.dir().join("ex-ray")).unwrap();

    let outcome = repair(&fx.layout, &plugins());

    assert!(matches!(outcome, RepairOutcome::Repaired { .. }), "{outcome:?}");
    assert_eq!(fs::read(fx.dir().join("ex-ray")).unwrap(), EX_RAY_BYTES);
    let mut seen = Vec::new();
    std::io::Read::read_to_end(&mut old, &mut seen).unwrap();
    assert_eq!(seen, b"an older ex-ray", "the replace swapped the name, not the file");
}

#[skuld::test]
fn a_plugin_with_the_right_bytes_and_the_wrong_mode_is_rewritten() {
    let fx = Fixture::new();
    repair(&fx.layout, &plugins());
    fs::set_permissions(fx.dir().join("galoshes"), fs::Permissions::from_mode(0o775)).unwrap();

    repair(&fx.layout, &plugins());

    assert_eq!(mode_of(&fx.dir().join("galoshes")), 0o755);
}

#[skuld::test]
fn a_folder_with_contents_at_a_plugin_name_is_replaced_by_the_plugin_and_the_next_repair_converges() {
    let fx = Fixture::new();
    repair(&fx.layout, &plugins());
    fs::remove_file(fx.dir().join("galoshes")).unwrap();
    fs::create_dir_all(fx.dir().join("galoshes").join("inner")).unwrap();
    fs::write(fx.dir().join("galoshes").join("inner").join("file"), b"x").unwrap();

    let outcome = repair(&fx.layout, &plugins());

    assert!(matches!(outcome, RepairOutcome::Repaired { .. }), "{outcome:?}");
    assert_eq!(fx.listing(), ["ex-ray", "galoshes", "layout.json"]);
    assert_eq!(fs::read(fx.dir().join("galoshes")).unwrap(), GALOSHES_BYTES);
    assert!(matches!(repair(&fx.layout, &plugins()), RepairOutcome::Converged));
}

#[skuld::test]
fn a_stray_folder_with_contents_is_removed_and_a_link_inside_it_leaves_its_target() {
    let fx = Fixture::new();
    repair(&fx.layout, &plugins());
    let elsewhere = fx.tmp.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    fs::write(elsewhere.join("keep"), b"theirs").unwrap();
    fs::create_dir_all(fx.dir().join("stray").join("deeper")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, fx.dir().join("stray").join("deeper").join("link")).unwrap();

    let outcome = repair(&fx.layout, &plugins());

    assert!(matches!(outcome, RepairOutcome::Repaired { .. }), "{outcome:?}");
    assert_eq!(fx.listing(), ["ex-ray", "galoshes", "layout.json"]);
    assert_eq!(fs::read(elsewhere.join("keep")).unwrap(), b"theirs");
}

#[skuld::test]
fn a_symlink_at_a_plugin_name_is_replaced_by_the_file_and_its_target_is_untouched() {
    let fx = Fixture::new();
    repair(&fx.layout, &plugins());
    let victim = fx.tmp.path().join("victim");
    fs::write(&victim, b"theirs").unwrap();
    fs::remove_file(fx.dir().join("ex-ray")).unwrap();
    std::os::unix::fs::symlink(&victim, fx.dir().join("ex-ray")).unwrap();

    repair(&fx.layout, &plugins());

    assert_eq!(fs::read(&victim).unwrap(), b"theirs");
    assert!(!fs::symlink_metadata(fx.dir().join("ex-ray"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(fx.dir().join("ex-ray")).unwrap(), EX_RAY_BYTES);
}

#[skuld::test]
fn stale_temp_names_and_extra_entries_are_removed() {
    let fx = Fixture::new();
    repair(&fx.layout, &plugins());
    fx.put(".ex-ray.4242.0.tmp", b"half", 0o600);
    fx.put("kcptun", b"extra", 0o755);

    repair(&fx.layout, &plugins());

    assert_eq!(fx.listing(), ["ex-ray", "galoshes", "layout.json"]);
}

#[skuld::test]
fn an_unsound_folder_is_rebuilt_whichever_way_it_is_unsound() {
    // The folder is group-writable: a stamp planted in it must not be read, and everything in it is replaced.
    let fx = Fixture::new();
    fx.make_sound_dir();
    fx.put("layout.json", br#"{"version": 2}"#, 0o644);
    fx.put("ex-ray", EX_RAY_BYTES, 0o755);
    fs::set_permissions(fx.dir(), fs::Permissions::from_mode(0o775)).unwrap();

    let outcome = repair(&fx.layout, &plugins());

    assert!(matches!(outcome, RepairOutcome::Repaired { .. }), "{outcome:?}");
    assert_eq!(mode_of(fx.dir()), 0o755);
    assert_eq!(fx.listing(), ["ex-ray", "galoshes", "layout.json"]);
    assert_eq!(layout_stamp::state(fx.dir()), StampState::Current);
}

#[skuld::test]
fn an_unsound_folder_holding_a_folder_is_rebuilt_and_converges() {
    let fx = Fixture::new();
    fx.make_sound_dir();
    fs::create_dir_all(fx.dir().join("old").join("deeper")).unwrap();
    fs::write(fx.dir().join("old").join("deeper").join("file"), b"x").unwrap();
    fs::set_permissions(fx.dir(), fs::Permissions::from_mode(0o775)).unwrap();

    let outcome = repair(&fx.layout, &plugins());

    assert!(matches!(outcome, RepairOutcome::Repaired { .. }), "{outcome:?}");
    assert_eq!(fx.listing(), ["ex-ray", "galoshes", "layout.json"]);
    assert!(matches!(repair(&fx.layout, &plugins()), RepairOutcome::Converged));
}

#[skuld::test]
fn a_sound_folder_with_another_mode_is_set_to_0755_and_its_files_are_left_alone() {
    // Not writable by others, so sound; but not what the docs promise.
    for mode in [0o700, 0o711, 0o750, 0o2755, 0o1755] {
        let fx = Fixture::new();
        repair(&fx.layout, &plugins());
        let before = fs::metadata(fx.dir().join("ex-ray")).unwrap().ino();
        fs::set_permissions(fx.dir(), fs::Permissions::from_mode(mode)).unwrap();

        let outcome = repair(&fx.layout, &plugins());

        assert!(
            matches!(outcome, RepairOutcome::Repaired { steps: 1 }),
            "{mode:o}: {outcome:?}"
        );
        assert_eq!(mode_of(fx.dir()), 0o755, "{mode:o}");
        assert_eq!(fs::metadata(fx.dir().join("ex-ray")).unwrap().ino(), before, "{mode:o}");
        assert!(
            matches!(repair(&fx.layout, &plugins()), RepairOutcome::Converged),
            "{mode:o}"
        );
    }
}

/// Whether `survey` finds the folder sound, reading nothing in it.
fn is_sound(layout: &PluginDirLayout) -> bool {
    matches!(survey(layout, &[]).unwrap(), Survey::SoundDir { .. })
}

#[skuld::test]
fn a_folder_of_another_group_than_the_owners_is_not_sound() {
    let fx = Fixture::new();
    repair(&fx.layout, &plugins());
    let mut other_group = fx.layout.clone();
    other_group.owner.1 += 1;

    assert!(is_sound(&fx.layout));
    assert!(!is_sound(&other_group));
}

#[skuld::test]
fn only_a_folder_of_the_owner_that_no_one_else_can_write_is_sound() {
    let fx = Fixture::new();
    assert!(!is_sound(&fx.layout), "nothing there");

    fx.make_sound_dir();
    for mode in [0o700, 0o750, 0o755, 0o2755] {
        fs::set_permissions(fx.dir(), fs::Permissions::from_mode(mode)).unwrap();
        assert!(is_sound(&fx.layout), "{mode:o}");
    }
    for mode in [0o775, 0o757, 0o777, 0o770] {
        fs::set_permissions(fx.dir(), fs::Permissions::from_mode(mode)).unwrap();
        assert!(!is_sound(&fx.layout), "{mode:o}: others can write it");
    }

    fs::set_permissions(fx.dir(), fs::Permissions::from_mode(0o755)).unwrap();
    let mut other_owner = fx.layout.clone();
    other_owner.owner.0 += 1;
    assert!(!is_sound(&other_owner), "another owner");
}

#[skuld::test]
fn a_link_or_file_at_the_folders_name_is_never_sound() {
    let fx = Fixture::new();
    let elsewhere = fx.tmp.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::symlink(&elsewhere, fx.dir()).unwrap();

    assert!(!is_sound(&fx.layout), "a link to a sound folder is not followed");

    fs::remove_file(fx.dir()).unwrap();
    fs::write(fx.dir(), b"x").unwrap();
    assert!(!is_sound(&fx.layout), "a file");
}

#[skuld::test]
fn a_symlink_where_the_folder_should_be_is_replaced_and_what_it_points_at_is_untouched() {
    let fx = Fixture::new();
    let elsewhere = fx.tmp.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    fs::write(elsewhere.join("keep"), b"theirs").unwrap();
    std::os::unix::fs::symlink(&elsewhere, fx.dir()).unwrap();

    repair(&fx.layout, &plugins());

    assert!(fs::symlink_metadata(fx.dir()).unwrap().is_dir(), "a real folder now");
    assert_eq!(fx.listing(), ["ex-ray", "galoshes", "layout.json"]);
    assert_eq!(fs::read(elsewhere.join("keep")).unwrap(), b"theirs");
    assert_eq!(
        fs::read_dir(&elsewhere).unwrap().count(),
        1,
        "nothing was written through the link"
    );
}

#[skuld::test]
fn a_file_where_the_folder_should_be_is_replaced() {
    let fx = Fixture::new();
    fs::write(fx.dir(), b"not a folder").unwrap();

    repair(&fx.layout, &plugins());

    assert_eq!(fx.listing(), ["ex-ray", "galoshes", "layout.json"]);
}

#[skuld::test]
fn any_prefix_of_a_plan_then_one_more_repair_converges() {
    // The plan for a folder that needs everything: a stale plugin, a stray, an unsound mode and no stamp.
    let reference = {
        let fx = Fixture::new();
        repair(&fx.layout, &plugins());
        fx.listing()
    };
    let needed = {
        let fx = Fixture::new();
        fx.make_sound_dir();
        fx.put("ex-ray", b"stale", 0o755);
        fx.put("stray", b"x", 0o755);
        let embedded = plugins();
        let carried: Vec<_> = embedded.iter().map(EmbeddedPlugin::carried).collect();
        decide_repair(&survey(&fx.layout, &carried).unwrap(), &carried)
            .steps
            .len()
    };
    assert!(
        needed >= 4,
        "the fixture needs a write, a removal and the stamp: {needed}"
    );
    for done in 0..=needed {
        let fx = Fixture::new();
        fx.make_sound_dir();
        fx.put("ex-ray", b"stale", 0o755);
        fx.put("stray", b"x", 0o755);
        let embedded = plugins();
        let carried: Vec<_> = embedded.iter().map(EmbeddedPlugin::carried).collect();
        let survey = survey(&fx.layout, &carried).unwrap();
        let plan = decide_repair(&survey, &carried);
        let prefix = RepairPlan {
            steps: plan.steps.iter().take(done).cloned().collect(),
            notes: Vec::new(),
        };

        apply(&prefix, &fx.layout, &plugins());
        let outcome = repair(&fx.layout, &plugins());

        assert!(
            matches!(outcome, RepairOutcome::Repaired { .. } | RepairOutcome::Converged),
            "after {done} steps: {outcome:?}"
        );
        assert_eq!(fx.listing(), reference, "after {done} steps");
        assert_eq!(
            fs::read(fx.dir().join("ex-ray")).unwrap(),
            EX_RAY_BYTES,
            "after {done} steps"
        );
        assert_eq!(layout_stamp::state(fx.dir()), StampState::Current, "after {done} steps");
    }
}

#[skuld::test]
fn a_build_with_no_payload_keeps_what_is_on_disk() {
    let fx = Fixture::new();
    repair(&fx.layout, &plugins());
    fx.put("ex-ray", b"newer than this stub build knows", 0o755);

    let outcome = repair(&fx.layout, &payloadless());

    assert!(matches!(outcome, RepairOutcome::Degraded { .. }), "{outcome:?}");
    assert_eq!(
        fs::read(fx.dir().join("ex-ray")).unwrap(),
        b"newer than this stub build knows"
    );
    assert_eq!(fx.listing(), ["ex-ray", "galoshes", "layout.json"]);
}

#[skuld::test]
fn a_build_with_no_payload_never_rebuilds_an_unsound_folder() {
    let fx = Fixture::new();
    repair(&fx.layout, &plugins());
    fs::set_permissions(fx.dir(), fs::Permissions::from_mode(0o775)).unwrap();

    let outcome = repair(&fx.layout, &payloadless());

    assert!(matches!(outcome, RepairOutcome::Degraded { .. }), "{outcome:?}");
    assert_eq!(fs::read(fx.dir().join("ex-ray")).unwrap(), EX_RAY_BYTES);
    assert_eq!(mode_of(fx.dir()), 0o775, "the folder was left as it was");
}

#[skuld::test]
fn a_build_with_no_payload_creates_a_missing_folder_with_only_the_stamp() {
    let fx = Fixture::new();

    let outcome = repair(&fx.layout, &payloadless());

    assert!(matches!(outcome, RepairOutcome::Degraded { .. }), "{outcome:?}");
    assert_eq!(fx.listing(), ["layout.json"]);
}

#[skuld::test]
fn a_newer_or_corrupt_stamp_leaves_every_file_untouched_and_refuses() {
    for (text, why) in [
        (r#"{"version": 2}"#, WhyUnreadable::CannotRead(CannotRead::Newer)),
        ("not json", WhyUnreadable::CannotRead(CannotRead::Corrupt)),
    ] {
        let fx = Fixture::new();
        fx.make_sound_dir();
        fx.put("layout.json", text.as_bytes(), 0o600);
        fx.put("ex-ray", b"stale", 0o755);
        fx.put("stray", b"x", 0o755);

        let outcome = repair(&fx.layout, &plugins());

        assert!(
            matches!(outcome, RepairOutcome::Refused(w) if w == why),
            "{text}: {outcome:?}"
        );
        assert_eq!(fs::read(fx.dir().join("ex-ray")).unwrap(), b"stale", "{text}");
        assert_eq!(fs::read_to_string(fx.dir().join("layout.json")).unwrap(), text);
        assert_eq!(fx.listing(), ["ex-ray", "layout.json", "stray"], "{text}");
    }
}

#[skuld::test]
fn an_unreadable_stamp_refuses_too() {
    // A directory at the stamp's name: the read fails with something that is not a missing file.
    let fx = Fixture::new();
    fx.make_sound_dir();
    fs::create_dir(fx.dir().join("layout.json")).unwrap();

    let outcome = repair(&fx.layout, &plugins());

    assert!(
        matches!(outcome, RepairOutcome::Refused(WhyUnreadable::ReadFailed(_))),
        "{outcome:?}"
    );
    assert_eq!(fx.listing(), ["layout.json"]);
}

#[skuld::test]
fn survey_lists_each_carried_plugin_once_then_the_strays() {
    let fx = Fixture::new();
    fx.make_sound_dir();
    fx.put("galoshes", b"other bytes", 0o755);
    fx.put("stray", b"x", 0o755);
    let embedded = plugins();
    let carried: Vec<_> = embedded.iter().map(EmbeddedPlugin::carried).collect();

    let survey = survey(&fx.layout, &carried).unwrap();

    assert_eq!(
        survey,
        Survey::SoundDir {
            record: StampState::Nothing,
            mode_right: true,
            entries: vec![
                ("ex-ray".to_owned(), Found::Missing),
                ("galoshes".to_owned(), Found::Differs),
                ("stray".to_owned(), Found::Unexpected),
            ]
        }
    );
}

#[skuld::test]
fn remove_folder_takes_the_folder_whatever_it_holds_and_whatever_the_stamp_says() {
    for stamp in [
        None,
        Some(r#"{"version": 1}"#),
        Some(r#"{"version": 2}"#),
        Some("not json"),
    ] {
        let fx = Fixture::new();
        fx.make_sound_dir();
        fx.put("ex-ray", EX_RAY_BYTES, 0o755);
        if let Some(text) = stamp {
            fx.put("layout.json", text.as_bytes(), 0o600);
        }

        fs::create_dir_all(fx.dir().join("inner").join("deeper")).unwrap();
        fs::write(fx.dir().join("inner").join("deeper").join("file"), b"x").unwrap();

        remove_folder(&fx.layout.dir, fx.layout.owner).unwrap();

        assert!(!fx.dir().exists(), "{stamp:?}");
    }
}

#[skuld::test]
fn remove_folder_removes_a_link_and_not_what_it_points_at_and_a_file() {
    let fx = Fixture::new();
    let elsewhere = fx.tmp.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    fs::write(elsewhere.join("keep"), b"theirs").unwrap();
    std::os::unix::fs::symlink(&elsewhere, fx.dir()).unwrap();

    remove_folder(&fx.layout.dir, fx.layout.owner).unwrap();

    assert!(fs::symlink_metadata(fx.dir()).is_err());
    assert_eq!(fs::read(elsewhere.join("keep")).unwrap(), b"theirs");

    fs::write(fx.dir(), b"a file").unwrap();
    remove_folder(&fx.layout.dir, fx.layout.owner).unwrap();
    assert!(fs::symlink_metadata(fx.dir()).is_err());
}

#[skuld::test]
fn remove_folder_of_nothing_is_ok() {
    let fx = Fixture::new();

    remove_folder(&fx.layout.dir, fx.layout.owner).unwrap();
    remove_folder(&fx.layout.dir, fx.layout.owner).unwrap();
}

#[skuld::test]
fn the_runtime_dir_is_made_0700_for_its_owner_and_made_again_without_error() {
    let fx = Fixture::new();
    let run = fx.tmp.path().join("run").join("hole");

    make_runtime_dir(&run, fx.layout.owner).unwrap();
    fs::set_permissions(&run, fs::Permissions::from_mode(0o755)).unwrap();
    make_runtime_dir(&run, fx.layout.owner).unwrap();

    assert_eq!(mode_of(&run), 0o700, "a second call tightens a loosened folder");
    assert_eq!(fs::metadata(&run).unwrap().uid(), fx.layout.owner.0);
}

#[skuld::test]
fn a_socket_at_a_plugin_name_is_replaced_by_the_file_and_the_next_repair_converges() {
    let fx = Fixture::new();
    repair(&fx.layout, &plugins());
    fs::remove_file(fx.dir().join("ex-ray")).unwrap();
    let _socket = std::os::unix::net::UnixListener::bind(fx.dir().join("ex-ray")).unwrap();

    let outcome = repair(&fx.layout, &plugins());

    assert!(matches!(outcome, RepairOutcome::Repaired { .. }), "{outcome:?}");
    assert_eq!(fs::read(fx.dir().join("ex-ray")).unwrap(), EX_RAY_BYTES);
    assert!(matches!(repair(&fx.layout, &plugins()), RepairOutcome::Converged));
}

#[skuld::test]
fn a_name_the_volume_reads_as_a_carried_name_is_that_entry_and_never_a_stray() {
    // What a volume lists for a carried file under another case: on a case-insensitive one the same entry renamed
    // (`Ex-Ray` opens as `ex-ray`), on a case-sensitive one the same file under a second name.
    let fx = Fixture::new();
    repair(&fx.layout, &plugins());
    let folds_case = fx.volume_folds_case();
    for (carried_name, variant) in [("ex-ray", "Ex-Ray"), ("layout.json", "Layout.json")] {
        let (from, to) = (fx.dir().join(carried_name), fx.dir().join(variant));
        if folds_case {
            fs::rename(from, to).unwrap();
        } else {
            fs::hard_link(from, to).unwrap();
        }
    }
    // Without this the test would pass on a volume that kept the stored name, never reaching the case-variant branch.
    let listing = fx.listing();
    for variant in ["Ex-Ray", "Layout.json"] {
        assert!(
            listing.iter().any(|name| name == variant),
            "the volume does not preserve case: {variant} is not listed in {listing:?}"
        );
    }
    let embedded = plugins();
    let carried: Vec<_> = embedded.iter().map(EmbeddedPlugin::carried).collect();

    let Survey::SoundDir { entries, .. } = survey(&fx.layout, &carried).unwrap() else {
        panic!("the folder is sound");
    };

    let strays: Vec<_> = entries
        .iter()
        .filter(|(_, found)| *found == Found::Unexpected)
        .collect();
    assert!(strays.is_empty(), "{strays:?}");
}

#[skuld::test]
fn a_name_that_only_looks_like_a_carried_name_is_a_stray_when_it_is_another_file() {
    // On a case-sensitive volume `Ex-Ray` is another file; on a case-insensitive one it is `ex-ray` itself, so writing
    // it only changes what `ex-ray` holds, and nothing is left over for repair to take for a stray.
    let fx = Fixture::new();
    repair(&fx.layout, &plugins());
    fx.put("Ex-Ray", b"not the plugin", 0o755);
    if !fx.volume_folds_case() {
        fx.put("Layout.json", b"{}", 0o600);
    }

    let outcome = repair(&fx.layout, &plugins());

    assert!(matches!(outcome, RepairOutcome::Repaired { .. }), "{outcome:?}");
    assert_eq!(fx.listing(), ["ex-ray", "galoshes", "layout.json"]);
    assert_eq!(fs::read(fx.dir().join("ex-ray")).unwrap(), EX_RAY_BYTES);
}

#[skuld::test]
fn a_repair_whose_folder_does_not_survey_as_converged_afterwards_is_degraded_and_says_so() {
    // Every step succeeds, yet the written file hashes to something other than what the plugin claims.
    let fx = Fixture::new();
    let mut embedded = plugins();
    embedded[0].sha256 = [0; 32];

    let outcome = repair(&fx.layout, &embedded);

    let RepairOutcome::Degraded { failures, .. } = outcome else {
        panic!("a folder that does not hold what hole carries is not repaired: {outcome:?}");
    };
    assert!(failures.iter().any(|f| f.contains("write ex-ray")), "{failures:?}");
}

#[skuld::test]
fn the_stamp_is_not_stored_when_an_earlier_step_failed() {
    let fx = Fixture::new();
    fx.make_sound_dir();
    let plan = RepairPlan {
        steps: vec![
            Step::Write("a plugin hole does not carry".to_owned()),
            Step::StoreRecord,
        ],
        notes: Vec::new(),
    };

    let failures = apply(&plan, &fx.layout, &plugins());

    assert_eq!(failures.len(), 2, "{failures:?}");
    assert_eq!(fx.listing(), Vec::<String>::new());
}

/// The half that needs root, on the elevated lane (the `TUN` label, as for every other privileged test in this crate):
/// the tests above run as the test user, whose own uid is the owner, so none of them can tell a chown from none.
#[cfg(target_os = "macos")]
mod as_root {
    use super::*;
    use crate::test_support::skuld_fixtures::TUN;

    /// A user that is not root.
    const USER: u32 = 4242;

    #[skuld::test(labels = [TUN], serial = TUN)]
    fn a_repair_gives_the_folder_every_plugin_and_the_stamp_to_root_whoever_held_them() {
        // SAFETY: geteuid takes no arguments and cannot fail.
        assert_eq!(unsafe { libc::geteuid() }, 0, "the elevated lane runs as root");
        let tmp = tempfile::tempdir().unwrap();
        let layout = PluginDirLayout {
            dir: tmp.path().join("Hole"),
            owner: (0, 0),
        };
        fs::create_dir(&layout.dir).unwrap();
        fs::set_permissions(&layout.dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(layout.dir.join("ex-ray"), EX_RAY_BYTES).unwrap();
        fs::set_permissions(layout.dir.join("ex-ray"), fs::Permissions::from_mode(0o755)).unwrap();
        for path in [layout.dir.clone(), layout.dir.join("ex-ray")] {
            std::os::unix::fs::chown(path, Some(USER), Some(USER)).unwrap();
        }

        let outcome = repair(&layout, &plugins());

        assert!(matches!(outcome, RepairOutcome::Repaired { .. }), "{outcome:?}");
        for name in ["", "ex-ray", "galoshes", "layout.json"] {
            let meta = fs::metadata(layout.dir.join(name)).unwrap();
            assert_eq!((meta.uid(), meta.gid()), (0, 0), "{name:?}");
        }
        assert!(matches!(repair(&layout, &plugins()), RepairOutcome::Converged));
    }
}
