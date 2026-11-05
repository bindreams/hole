use super::scratch::ScratchChangeKey;
use super::*;
use crate::disable_record::DisabledState;
use crate::service_scm::repair::display;
use crate::service_scm::retire::StartRead;
use crate::service_start::StartType;
use crate::test_support::reap_child::EchoChild;

/// The value's name, written out so that renaming it in the code is a decision
/// a test notices.
const VALUE: &str = "HoleChangeMark";

#[skuld::test]
fn a_key_with_no_mark_reads_as_none_and_names_no_holder() {
    let (scratch, _key) = ScratchChangeKey::created("unset");
    assert_eq!(scratch.mark().read(), ChangeMark::new(None, None));
}

#[skuld::test]
fn a_change_begun_names_its_holder_and_a_change_ended_names_none() {
    let (scratch, key) = ScratchChangeKey::created("round-trip");
    let mark = scratch.mark();

    mark.begin(&Stamp::current()).expect("begin");
    assert_eq!(
        key.get_string(VALUE).expect("the value, by its name"),
        format!("1:{}", Stamp::current().encode())
    );
    assert_eq!(mark.read().holder(), Some(Changer::Running), "this process holds it");

    mark.end(&Stamp::current()).expect("end");
    ScratchChangeKey::assert_at_rest(&key.get_string(VALUE).expect("the value"), 2, &Stamp::current());
    assert_eq!(mark.read().holder(), None);
}

/// Every transition changes the value, which is what lets a reader see that a
/// change began and ended between its two reads.
#[skuld::test]
fn every_transition_gives_the_mark_a_value_it_has_not_had() {
    let (scratch, _key) = ScratchChangeKey::created("counts");
    let mark = scratch.mark();
    let mut seen = vec![mark.read()];
    for _ in 0..3 {
        mark.begin(&Stamp::current()).expect("begin");
        seen.push(mark.read());
        mark.end(&Stamp::current()).expect("end");
        seen.push(mark.read());
    }
    for (i, a) in seen.iter().enumerate() {
        for b in &seen[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

/// A holder that crashed leaves its mark; its process is gone, so it names a
/// holder that does not run, and the next holder takes the mark over.
#[skuld::test]
fn a_holder_that_exited_leaves_a_mark_naming_a_process_that_does_not_run() {
    let (scratch, key) = ScratchChangeKey::created("crashed");
    let mut holder = EchoChild::spawn();
    let stamp = Stamp::of_listed_process(holder.pid()).unwrap().expect("listed");
    key.set_string(VALUE, format!("5:{}", stamp.encode()))
        .expect("its mark");
    assert_eq!(scratch.mark().read().holder(), Some(Changer::Running), "while it runs");

    holder.release_and_wait();
    let mark = scratch.mark();
    assert_eq!(mark.read().holder(), Some(Changer::NotRunning));

    mark.begin(&Stamp::current()).expect("the next holder");
    assert_eq!(
        key.get_string(VALUE).expect("the value"),
        format!("6:{}", Stamp::current().encode()),
        "counted on from the crashed holder's"
    );
}

/// A value that is not a mark names nobody, and the count starts over from it.
#[skuld::test]
fn a_value_that_is_not_a_mark_names_no_holder() {
    for text in ["", "x", "1:", "1:2", "a:1:2", "1:x:2", "-1:1:2", ":1:2"] {
        let (scratch, key) = ScratchChangeKey::created("garbage");
        key.set_string(VALUE, text).expect("write");
        assert_eq!(scratch.mark().read().holder(), None, "{text:?}");
    }
    let (scratch, key) = ScratchChangeKey::created("not-a-string");
    key.set_u32(VALUE, 7).expect("write");
    assert_eq!(scratch.mark().read().holder(), None);
    scratch.mark().end(&Stamp::current()).expect("end");
    ScratchChangeKey::assert_at_rest(&key.get_string(VALUE).expect("replaced"), 1, &Stamp::current());
}

/// How many warnings `body` logs.
fn warnings(body: impl FnOnce()) -> usize {
    garter::tracing_test::captured(body).matches("WARN").count()
}

/// A stored value whose count does not parse restarts the count on a write and
/// says so once, without quoting the value.
#[skuld::test]
fn writing_over_an_unreadable_mark_warns_once_and_restarts_the_count() {
    for text in ["", "secret-text", ":1:2", "-1:1:2"] {
        let (scratch, key) = ScratchChangeKey::created("unreadable-write");
        key.set_string(VALUE, text).expect("write");
        let log = garter::tracing_test::captured(|| scratch.mark().begin(&Stamp::current()).expect("begin"));
        assert_eq!(log.matches("WARN").count(), 1, "{text:?}: {log:?}");
        assert!(!log.contains("secret-text"), "{log:?}");
        assert!(
            key.get_string(VALUE).expect("the value").starts_with("1:"),
            "{text:?}: the count restarted"
        );
    }
}

/// A value of the wrong type is no mark: one warning on a write, and the count
/// starts at the first change.
#[skuld::test]
fn writing_over_a_value_of_the_wrong_type_warns_once() {
    let (scratch, key) = ScratchChangeKey::created("wrong-type-write");
    key.set_u32(VALUE, 7).expect("write");
    let log = garter::tracing_test::captured(|| scratch.mark().begin(&Stamp::current()).expect("begin"));
    assert_eq!(log.matches("WARN").count(), 1, "{log:?}");
    assert!(
        key.get_string(VALUE).expect("replaced").starts_with("1:"),
        "the count restarted"
    );
}

/// A missing value or key is the first change, not an error.
#[skuld::test]
fn a_missing_mark_is_silent_to_write_and_to_read() {
    let (scratch, _key) = ScratchChangeKey::created("missing-silent");
    let mark = scratch.mark();
    assert_eq!(warnings(|| assert_eq!(mark.read(), ChangeMark::new(None, None))), 0);
    assert_eq!(warnings(|| mark.begin(&Stamp::current()).expect("begin")), 0);

    let no_key = ScratchChangeKey::named("missing-key");
    let mark = no_key.mark();
    assert_eq!(warnings(|| assert_eq!(mark.read(), ChangeMark::new(None, None))), 0);
    assert_eq!(warnings(|| mark.begin(&Stamp::current()).expect("begin")), 0);
}

/// A stored string whose count does not parse is kept as the mark, names no
/// holder, and is warned about once per read, without quoting it.
#[skuld::test]
fn reading_an_unreadable_mark_warns_once_and_keeps_the_string() {
    for text in ["", "secret-text", ":1:2", "-1:1:2"] {
        let (scratch, key) = ScratchChangeKey::created("unreadable-read");
        key.set_string(VALUE, text).expect("write");
        let mut mark = None;
        let log = garter::tracing_test::captured(|| mark = Some(scratch.mark().read()));
        assert_eq!(mark, Some(ChangeMark::new(Some(text.to_owned()), None)), "{text:?}");
        assert_eq!(log.matches("WARN").count(), 1, "{text:?}: {log:?}");
        assert!(!log.contains("secret-text"), "{log:?}");
    }
}

/// A readable mark that names no holder (a bare count, an at-rest value) is not
/// an unreadable one.
#[skuld::test]
fn reading_a_mark_with_a_count_is_silent() {
    for text in ["7", "7/1:2/3"] {
        let (scratch, key) = ScratchChangeKey::created("readable-read");
        key.set_string(VALUE, text).expect("write");
        assert_eq!(warnings(|| drop(scratch.mark().read())), 0, "{text:?}");
    }
}

/// A value of the wrong type is no mark, and warned about once per read.
#[skuld::test]
fn a_value_of_the_wrong_type_is_read_as_no_mark_and_warned_about() {
    let (scratch, key) = ScratchChangeKey::created("wrong-type-read");
    key.set_u32(VALUE, 7).expect("write");
    let mut mark = None;
    let log = garter::tracing_test::captured(|| mark = Some(scratch.mark().read()));
    assert_eq!(mark, Some(ChangeMark::new(None, None)));
    assert_eq!(log.matches("WARN").count(), 1, "{log:?}");
}

/// No key is no service: nothing to mark, and a key made here would outlive it.
#[skuld::test]
fn a_mark_with_no_key_is_neither_written_nor_an_error() {
    let scratch = ScratchChangeKey::named("no-key");
    let mark = scratch.mark();
    mark.begin(&Stamp::current()).expect("begin");
    mark.end(&Stamp::current()).expect("end");
    assert!(!scratch.exists(), "no key was made");
    assert_eq!(mark.read(), ChangeMark::new(None, None));
}

/// Old bare `<n>` and new `<n>/<stamp>/<seq>` at rest both seed the next count.
#[skuld::test]
fn the_count_goes_on_from_an_at_rest_value_of_either_format() {
    let (scratch, key) = ScratchChangeKey::created("counts-on");
    let mark = scratch.mark();
    let holder = Stamp::current();
    for (at_rest, next) in [("7", 8), (&*format!("7/{}/3", holder.encode()), 8)] {
        key.set_string(VALUE, at_rest).expect("write");
        mark.begin(&holder).expect("begin");
        assert_eq!(
            key.get_string(VALUE).expect("the value"),
            format!("{next}:{}", holder.encode()),
            "{at_rest:?}"
        );
    }
}

/// A bare `<n>` at rest, as earlier builds wrote it, names no holder and never
/// equals what a change that ends at the same count writes now.
#[skuld::test]
fn a_bare_count_at_rest_never_equals_the_mark_a_change_ends_with_now() {
    let (old, old_key) = ScratchChangeKey::created("bare-at-rest");
    old_key.set_string(VALUE, "2").expect("write");
    let bare = old.mark().read();
    assert_eq!(bare.holder(), None);

    let (new, _key) = ScratchChangeKey::created("ended-at-two");
    let mark = new.mark();
    mark.begin(&Stamp::current()).expect("begin");
    mark.end(&Stamp::current()).expect("end");
    let ended = mark.read();
    ScratchChangeKey::assert_at_rest(&new.stored(), 2, &Stamp::current());
    assert_ne!(bare, ended);
}

/// At the same count and `seq`, two holders that differ in only one field of
/// their stamp leave different values: two processes each start `seq` at 0.
#[skuld::test]
fn at_rest_values_of_the_same_count_and_seq_differ_by_stamp() {
    let base = Stamp { pid: 4, created: 40 };
    let other_pid = Stamp { pid: 5, created: 40 };
    let other_created = Stamp { pid: 4, created: 41 };
    let value = at_rest(2, &base, 0);
    assert_ne!(value, at_rest(2, &other_pid, 0));
    assert_ne!(value, at_rest(2, &other_created, 0));
}

/// Two installs that each end on a key of their own end at the same count; the
/// mark must still differ, because a status read that sees equal marks takes
/// them for one stretch with no change in it.
#[skuld::test]
fn changes_that_end_on_a_fresh_key_each_leave_a_different_mark() {
    let (scratch, key) = ScratchChangeKey::created("fresh-keys");
    let mark = scratch.mark();
    let (first, second) = (Stamp { pid: 1, created: 10 }, Stamp { pid: 2, created: 20 });

    mark.begin(&first).expect("begin");
    mark.end(&first).expect("end");
    let after_first = mark.read();

    drop(key);
    let _fresh = scratch.recreated();
    mark.begin(&second).expect("mark again");
    mark.end(&second).expect("end");
    assert_ne!(mark.read(), after_first);
}

/// One process that ends a change on each of two fresh keys, both at the same
/// count, repeats its stamp; the mark must still differ.
#[skuld::test]
fn one_process_ending_two_changes_on_fresh_keys_at_the_same_count_leaves_two_marks() {
    let holder = Stamp::current();
    let mut at_rest = Vec::new();
    for name in ["same-process-a", "same-process-b"] {
        let (scratch, key) = ScratchChangeKey::created(name);
        let mark = scratch.mark();
        mark.begin(&holder).expect("begin");
        mark.end(&holder).expect("end");
        at_rest.push(key.get_string(VALUE).expect("the value"));
    }
    assert!(at_rest.iter().all(|value| value.starts_with("2/")), "{at_rest:?}");
    assert_ne!(at_rest[0], at_rest[1]);
}

/// A status reader whose service is reinstalled (key deleted and recreated)
/// right after its first start-type read.
struct Reinstalled<'a> {
    scratch: &'a ScratchChangeKey,
    mark: ChangeKey,
    start: StartType,
    reinstalled: bool,
    reads: usize,
}

impl StartRead for Reinstalled<'_> {
    fn read_start_type(&mut self) -> io::Result<StartType> {
        self.reads += 1;
        let start = self.start;
        if !self.reinstalled {
            // The old service was disabled when it was read; the new one is not.
            self.reinstalled = true;
            self.start = StartType::Auto;
            let installer = Stamp { pid: 7, created: 70 };
            self.mark.begin(&installer).expect("begin on the old key");
            let _key = self.scratch.recreated();
            self.mark.begin(&installer).expect("mark the new key");
            self.mark.end(&installer).expect("end");
            return Ok(StartType::Disabled);
        }
        Ok(start)
    }

    fn read_changer(&mut self) -> Option<Changer> {
        self.reads += 1;
        None
    }

    fn read_mark(&mut self) -> ChangeMark {
        self.reads += 1;
        self.mark.read()
    }
}

/// Equal counts across a reinstall must not read as no change: that would
/// report the service as disabled by an administrator.
#[skuld::test]
fn a_status_read_that_a_reinstall_straddles_reads_again() {
    let (scratch, key) = ScratchChangeKey::created("reinstall-straddle");
    let mark = scratch.mark();
    let previous_install = Stamp { pid: 3, created: 30 };
    mark.begin(&previous_install).expect("begin");
    mark.end(&previous_install).expect("end");
    drop(key);

    let mut reader = Reinstalled {
        scratch: &scratch,
        mark,
        start: StartType::Disabled,
        reinstalled: false,
        reads: 0,
    };
    assert_eq!(display(&mut reader), DisabledState::NotDisabled);
    assert_eq!(
        reader.reads, 8,
        "the first pass is not accepted: two passes of four reads"
    );
}
