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
    assert_eq!(
        key.get_string(VALUE).expect("the value"),
        format!("2/{}", Stamp::current().encode()),
        "the count and the process that ended the change"
    );
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
    assert_eq!(
        key.get_string(VALUE).expect("replaced"),
        format!("1/{}", Stamp::current().encode())
    );
}

/// A value of the wrong type is read as an empty mark, and says so, as every
/// other failed read of the mark does.
#[skuld::test]
fn a_value_of_the_wrong_type_is_read_as_empty_and_warned_about() {
    use garter::test_utils::WaitableWriter;
    use garter::tracing_test::set_default_in_current_thread;

    let (scratch, key) = ScratchChangeKey::created("wrong-type");
    key.set_u32(VALUE, 7).expect("write");
    let writer = WaitableWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .finish();
    let mark = {
        let _guard = set_default_in_current_thread(subscriber);
        scratch.mark().read()
    };
    assert_eq!(mark, ChangeMark::new(Some(String::new()), None));
    assert!(writer.snapshot().contains("WARN"), "{:?}", writer.snapshot());
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

/// The count continues from an at-rest value of either format: the one a change
/// ends with and the bare count an earlier build left.
#[skuld::test]
fn the_count_goes_on_from_an_at_rest_value_of_either_format() {
    let (scratch, key) = ScratchChangeKey::created("counts-on");
    let mark = scratch.mark();
    let holder = Stamp::current();
    for (at_rest, next) in [("7", 8), (&*format!("7/{}", holder.encode()), 8)] {
        key.set_string(VALUE, at_rest).expect("write");
        mark.begin(&holder).expect("begin");
        assert_eq!(
            key.get_string(VALUE).expect("the value"),
            format!("{next}:{}", holder.encode()),
            "{at_rest:?}"
        );
    }
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

/// A status reader over the real mark in a scratch key, whose service is
/// reinstalled by another process right after its first read of the start type:
/// the old key is deleted and a new one made, and the new service has a start
/// type and no record yet.
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

/// The service's key is deleted and made again by a reinstall, and both
/// installs end at the same count: a read that took the equal marks for no
/// change would call the service disabled by an administrator.
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
