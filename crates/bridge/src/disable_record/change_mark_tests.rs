use super::scratch::ScratchChangeKey;
use super::*;
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

    mark.end().expect("end");
    assert_eq!(key.get_string(VALUE).expect("the value"), "2");
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
        mark.end().expect("end");
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
    scratch.mark().end().expect("end");
    assert_eq!(key.get_string(VALUE).expect("replaced"), "1");
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
    mark.end().expect("end");
    assert!(!scratch.exists(), "no key was made");
    assert_eq!(mark.read(), ChangeMark::new(None, None));
}
