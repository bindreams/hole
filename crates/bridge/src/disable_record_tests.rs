use super::*;

#[skuld::test]
fn disabled_by_is_decided_on_the_record_alone() {
    assert_eq!(DisabledBy::of(RecordState::Present), DisabledBy::InterruptedChange);
    assert_eq!(DisabledBy::of(RecordState::Absent), DisabledBy::Elsewhere);
}

#[skuld::test]
fn a_probe_that_found_the_process_running_is_a_running_changer_and_no_other_answer_is() {
    assert_eq!(Changer::of(Ok(true)), Changer::Running);
    assert_eq!(Changer::of(Ok(false)), Changer::NotRunning);
    // A probe that failed cannot say it runs: the user is never left waiting.
    assert_eq!(Changer::of(Err(std::io::Error::other("refused"))), Changer::NotRunning);
}

#[skuld::test]
fn a_running_changer_is_a_change_in_progress_whatever_the_start_type_says() {
    for by in [None, Some(DisabledBy::InterruptedChange), Some(DisabledBy::Elsewhere)] {
        assert_eq!(
            DisabledState::of(None, Some(Changer::Running), by),
            DisabledState::InChange,
            "{by:?}"
        );
    }
}

/// The holder of the lock is the change in progress, over every start type
/// and with or without a record: a holder that stamps nothing is still one.
#[skuld::test]
fn a_running_lock_holder_is_a_change_in_progress_whatever_the_record_and_start_type_say() {
    for changer in [None, Some(Changer::NotRunning), Some(Changer::Running)] {
        for by in [None, Some(DisabledBy::InterruptedChange), Some(DisabledBy::Elsewhere)] {
            assert_eq!(
                DisabledState::of(Some(Changer::Running), changer, by),
                DisabledState::InChange,
                "{changer:?} {by:?}"
            );
        }
    }
}

#[skuld::test]
fn a_changer_that_is_gone_or_no_record_leaves_the_start_types_answer() {
    // A holder that is gone (it crashed holding the lock) leaves the same answer.
    for holder in [Some(Changer::NotRunning), None] {
        for changer in [Some(Changer::NotRunning), None] {
            assert_eq!(DisabledState::of(holder, changer, None), DisabledState::NotDisabled);
            assert_eq!(
                DisabledState::of(holder, changer, Some(DisabledBy::InterruptedChange)),
                DisabledState::By(DisabledBy::InterruptedChange)
            );
            assert_eq!(
                DisabledState::of(holder, changer, Some(DisabledBy::Elsewhere)),
                DisabledState::By(DisabledBy::Elsewhere)
            );
        }
    }
}
