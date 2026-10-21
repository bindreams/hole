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
            DisabledState::of(Some(Changer::Running), by),
            DisabledState::InChange,
            "{by:?}"
        );
    }
}

#[skuld::test]
fn a_changer_that_is_gone_or_no_record_leaves_the_start_types_answer() {
    for changer in [Some(Changer::NotRunning), None] {
        assert_eq!(DisabledState::of(changer, None), DisabledState::NotDisabled);
        assert_eq!(
            DisabledState::of(changer, Some(DisabledBy::InterruptedChange)),
            DisabledState::By(DisabledBy::InterruptedChange)
        );
        assert_eq!(
            DisabledState::of(changer, Some(DisabledBy::Elsewhere)),
            DisabledState::By(DisabledBy::Elsewhere)
        );
    }
}
