use super::*;

#[skuld::test]
fn disabled_by_is_decided_on_the_record_alone() {
    assert_eq!(DisabledBy::of(RecordState::Present), DisabledBy::InterruptedChange);
    assert_eq!(DisabledBy::of(RecordState::Absent), DisabledBy::Elsewhere);
}
