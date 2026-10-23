use super::*;

const STARTS: [StartType; 4] = [
    StartType::Auto,
    StartType::Demand,
    StartType::Disabled,
    StartType::Other,
];
const RECORDS: [RecordState; 2] = [RecordState::Absent, RecordState::Present];

// The decision --------------------------------------------------------------------------------------------------------

#[skuld::test]
fn repair_step_is_decided_by_record_and_start_type() {
    use RecordState::{Absent, Present};
    use RepairStep::*;
    // Every cell of the table: with a record, a Disabled service is ours to reset and
    // any other start type means the record is stale; with none, a Disabled service is
    // an administrator's and nothing else needs anything.
    let table = [
        (Present, StartType::Disabled, ResetThenClear),
        (Present, StartType::Auto, ClearRecordOnly),
        (Present, StartType::Demand, ClearRecordOnly),
        (Present, StartType::Other, ClearRecordOnly),
        (Absent, StartType::Disabled, LeaveDisabled),
        (Absent, StartType::Auto, Nothing),
        (Absent, StartType::Demand, Nothing),
        (Absent, StartType::Other, Nothing),
    ];
    for (record, start, expected) in table {
        assert_eq!(RepairStep::of(record, start), expected, "{record:?} over {start:?}");
    }
}

#[skuld::test]
fn only_a_service_left_disabled_is_not_started() {
    assert!(RepairStep::Nothing.starts_service());
    assert!(RepairStep::ClearRecordOnly.starts_service());
    assert!(RepairStep::ResetThenClear.starts_service());
    assert!(!RepairStep::LeaveDisabled.starts_service());
}

#[skuld::test]
fn a_disabled_service_is_attributed_by_its_record_and_no_other_is_attributed() {
    for record in RECORDS {
        for start in STARTS {
            let by = RepairStep::of(record, start).disabled_by();
            let expected = match (start, record) {
                (StartType::Disabled, RecordState::Present) => Some(DisabledBy::InterruptedChange),
                (StartType::Disabled, RecordState::Absent) => Some(DisabledBy::Elsewhere),
                _ => None,
            };
            assert_eq!(by, expected, "{record:?} over {start:?}");
        }
    }
}

// Installing ----------------------------------------------------------------------------------------------------------

#[skuld::test]
fn a_reinstall_keeps_only_an_administrators_disable() {
    assert_eq!(InstallStart::for_disabled_by(None), InstallStart::Automatic);
    assert_eq!(
        InstallStart::for_disabled_by(Some(DisabledBy::InterruptedChange)),
        InstallStart::Automatic
    );
    assert_eq!(
        InstallStart::for_disabled_by(Some(DisabledBy::Elsewhere)),
        InstallStart::LeaveDisabled
    );
}
