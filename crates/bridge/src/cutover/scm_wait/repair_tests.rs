use super::*;

const STARTS: [StartType; 4] = [
    StartType::Auto,
    StartType::Demand,
    StartType::Disabled,
    StartType::Other,
];
const RECORDS: [RecordState; 2] = [RecordState::Absent, RecordState::Present];

/// A service's configuration that logs every call and holds a model of what the
/// calls leave behind.
struct FakeConfig {
    calls: Vec<String>,
    start: StartType,
    record: RecordState,
    /// Calls that fail, by the name they are logged under.
    fail: Vec<&'static str>,
}

impl FakeConfig {
    fn new(record: RecordState, start: StartType) -> Self {
        Self {
            calls: vec![],
            start,
            record,
            fail: vec![],
        }
    }

    fn failing(mut self, call: &'static str) -> Self {
        self.fail.push(call);
        self
    }

    fn call(&mut self, name: String) -> io::Result<()> {
        let fails = self.fail.iter().any(|f| name.starts_with(f));
        self.calls.push(name);
        if fails {
            return Err(io::Error::other("injected"));
        }
        Ok(())
    }

    fn calls(&self) -> Vec<&str> {
        self.calls.iter().map(String::as_str).collect()
    }
}

impl StartConfig for FakeConfig {
    fn start_type(&mut self) -> io::Result<StartType> {
        self.call("start_type".into())?;
        Ok(self.start)
    }

    fn set_start_type(&mut self, to: StartWrite) -> io::Result<()> {
        self.call(format!("set_start_type({to:?})"))?;
        self.start = match to {
            StartWrite::Auto => StartType::Auto,
            StartWrite::Demand => StartType::Demand,
            StartWrite::Disabled => StartType::Disabled,
        };
        Ok(())
    }

    fn record_state(&mut self) -> RecordState {
        self.calls.push("record_state".into());
        self.record
    }

    fn clear_record(&mut self) -> io::Result<()> {
        self.call("clear_record".into())?;
        self.record = RecordState::Absent;
        Ok(())
    }
}

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
                (StartType::Disabled, RecordState::Present) => Some(DisabledBy::InterruptedUninstall),
                (StartType::Disabled, RecordState::Absent) => Some(DisabledBy::Elsewhere),
                _ => None,
            };
            assert_eq!(by, expected, "{record:?} over {start:?}");
        }
    }
}

// Reading -------------------------------------------------------------------------------------------------------------

#[skuld::test]
fn observing_reads_the_two_facts_and_writes_nothing() {
    for record in RECORDS {
        for start in STARTS {
            let mut config = FakeConfig::new(record, start);
            let step = observe(&mut config).unwrap();
            assert_eq!(step, RepairStep::of(record, start));
            assert_eq!(
                config.calls(),
                ["start_type", "record_state"],
                "{record:?} over {start:?}"
            );
        }
    }
}

#[skuld::test]
fn a_failed_read_is_the_error_and_nothing_is_written() {
    let mut config = FakeConfig::new(RecordState::Present, StartType::Disabled).failing("start_type");
    assert!(matches!(repair(&mut config), Err(RepairError::StartType(_))));
    assert_eq!(config.calls(), ["start_type"]);
}

// Repairing -----------------------------------------------------------------------------------------------------------

#[skuld::test]
fn a_record_over_a_disabled_service_is_reset_to_automatic_and_then_cleared() {
    let mut config = FakeConfig::new(RecordState::Present, StartType::Disabled);
    assert_eq!(repair(&mut config).unwrap(), RepairStep::ResetThenClear);
    // The record goes last, so a repair cut short after the start-type write
    // still leaves a service that is not Disabled and a stale record, never a
    // Disabled service of ours without its record.
    assert_eq!(
        config.calls(),
        ["start_type", "record_state", "set_start_type(Auto)", "clear_record"]
    );
    assert_eq!((config.start, config.record), (StartType::Auto, RecordState::Absent));
}

#[skuld::test]
fn a_record_over_a_service_that_is_not_disabled_is_cleared_and_the_start_type_is_not_written() {
    for start in [StartType::Auto, StartType::Demand, StartType::Other] {
        let mut config = FakeConfig::new(RecordState::Present, start);
        assert_eq!(repair(&mut config).unwrap(), RepairStep::ClearRecordOnly);
        assert_eq!(
            config.calls(),
            ["start_type", "record_state", "clear_record"],
            "{start:?}"
        );
        assert_eq!(config.start, start);
    }
}

#[skuld::test]
fn a_disabled_service_without_a_record_is_an_administrators_and_is_left_alone() {
    let mut config = FakeConfig::new(RecordState::Absent, StartType::Disabled);
    assert_eq!(repair(&mut config).unwrap(), RepairStep::LeaveDisabled);
    assert_eq!(config.calls(), ["start_type", "record_state"]);
    assert_eq!(
        (config.start, config.record),
        (StartType::Disabled, RecordState::Absent)
    );
}

#[skuld::test]
fn a_service_with_nothing_to_repair_is_not_written() {
    for start in [StartType::Auto, StartType::Demand, StartType::Other] {
        let mut config = FakeConfig::new(RecordState::Absent, start);
        assert_eq!(repair(&mut config).unwrap(), RepairStep::Nothing);
        assert_eq!(config.calls(), ["start_type", "record_state"], "{start:?}");
    }
}

#[skuld::test]
fn a_failed_reset_is_the_error_and_leaves_the_record() {
    let mut config = FakeConfig::new(RecordState::Present, StartType::Disabled).failing("set_start_type");
    assert!(matches!(repair(&mut config), Err(RepairError::Reset(_))));
    assert_eq!(config.calls(), ["start_type", "record_state", "set_start_type(Auto)"]);
    assert_eq!(
        (config.start, config.record),
        (StartType::Disabled, RecordState::Present)
    );
}

#[skuld::test]
fn a_failed_clear_after_the_reset_does_not_fail_the_repair() {
    // The service is repaired; the record left behind is stale, and the next
    // retirement, cutover or install sweeps it.
    let mut config = FakeConfig::new(RecordState::Present, StartType::Disabled).failing("clear_record");
    assert_eq!(repair(&mut config).unwrap(), RepairStep::ResetThenClear);
    assert_eq!(config.start, StartType::Auto);

    let mut config = FakeConfig::new(RecordState::Present, StartType::Auto).failing("clear_record");
    assert_eq!(repair(&mut config).unwrap(), RepairStep::ClearRecordOnly);
}

// Enabling ------------------------------------------------------------------------------------------------------------

#[skuld::test]
fn enabling_writes_automatic_whatever_the_record_says_and_then_clears_it() {
    for record in RECORDS {
        for start in STARTS {
            let mut config = FakeConfig::new(record, start);
            enable(&mut config).unwrap();
            assert_eq!(
                config.calls(),
                ["set_start_type(Auto)", "clear_record"],
                "{record:?} over {start:?}"
            );
            assert_eq!((config.start, config.record), (StartType::Auto, RecordState::Absent));
        }
    }
}

#[skuld::test]
fn a_failed_enable_write_is_the_error_and_leaves_the_record() {
    let mut config = FakeConfig::new(RecordState::Present, StartType::Disabled).failing("set_start_type");
    assert!(matches!(enable(&mut config), Err(RepairError::Reset(_))));
    assert_eq!(config.calls(), ["set_start_type(Auto)"]);
    assert_eq!(config.record, RecordState::Present);
}

#[skuld::test]
fn a_failed_clear_after_enabling_does_not_fail_the_enable() {
    let mut config = FakeConfig::new(RecordState::Present, StartType::Disabled).failing("clear_record");
    enable(&mut config).unwrap();
    assert_eq!(config.start, StartType::Auto);
}

// Displaying ----------------------------------------------------------------------------------------------------------

#[skuld::test]
fn a_gui_reading_names_who_disabled_the_service_from_what_it_found() {
    let by = |record, start| for_display(observe(&mut FakeConfig::new(record, start)));
    assert_eq!(
        by(RecordState::Present, StartType::Disabled),
        Some(DisabledBy::InterruptedUninstall)
    );
    assert_eq!(
        by(RecordState::Absent, StartType::Disabled),
        Some(DisabledBy::Elsewhere)
    );
    assert_eq!(by(RecordState::Present, StartType::Auto), None);
    assert_eq!(by(RecordState::Absent, StartType::Auto), None);
}

#[skuld::test]
fn a_gui_reading_that_cannot_read_the_start_type_says_nothing() {
    let mut config = FakeConfig::new(RecordState::Present, StartType::Disabled).failing("start_type");
    assert_eq!(for_display(observe(&mut config)), None);
}

// Installing ----------------------------------------------------------------------------------------------------------

#[skuld::test]
fn a_reinstall_keeps_only_an_administrators_disable() {
    assert_eq!(InstallStart::for_disabled_by(None), InstallStart::Automatic);
    assert_eq!(
        InstallStart::for_disabled_by(Some(DisabledBy::InterruptedUninstall)),
        InstallStart::Automatic
    );
    assert_eq!(
        InstallStart::for_disabled_by(Some(DisabledBy::Elsewhere)),
        InstallStart::LeaveDisabled
    );
}
