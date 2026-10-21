use super::*;
use crate::disable_record::{Changer, DisabledBy, DisabledState, RecordState};
use crate::service_start::{RepairStep, StartType};

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
    /// Whether the process that stamped the record is running.
    changer: Changer,
}

impl FakeConfig {
    fn new(record: RecordState, start: StartType) -> Self {
        Self {
            calls: vec![],
            start,
            record,
            fail: vec![],
            changer: Changer::NotRunning,
        }
    }

    fn stamped_by(mut self, changer: Changer) -> Self {
        self.changer = changer;
        self
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

    fn write_record(&mut self) -> io::Result<()> {
        self.call("write_record".into())?;
        self.record = RecordState::Present;
        self.changer = Changer::Running;
        Ok(())
    }

    fn record_changer(&mut self) -> Option<Changer> {
        self.calls.push("record_changer".into());
        match self.record {
            RecordState::Absent => None,
            RecordState::Present => Some(self.changer),
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
        [
            "start_type",
            "record_state",
            "write_record",
            "set_start_type(Auto)",
            "clear_record"
        ]
    );
    assert_eq!((config.start, config.record), (StartType::Auto, RecordState::Absent));
}

/// The repair stamps the record before it changes the start type, so a reader
/// sees a running changer, not the interrupted change's dead one, while it
/// works. A stamp that cannot be written costs only that wording.
#[skuld::test]
fn a_repair_that_cannot_stamp_the_record_goes_on() {
    let mut config = FakeConfig::new(RecordState::Present, StartType::Disabled).failing("write_record");
    assert_eq!(repair(&mut config).unwrap(), RepairStep::ResetThenClear);
    assert_eq!(
        config.calls(),
        [
            "start_type",
            "record_state",
            "write_record",
            "set_start_type(Auto)",
            "clear_record"
        ]
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
    assert_eq!(
        config.calls(),
        ["start_type", "record_state", "write_record", "set_start_type(Auto)"]
    );
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
                ["write_record", "set_start_type(Auto)", "clear_record"],
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
    assert_eq!(config.calls(), ["write_record", "set_start_type(Auto)"]);
    assert_eq!(config.record, RecordState::Present);
}

#[skuld::test]
fn an_enable_that_cannot_stamp_the_record_goes_on() {
    let mut config = FakeConfig::new(RecordState::Absent, StartType::Disabled).failing("write_record");
    enable(&mut config).unwrap();
    assert_eq!(config.calls(), ["write_record", "set_start_type(Auto)", "clear_record"]);
    assert_eq!((config.start, config.record), (StartType::Auto, RecordState::Absent));
}

#[skuld::test]
fn a_failed_clear_after_enabling_does_not_fail_the_enable() {
    let mut config = FakeConfig::new(RecordState::Present, StartType::Disabled).failing("clear_record");
    enable(&mut config).unwrap();
    assert_eq!(config.start, StartType::Auto);
}

// Displaying ----------------------------------------------------------------------------------------------------------

/// What a GUI reading says: the start type, then the record's changer, and
/// nothing is written.
#[skuld::test]
fn a_gui_reading_reads_and_writes_nothing() {
    for record in RECORDS {
        for start in STARTS {
            let mut config = FakeConfig::new(record, start);
            display(&mut config);
            assert_eq!(
                config.calls(),
                ["start_type", "record_changer"],
                "{record:?} over {start:?}"
            );
        }
    }
}

#[skuld::test]
fn a_gui_reading_names_who_disabled_the_service_from_what_it_found() {
    let state = |record, start| display(&mut FakeConfig::new(record, start));
    assert_eq!(
        state(RecordState::Present, StartType::Disabled),
        DisabledState::By(DisabledBy::InterruptedChange)
    );
    assert_eq!(
        state(RecordState::Absent, StartType::Disabled),
        DisabledState::By(DisabledBy::Elsewhere)
    );
    assert_eq!(state(RecordState::Present, StartType::Auto), DisabledState::NotDisabled);
    assert_eq!(state(RecordState::Absent, StartType::Auto), DisabledState::NotDisabled);
}

/// A record stamped by a process that runs is a change in progress, over
/// every start type: the retirement writes the record before it disables the
/// service and clears it after it restores it.
#[skuld::test]
fn a_gui_reading_of_a_record_whose_writer_runs_is_a_change_in_progress() {
    for start in STARTS {
        let mut config = FakeConfig::new(RecordState::Present, start).stamped_by(Changer::Running);
        assert_eq!(display(&mut config), DisabledState::InChange, "{start:?}");
    }
}

#[skuld::test]
fn a_gui_reading_that_cannot_read_the_start_type_says_nothing_of_a_disable_but_still_sees_a_running_changer() {
    let mut config = FakeConfig::new(RecordState::Present, StartType::Disabled).failing("start_type");
    assert_eq!(display(&mut config), DisabledState::NotDisabled);

    let mut config = FakeConfig::new(RecordState::Present, StartType::Disabled)
        .failing("start_type")
        .stamped_by(Changer::Running);
    assert_eq!(display(&mut config), DisabledState::InChange);
}
