use super::*;
use crate::disable_record::{ChangeMark, Changer, DisabledBy, DisabledState, RecordState};
use crate::service_scm::retire::StartRead;
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
                ["record_state", "write_record", "set_start_type(Auto)", "clear_record"],
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
    assert_eq!(config.calls(), ["record_state", "write_record", "set_start_type(Auto)"]);
    assert_eq!(config.record, RecordState::Present);
}

/// An administrator's Disable has no record. The stamp `enable` makes would
/// turn it into an interrupted Hole change if the write failed and the stamp
/// stayed, and the elevated paths undo those; so a record this call made is
/// its own to remove.
#[skuld::test]
fn a_failed_enable_write_removes_the_record_it_made_and_leaves_the_disable_an_administrators() {
    let mut config = FakeConfig::new(RecordState::Absent, StartType::Disabled).failing("set_start_type");
    assert!(matches!(enable(&mut config), Err(RepairError::Reset(_))));
    assert_eq!(
        config.calls(),
        ["record_state", "write_record", "set_start_type(Auto)", "clear_record"]
    );
    assert_eq!(
        (config.start, config.record),
        (StartType::Disabled, RecordState::Absent)
    );
    assert_eq!(
        display(&mut config),
        DisabledState::By(DisabledBy::Elsewhere),
        "the GUI still offers Enable, not Repair"
    );
}

#[skuld::test]
fn a_failed_enable_write_that_could_not_stamp_has_no_record_of_its_own_to_remove() {
    let mut config = FakeConfig::new(RecordState::Absent, StartType::Disabled)
        .failing("write_record")
        .failing("set_start_type");
    assert!(matches!(enable(&mut config), Err(RepairError::Reset(_))));
    assert_eq!(config.calls(), ["record_state", "write_record", "set_start_type(Auto)"]);
}

#[skuld::test]
fn an_enable_that_cannot_stamp_the_record_goes_on() {
    let mut config = FakeConfig::new(RecordState::Absent, StartType::Disabled).failing("write_record");
    enable(&mut config).unwrap();
    assert_eq!(
        config.calls(),
        ["record_state", "write_record", "set_start_type(Auto)", "clear_record"]
    );
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

// Displaying while a writer changes the service -----------------------------------------------------------------------

/// What a writer changes: the start type, the record's changer and the change
/// mark.
struct Service {
    start: StartType,
    changer: Option<Changer>,
    mark: ChangeMark,
}

/// What a writer does to the service.
type Event = Box<dyn FnMut(&mut Service)>;

/// A status reader over a service that a writer changes between the reader's
/// reads: `events` run once, each after the reader's n-th read (counted from 1).
struct Straddled {
    service: Service,
    reads: usize,
    events: Vec<(usize, Event)>,
}

impl Straddled {
    fn new(service: Service) -> Self {
        Self {
            service,
            reads: 0,
            events: vec![],
        }
    }

    fn after_read(mut self, n: usize, event: impl FnMut(&mut Service) + 'static) -> Self {
        self.events.push((n, Box::new(event)));
        self
    }

    fn read<T>(&mut self, read: impl FnOnce(&Service) -> T) -> T {
        let answer = read(&self.service);
        self.reads += 1;
        for (n, event) in &mut self.events {
            if *n == self.reads {
                event(&mut self.service);
            }
        }
        answer
    }
}

impl StartRead for Straddled {
    fn read_start_type(&mut self) -> io::Result<StartType> {
        Ok(self.read(|service| service.start))
    }

    fn read_changer(&mut self) -> Option<Changer> {
        self.read(|service| service.changer)
    }

    fn read_mark(&mut self) -> ChangeMark {
        self.read(|service| service.mark.clone())
    }
}

fn idle(generation: u32) -> ChangeMark {
    ChangeMark::new(Some(generation.to_string()), None)
}

fn busy(generation: u32, holder: Changer) -> ChangeMark {
    ChangeMark::new(Some(format!("{generation}:holder")), Some(holder))
}

/// A whole retirement (it begins, stamps, disables, restores, clears and ends)
/// inside one status read: the start type read while it was disabling and the
/// record read after it cleared it would say an administrator disabled the
/// service, so the read goes again.
#[skuld::test]
fn a_status_read_that_a_whole_change_straddles_reads_again() {
    let mut reader = Straddled::new(Service {
        start: StartType::Auto,
        changer: None,
        mark: idle(0),
    })
    .after_read(1, |service| {
        service.mark = busy(1, Changer::Running);
        service.changer = Some(Changer::Running);
        service.start = StartType::Disabled;
    })
    .after_read(2, |service| {
        service.start = StartType::Auto;
        service.changer = None;
        service.mark = idle(2);
    });
    assert_eq!(display(&mut reader), DisabledState::NotDisabled);
}

/// A holder that stamps nothing is still a change in progress.
#[skuld::test]
fn a_status_read_while_a_holder_runs_is_a_change_in_progress_with_no_record() {
    let mut reader = Straddled::new(Service {
        start: StartType::Disabled,
        changer: None,
        mark: busy(1, Changer::Running),
    });
    assert_eq!(display(&mut reader), DisabledState::InChange);
}

/// A holder that crashed leaves its mark busy for good; reads go on as if
/// nothing held the lock, and are not repeated for ever.
#[skuld::test]
fn a_status_read_over_a_holder_that_is_gone_answers_from_the_record() {
    let mut reader = Straddled::new(Service {
        start: StartType::Disabled,
        changer: Some(Changer::NotRunning),
        mark: busy(1, Changer::NotRunning),
    });
    assert_eq!(display(&mut reader), DisabledState::By(DisabledBy::InterruptedChange));
    assert_eq!(reader.reads, 4, "one pass: mark, start type, record, mark");
}

/// Another change begins between two passes: the read goes again until two
/// marks match.
#[skuld::test]
fn a_status_read_goes_again_until_two_marks_match() {
    let mut reader = Straddled::new(Service {
        start: StartType::Auto,
        changer: None,
        mark: idle(0),
    })
    .after_read(3, |service| service.mark = idle(2))
    .after_read(7, |service| service.mark = idle(4));
    assert_eq!(display(&mut reader), DisabledState::NotDisabled);
    assert_eq!(
        reader.reads, 12,
        "passes of four reads: the first two differ, the third matches"
    );
}
