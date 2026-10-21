//! A session over the real one that records every act the retirement makes on
//! it, in order, so a test asserts the order from the record and not from the
//! outcome. The real session still does the work: the state a later look reads
//! comes from the SCM.

use hole_bridge::cutover::scm_wait::call_error::{service_gone, ServiceGone};
use hole_bridge::cutover::scm_wait::hold::Look;
use hole_bridge::cutover::scm_wait::retire::{FailureActions, ServiceSession, StartConfig, StartWrite, Survivors};
use hole_bridge::cutover::scm_wait::scan::ScanFinding;
use hole_bridge::cutover::scm_wait::settle::StopActor;
use hole_bridge::cutover::scm_wait::Observed;
use hole_bridge::disable_record::{Changer, RecordState};
use hole_bridge::platform::os::{Opening, RetireSession};
use hole_bridge::service_start::StartType;

/// A call on the session the SCM can refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Call {
    ReadStartType,
    ArmLeaving,
    ControlStop,
    SetStartType,
    SetFailureActions,
    Delete,
}

/// One act on the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A look, as it came back.
    Observed(Look),
    ArmLeaving(Observed),
    /// A Stop, with the state of the last look before it and the start type
    /// the SCM held at that moment, if a read of it was answered: a service
    /// marked for deletion may refuse the read.
    Stop {
        after: Option<Observed>,
        start_type: Option<StartType>,
    },
    AwaitCallback,
    AwaitHeldExits,
    HoldScanned,
    SetStartType(StartWrite),
    SetFailureActions(FailureActions),
    /// The record that an uninstall disabled the service, written or removed.
    WriteRecord,
    ClearRecord,
    /// The delete, with the start type the SCM held at that moment, if a read
    /// of it was answered.
    Delete {
        start_type: Option<StartType>,
    },
    /// The SCM refused `call` through the session's handle; `marked` is
    /// whether it answered that the service is marked for deletion.
    Refused {
        call: Call,
        marked: bool,
    },
}

/// Called for each act after it is recorded and before the real session
/// performs it, so a wait is announced before it blocks. A look is recorded
/// after it is made.
pub type Hook<'a> = Box<dyn FnMut(&Event) + 'a>;

pub struct Recording<'a, S> {
    inner: S,
    events: Vec<Event>,
    hook: Hook<'a>,
}

impl<'a, S> Recording<'a, S> {
    pub fn new(inner: S, hook: Hook<'a>) -> Self {
        Self {
            inner,
            events: vec![],
            hook,
        }
    }

    /// Closes the session's SCM handles, which keep a deleted service
    /// registered, and returns what it recorded.
    pub fn finish(self) -> Trace {
        Trace(self.events)
    }

    fn record(&mut self, event: Event) {
        self.events.push(event);
        (self.hook)(&event);
    }

    /// `result`, after recording it as a refusal of `call` if it is one.
    fn note<T>(&mut self, call: Call, result: std::io::Result<T>) -> std::io::Result<T> {
        if let Err(error) = &result {
            let marked = service_gone(error) == Some(ServiceGone::MarkedForDeletion);
            self.record(Event::Refused { call, marked });
        }
        result
    }

    fn last_observed(&self) -> Option<Observed> {
        self.events.iter().rev().find_map(|event| match event {
            Event::Observed(look) => Some(look.observed),
            _ => None,
        })
    }
}

/// The real session for `HoleBridge`, which must be registered.
pub fn open_retire_session<'a>(hook: Hook<'a>) -> Recording<'a, RetireSession> {
    let inner = match RetireSession::open().expect("open the retire session") {
        Opening::Opened(session) => session,
        Opening::Absent => panic!("the service is registered"),
    };
    Recording::new(inner, hook)
}

impl<S: ServiceSession> StopActor for Recording<'_, S> {
    fn observe(&mut self) -> std::io::Result<Look> {
        let look = self.inner.observe()?;
        self.record(Event::Observed(look));
        Ok(look)
    }

    fn arm_leaving(&mut self, from: Observed) -> std::io::Result<()> {
        self.record(Event::ArmLeaving(from));
        let result = self.inner.arm_leaving(from);
        self.note(Call::ArmLeaving, result)
    }

    fn control_stop(&mut self) -> std::io::Result<()> {
        // The read is the test's own, on the session's handle, and is not an
        // act of the retirement. A marked service may refuse it.
        let start_type = self.inner.start_type().ok();
        let after = self.last_observed();
        self.record(Event::Stop { after, start_type });
        let result = self.inner.control_stop();
        self.note(Call::ControlStop, result)
    }

    fn await_callback(&mut self) -> std::io::Result<()> {
        self.record(Event::AwaitCallback);
        self.inner.await_callback()
    }

    fn await_held_exits(&mut self) -> std::io::Result<()> {
        self.record(Event::AwaitHeldExits);
        self.inner.await_held_exits()
    }

    fn hold_scanned(&mut self) -> std::io::Result<ScanFinding> {
        self.record(Event::HoldScanned);
        self.inner.hold_scanned()
    }
}

impl<S: ServiceSession> StartConfig for Recording<'_, S> {
    fn start_type(&mut self) -> std::io::Result<StartType> {
        let result = self.inner.start_type();
        self.note(Call::ReadStartType, result)
    }

    fn set_start_type(&mut self, to: StartWrite) -> std::io::Result<()> {
        self.record(Event::SetStartType(to));
        let result = self.inner.set_start_type(to);
        self.note(Call::SetStartType, result)
    }

    fn record_state(&mut self) -> RecordState {
        self.inner.record_state()
    }

    fn clear_record(&mut self) -> std::io::Result<()> {
        self.record(Event::ClearRecord);
        self.inner.clear_record()
    }

    fn write_record(&mut self) -> std::io::Result<()> {
        self.record(Event::WriteRecord);
        self.inner.write_record()
    }

    fn record_changer(&mut self) -> Option<Changer> {
        self.inner.record_changer()
    }
}

impl<S: ServiceSession> ServiceSession for Recording<'_, S> {
    fn set_failure_actions(&mut self, actions: FailureActions) -> std::io::Result<()> {
        self.record(Event::SetFailureActions(actions));
        let result = self.inner.set_failure_actions(actions);
        self.note(Call::SetFailureActions, result)
    }

    fn delete(&mut self) -> std::io::Result<()> {
        // The read is the test's own, as in `control_stop`.
        let start_type = self.inner.start_type().ok();
        self.record(Event::Delete { start_type });
        let result = self.inner.delete();
        self.note(Call::Delete, result)
    }
}

/// What a retirement did, in order.
#[derive(Debug)]
pub struct Trace(Vec<Event>);

impl Trace {
    /// The state each look reported, in order.
    pub fn observed(&self) -> Vec<Observed> {
        self.0
            .iter()
            .filter_map(|event| match event {
                Event::Observed(look) => Some(look.observed),
                _ => None,
            })
            .collect()
    }

    /// Every act, in order.
    pub fn events(&self) -> &[Event] {
        &self.0
    }

    /// The calls the SCM refused, in order, with whether each was answered as
    /// marked for deletion.
    pub fn refusals(&self) -> Vec<(Call, bool)> {
        self.0
            .iter()
            .filter_map(|event| match event {
                Event::Refused { call, marked } => Some((*call, *marked)),
                _ => None,
            })
            .collect()
    }

    pub fn stops(&self) -> usize {
        self.0
            .iter()
            .filter(|event| matches!(event, Event::Stop { .. }))
            .count()
    }

    /// What every deregistering retirement's record must satisfy, whatever the
    /// service was doing when it began:
    ///
    /// - a Stop goes out only after a look that read RUNNING;
    /// - every Stop and the delete found the start type disabled, which is
    ///   what keeps the SCM from starting the service once it stops;
    /// - nothing follows the delete but the clearing of the record.
    pub fn assert_the_order_of_a_deregistration(&self) {
        for event in &self.0 {
            match event {
                Event::Stop { after, start_type } => {
                    assert_eq!(
                        *after,
                        Some(Observed::Running),
                        "a Stop went out after a look that did not read RUNNING: {self:#?}"
                    );
                    assert_eq!(
                        *start_type,
                        Some(StartType::Disabled),
                        "a Stop went out with the start type not disabled: {self:#?}"
                    );
                }
                Event::Delete { start_type } => assert_eq!(
                    *start_type,
                    Some(StartType::Disabled),
                    "the delete came with the start type not disabled: {self:#?}"
                ),
                _ => {}
            }
        }
        let after_the_delete = self
            .0
            .iter()
            .rev()
            .take_while(|event| matches!(event, Event::ClearRecord))
            .count();
        assert!(
            self.0.len() > after_the_delete
                && matches!(self.0[self.0.len() - after_the_delete - 1], Event::Delete { .. }),
            "the session was used after the delete, or never deleted the service: {self:#?}"
        );
    }

    /// Fails unless a Stop went out only after a look that read RUNNING.
    pub fn assert_every_stop_follows_a_running_look(&self) {
        for event in &self.0 {
            if let Event::Stop { after, .. } = event {
                assert_eq!(
                    *after,
                    Some(Observed::Running),
                    "a Stop went out after a look that did not read RUNNING: {self:#?}"
                );
            }
        }
    }

    /// What a retirement of a service found marked for deletion must satisfy:
    /// the one refusal is a start-type read or write answered as marked, every
    /// start-type write was that refusal, and no failure-actions write, delete
    /// or restore was issued.
    pub fn assert_a_start_type_call_was_refused_as_marked_and_nothing_changed(&self) {
        assert!(
            matches!(
                self.refusals().as_slice(),
                [(Call::ReadStartType | Call::SetStartType, true)]
            ),
            "the one refusal must be a start-type call answered as marked: {self:#?}"
        );
        for (at, event) in self.0.iter().enumerate() {
            match event {
                Event::SetStartType(_) => assert!(
                    matches!(
                        self.0.get(at + 1),
                        Some(Event::Refused {
                            call: Call::SetStartType,
                            ..
                        })
                    ),
                    "a start-type write was not refused: {self:#?}"
                ),
                Event::SetFailureActions(_) | Event::Delete { .. } => {
                    panic!("the retirement changed a service that was marked for deletion: {self:#?}")
                }
                _ => {}
            }
        }
        self.assert_the_record_written_was_cleared();
    }

    /// Fails unless every record the retirement wrote was cleared.
    pub fn assert_the_record_written_was_cleared(&self) {
        let count = |wanted: fn(&Event) -> bool| self.0.iter().filter(|event| wanted(event)).count();
        assert_eq!(
            count(|event| matches!(event, Event::WriteRecord)),
            count(|event| matches!(event, Event::ClearRecord)),
            "a record was written and not cleared, or cleared and not written: {self:#?}"
        );
    }

    /// Fails unless every Stop came straight after an arm for the states
    /// but RUNNING. A service whose process the retirement cannot hold has no
    /// exit to wait on, so the SCM's report of the Stop is the only event, and
    /// an arm taken after the Stop can miss it.
    pub fn assert_every_stop_follows_an_arm(&self) {
        assert!(self.stops() > 0, "no Stop was sent, so this proves nothing: {self:#?}");
        for (at, event) in self.0.iter().enumerate() {
            if !matches!(event, Event::Stop { .. }) {
                continue;
            }
            assert!(
                at > 0 && self.0[at - 1] == Event::ArmLeaving(Observed::Running),
                "a Stop was not preceded by an arm leaving RUNNING: {self:#?}"
            );
        }
    }
}

/// One act on the survivors of a removed service entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurvivorEvent {
    /// A scan, with what it found.
    HoldScanned(ScanFinding),
    AwaitExits,
}

/// Called for each act after it is recorded and before the real survivors
/// perform it, so a wait is announced before it blocks.
pub type SurvivorHook<'a> = Box<dyn FnMut(&SurvivorEvent) + 'a>;

/// Survivors over the real ones that report every act to a hook. The hook is
/// the record: `retire_over` consumes the survivors it builds, so nothing is
/// left to read after it returns.
pub struct RecordingSurvivors<'a, W> {
    inner: W,
    hook: SurvivorHook<'a>,
}

impl<'a, W> RecordingSurvivors<'a, W> {
    pub fn new(inner: W, hook: SurvivorHook<'a>) -> Self {
        Self { inner, hook }
    }
}

impl<W: Survivors> Survivors for RecordingSurvivors<'_, W> {
    fn hold_scanned(&mut self) -> std::io::Result<ScanFinding> {
        let finding = self.inner.hold_scanned()?;
        (self.hook)(&SurvivorEvent::HoldScanned(finding));
        Ok(finding)
    }

    fn await_exits(&mut self) -> std::io::Result<()> {
        (self.hook)(&SurvivorEvent::AwaitExits);
        self.inner.await_exits()
    }
}
