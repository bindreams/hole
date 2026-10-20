//! A session over the real one that records every act the retirement makes on
//! it, in order, so a test asserts the order from the record and not from the
//! outcome. The real session still does the work: the state a later look reads
//! comes from the SCM.

use hole_bridge::cutover::scm_wait::hold::Look;
use hole_bridge::cutover::scm_wait::retire::{FailureActions, ServiceSession, StartType, StartWrite};
use hole_bridge::cutover::scm_wait::settle::StopActor;
use hole_bridge::cutover::scm_wait::Observed;
use hole_bridge::platform::os::{Opening, RetireSession};

/// One act on the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A look, as it came back.
    Observed(Look),
    ArmLeaving(Observed),
    /// A Stop, with the state of the last look before it and the start type
    /// the SCM held at that moment.
    Stop {
        after: Option<Observed>,
        start_type: StartType,
    },
    AwaitCallback,
    AwaitHeldExits,
    HoldScanned,
    SetStartType(StartWrite),
    SetFailureActions(FailureActions),
    /// The delete, with the start type the SCM held at that moment.
    Delete {
        start_type: StartType,
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
        self.inner.arm_leaving(from)
    }

    fn control_stop(&mut self) -> std::io::Result<()> {
        // The read is the test's own, on the session's handle, and is not an
        // act of the retirement.
        let start_type = self.inner.start_type()?;
        let after = self.last_observed();
        self.record(Event::Stop { after, start_type });
        self.inner.control_stop()
    }

    fn await_callback(&mut self) -> std::io::Result<()> {
        self.record(Event::AwaitCallback);
        self.inner.await_callback()
    }

    fn await_held_exits(&mut self) -> std::io::Result<()> {
        self.record(Event::AwaitHeldExits);
        self.inner.await_held_exits()
    }

    fn hold_scanned(&mut self) -> std::io::Result<()> {
        self.record(Event::HoldScanned);
        self.inner.hold_scanned()
    }
}

impl<S: ServiceSession> ServiceSession for Recording<'_, S> {
    fn start_type(&mut self) -> std::io::Result<StartType> {
        self.inner.start_type()
    }

    fn set_start_type(&mut self, to: StartWrite) -> std::io::Result<()> {
        self.record(Event::SetStartType(to));
        self.inner.set_start_type(to)
    }

    fn set_failure_actions(&mut self, actions: FailureActions) -> std::io::Result<()> {
        self.record(Event::SetFailureActions(actions));
        self.inner.set_failure_actions(actions)
    }

    fn delete(&mut self) -> std::io::Result<()> {
        let start_type = self.inner.start_type()?;
        self.record(Event::Delete { start_type });
        self.inner.delete()
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
    /// - nothing follows the delete.
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
                        StartType::Disabled,
                        "a Stop went out with the start type not disabled: {self:#?}"
                    );
                }
                Event::Delete { start_type } => assert_eq!(
                    *start_type,
                    StartType::Disabled,
                    "the delete came with the start type not disabled: {self:#?}"
                ),
                _ => {}
            }
        }
        assert!(
            matches!(self.0.last(), Some(Event::Delete { .. })),
            "the session was used after the delete, or never deleted the service: {self:#?}"
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
