use super::*;
use std::cell::{Cell, RefCell};

/// Mock with single-use pre-loaded results. A call with no loaded result
/// panics, so "this method must not be called" is asserted by omission and
/// double-calls fail loudly.
struct FakeAutostart {
    is_enabled_result: RefCell<Option<Result<bool, Error>>>,
    enable_result: RefCell<Option<Result<(), Error>>>,
    disable_result: RefCell<Option<Result<(), Error>>>,
    enable_calls: Cell<usize>,
    disable_calls: Cell<usize>,
}

impl FakeAutostart {
    fn new(
        is_enabled: Result<bool, Error>,
        enable: Option<Result<(), Error>>,
        disable: Option<Result<(), Error>>,
    ) -> Self {
        Self {
            is_enabled_result: RefCell::new(Some(is_enabled)),
            enable_result: RefCell::new(enable),
            disable_result: RefCell::new(disable),
            enable_calls: Cell::new(0),
            disable_calls: Cell::new(0),
        }
    }
}

impl Autostart for FakeAutostart {
    fn is_enabled(&self) -> Result<bool, Error> {
        self.is_enabled_result
            .borrow_mut()
            .take()
            .expect("unexpected is_enabled call")
    }

    fn enable(&self) -> Result<(), Error> {
        self.enable_calls.set(self.enable_calls.get() + 1);
        self.enable_result.borrow_mut().take().expect("unexpected enable call")
    }

    fn disable(&self) -> Result<(), Error> {
        self.disable_calls.set(self.disable_calls.get() + 1);
        self.disable_result
            .borrow_mut()
            .take()
            .expect("unexpected disable call")
    }
}

#[skuld::test]
fn toggle_enables_when_disabled() {
    let fake = FakeAutostart::new(Ok(false), Some(Ok(())), None);
    let result = toggle(&fake);
    assert!(matches!(result, Ok(true)));
    assert_eq!(fake.enable_calls.get(), 1);
    assert_eq!(fake.disable_calls.get(), 0);
}

#[skuld::test]
fn toggle_disables_when_enabled() {
    let fake = FakeAutostart::new(Ok(true), None, Some(Ok(())));
    let result = toggle(&fake);
    assert!(matches!(result, Ok(false)));
    assert_eq!(fake.enable_calls.get(), 0);
    assert_eq!(fake.disable_calls.get(), 1);
}

#[skuld::test]
fn check_failure_skips_toggle() {
    let fake = FakeAutostart::new(Err(Error::Anyhow("registry denied".into())), None, None);
    let result = toggle(&fake);
    assert!(matches!(result, Err(ToggleError::Check(_))));
    assert_eq!(fake.enable_calls.get(), 0);
    assert_eq!(fake.disable_calls.get(), 0);
}

#[skuld::test]
fn enable_failure_is_reported() {
    let fake = FakeAutostart::new(Ok(false), Some(Err(Error::Anyhow("plist write failed".into()))), None);
    assert!(matches!(toggle(&fake), Err(ToggleError::Enable(_))));
    assert_eq!(fake.enable_calls.get(), 1);
    assert_eq!(fake.disable_calls.get(), 0);
}

#[skuld::test]
fn disable_failure_is_reported() {
    let fake = FakeAutostart::new(Ok(true), None, Some(Err(Error::Anyhow("plist remove failed".into()))));
    assert!(matches!(toggle(&fake), Err(ToggleError::Disable(_))));
    assert_eq!(fake.enable_calls.get(), 0);
    assert_eq!(fake.disable_calls.get(), 1);
}

#[skuld::test]
fn user_message_is_pii_free_while_log_detail_keeps_the_path() {
    // auto-launch's AppPathDoesntExist embeds the full executable path; the
    // plugin stringifies it into Error::Anyhow. The dialog string must not
    // leak it, the gui.log string must keep it.
    let underlying = "app path doesn't exist: /Users/jdoe/Applications/Hole.app";
    for (err, op_word) in [
        (ToggleError::Check(Error::Anyhow(underlying.into())), "check"),
        (ToggleError::Enable(Error::Anyhow(underlying.into())), "enable"),
        (ToggleError::Disable(Error::Anyhow(underlying.into())), "disable"),
    ] {
        let dialog = err.user_message();
        assert!(!dialog.contains("/Users/jdoe"), "dialog leaks path: {dialog}");
        assert!(dialog.contains("Start at Login"), "dialog lacks context: {dialog}");
        assert!(dialog.contains("gui.log"), "dialog lacks log pointer: {dialog}");
        assert!(
            dialog.to_lowercase().contains(op_word),
            "dialog does not say which operation failed: {dialog}"
        );

        let log_line = format!("{err}");
        assert!(log_line.contains(underlying), "log line lost detail: {log_line}");
    }
}

// set() — target-state mutation used by the dashboard (the tray uses toggle()).

#[skuld::test]
fn set_true_enables() {
    // is_enabled is loaded with an Err to prove set() never reads current state.
    let fake = FakeAutostart::new(Err(Error::Anyhow("must not read".into())), Some(Ok(())), None);
    assert!(set(&fake, true).is_ok());
    assert_eq!(fake.enable_calls.get(), 1);
    assert_eq!(fake.disable_calls.get(), 0);
}

#[skuld::test]
fn set_false_disables() {
    let fake = FakeAutostart::new(Err(Error::Anyhow("must not read".into())), None, Some(Ok(())));
    assert!(set(&fake, false).is_ok());
    assert_eq!(fake.enable_calls.get(), 0);
    assert_eq!(fake.disable_calls.get(), 1);
}

#[skuld::test]
fn set_true_enable_failure_reported() {
    let fake = FakeAutostart::new(
        Err(Error::Anyhow("must not read".into())),
        Some(Err(Error::Anyhow("plist write failed".into()))),
        None,
    );
    assert!(matches!(set(&fake, true), Err(ToggleError::Enable(_))));
    assert_eq!(fake.enable_calls.get(), 1);
}

#[skuld::test]
fn set_false_disable_failure_reported() {
    let fake = FakeAutostart::new(
        Err(Error::Anyhow("must not read".into())),
        None,
        Some(Err(Error::Anyhow("plist remove failed".into()))),
    );
    assert!(matches!(set(&fake, false), Err(ToggleError::Disable(_))));
    assert_eq!(fake.disable_calls.get(), 1);
}

// is_enabled() — live read wrapped as ToggleError::Check.

#[skuld::test]
fn is_enabled_reports_state() {
    let fake = FakeAutostart::new(Ok(true), None, None);
    assert!(matches!(is_enabled(&fake), Ok(true)));
}

#[skuld::test]
fn is_enabled_wraps_check_error() {
    let fake = FakeAutostart::new(Err(Error::Anyhow("registry denied".into())), None, None);
    assert!(matches!(is_enabled(&fake), Err(ToggleError::Check(_))));
}
