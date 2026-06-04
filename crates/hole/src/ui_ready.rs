//! UI-readiness synchronization for webdriver tests.
//!
//! The dashboard webview navigates to `tauri.localhost/index.html`
//! asynchronously after window creation. WebDriver's session is
//! established before that navigation completes, so any test that
//! interacts with the page before init() finishes is racing.
//!
//! `UiReady` provides an event-driven signal between the UI and any
//! webdriver test: `ui/main.ts::init()` calls `signal_ui_ready` at
//! the end (success or failure), and the test calls `wait_ui_ready`
//! to park on a `watch` channel until the signal arrives. No polling,
//! no timeouts in the sync path.

use tokio::sync::watch;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct UiReadyResult {
    pub ok: bool,
    pub error: Option<String>,
}

pub struct UiReady {
    tx: watch::Sender<Option<UiReadyResult>>,
}

impl Default for UiReady {
    fn default() -> Self {
        let (tx, _rx) = watch::channel(None);
        Self { tx }
    }
}

impl UiReady {
    /// Latch a result. Calling more than once overwrites the latched
    /// value; receivers that already observed the first value keep
    /// their snapshot.
    ///
    /// `send_replace` is used (rather than `send`) because the watch
    /// has no active receivers between `Default::default()` and the
    /// first [`wait`] call — `send` returns an Err in that window and
    /// silently drops the value.
    pub fn signal(&self, result: UiReadyResult) {
        self.tx.send_replace(Some(result));
    }

    /// Park until [`signal`] has been called at least once.
    pub async fn wait(&self) -> UiReadyResult {
        let mut rx = self.tx.subscribe();
        let guard = rx
            .wait_for(|state| state.is_some())
            .await
            .expect("UiReady sender held by Self; can never drop while wait() is in progress");
        guard.clone().expect("predicate guarantees Some")
    }
}

#[tauri::command]
pub async fn signal_ui_ready(state: tauri::State<'_, UiReady>, result: UiReadyResult) -> Result<(), String> {
    state.signal(result);
    Ok(())
}

#[tauri::command]
pub async fn wait_ui_ready(state: tauri::State<'_, UiReady>) -> Result<UiReadyResult, String> {
    Ok(state.wait().await)
}

#[cfg(test)]
#[path = "ui_ready_tests.rs"]
mod ui_ready_tests;
