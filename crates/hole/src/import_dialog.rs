//! The interactive import flow: pick a file, import it, report what
//! happened.
//!
//! All of it runs in this process, on purpose. File > Import lives in a
//! Rust-owned menu and the import itself is already Rust
//! ([`commands::import_file`]), so routing the click through the webview
//! would mean handing a *command* to a document that may not be listening
//! yet — an exactly-once delivery problem, over a channel
//! ([`Emitter::emit`]) that reports success as soon as it dispatches. Doing
//! the work here leaves the frontend nothing to *do*: the servers are
//! already parsed, deduped and persisted by the time
//! [`EVENT_SERVERS_IMPORTED`] goes out. A dashboard that misses it still
//! shows them on its next config load; what it skips is the summary toast
//! and the auto-test of the new entries.
//!
//! Failures are rendered here too ([`describe_failure`]) so they can be
//! shown whether or not a window is up, and so the wording has one home
//! instead of a Rust enum and a TypeScript mirror of it.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use hole_common::config::ServerEntry;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_dialog::DialogExt;
use tracing::{info, warn};

use crate::commands::{import_file, ImportFailure};
use crate::state::AppState;

/// Emitted after any import attempt that changed something or failed. The
/// dashboard's matching `listen()` is in `ui/main.ts`; nothing ties the two
/// names together but the test in `import_dialog_tests.rs`.
pub const EVENT_SERVERS_IMPORTED: &str = "servers-imported";

// ImportFlow ==========================================================================================================

/// Keeps the interactive import flow to one at a time.
///
/// Two policies, because the two things being guarded want different
/// answers to "someone else is busy":
///
/// * The **picker** *refuses*. Clicking Import while the file dialog is
///   already up should do nothing — queueing a second dialog behind the
///   first is never what the user meant.
/// * The **import** *waits*. A drop that lands mid-import is a separate
///   request the user still wants honoured, but its per-file error dialogs
///   must not stack on top of the running one's.
#[derive(Default)]
pub struct ImportFlow {
    picker_open: AtomicBool,
    running: Mutex<()>,
}

impl ImportFlow {
    /// Claim the right to open the picker, or `None` when one is already
    /// up. Dropping the returned [`PickerClaim`] releases it.
    pub fn claim_picker(self: &Arc<Self>) -> Option<PickerClaim> {
        self.picker_open
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        Some(PickerClaim(Arc::clone(self)))
    }
}

/// Holds the picker open for as long as it lives. Release is by `Drop`, so
/// every way out of the dialog — a chosen file, a cancel, an unwind —
/// frees it without a caller having to remember to.
pub struct PickerClaim(Arc<ImportFlow>);

impl Drop for PickerClaim {
    fn drop(&mut self) {
        self.0.picker_open.store(false, Ordering::Release);
    }
}

// Failure rendering ===================================================================================================

/// A failure as the user should read it.
pub struct FailureMessage {
    pub title: String,
    pub body: String,
}

/// Describe `failure` in plain language, for a reader who knows what a
/// Shadowsocks profile is but not necessarily what JSON is.
pub fn describe_failure(failure: &ImportFailure) -> FailureMessage {
    let (title, body) = match failure {
        ImportFailure::FileError { detail } => ("Could not import the file", detail.clone()),
        ImportFailure::CorruptedJson => (
            "Could not import the file",
            "This file is not valid JSON — it may be corrupted or in a wrong format.".to_string(),
        ),
        ImportFailure::UnrecognizedFormat { missing_field } => (
            "Could not import the file",
            format!(
                "This file was not recognized as a Shadowsocks configuration: \
                 the required field \"{missing_field}\" is missing."
            ),
        ),
        ImportFailure::UnsupportedPlugin { plugin, supported } => (
            "Plugin not supported",
            format!(
                "The profile uses plugin \"{plugin}\", which is not bundled with Hole. \
                 Hole bundles: {}.",
                supported.join(", ")
            ),
        ),
        ImportFailure::InvalidValue { detail } => (
            "Could not import the file",
            format!("Invalid value in the profile: {detail}."),
        ),
        // `import_file` assigns the new config only after the save
        // succeeds, so a save failure rolls the whole import back — saying
        // it "imported but could not save" would leave the user believing
        // servers are loaded that are not.
        ImportFailure::SaveFailed => (
            "Could not save the profile",
            "Hole could not save the imported profile to disk, so the import was not applied. \
             See gui.log for details."
                .to_string(),
        ),
    };
    FailureMessage {
        title: title.to_string(),
        body,
    }
}

// Outcome =============================================================================================================

/// What an import attempt did, as the dashboard needs to hear it: the
/// servers to render and auto-test, and how many files failed (each of
/// which the user has already seen a dialog for).
#[derive(Debug, Clone, Serialize)]
pub struct ImportOutcome {
    pub appended: Vec<ServerEntry>,
    pub failed: usize,
}

/// Show `message` and wait for the user to dismiss it. Blocking and
/// sequential on purpose: each failure is about one specific file, so they
/// should be acknowledged one at a time rather than collapse into a toast.
/// Must not be called on the main thread.
fn show_failure(app: &AppHandle, message: &FailureMessage) {
    app.dialog()
        .message(message.body.clone())
        .title(message.title.clone())
        .kind(tauri_plugin_dialog::MessageDialogKind::Error)
        .blocking_show();
}

/// Fold per-file results into the outcome the dashboard hears, calling
/// `report` for each failure as it happens.
///
/// Split from [`import_and_report`] so the accumulation — which decides what
/// the dashboard renders and auto-tests — is testable without an
/// `AppHandle`. Consumes `results` lazily, so `report` runs between files.
fn aggregate<'a>(
    results: impl IntoIterator<Item = Result<Vec<ServerEntry>, ImportFailure>>,
    mut report: impl FnMut(&ImportFailure) + 'a,
) -> ImportOutcome {
    let mut appended = Vec::new();
    let mut failed = 0;
    for result in results {
        match result {
            Ok(mut servers) => appended.append(&mut servers),
            Err(failure) => {
                failed += 1;
                report(&failure);
            }
        }
    }
    ImportOutcome { appended, failed }
}

// Entry points ========================================================================================================

/// Open the file picker and import what the user chooses. Returns as soon
/// as the dialog is up; the import runs off the main thread when it closes.
///
/// A click while a picker is already open is ignored — see [`ImportFlow`].
pub fn pick_and_import(app: &AppHandle) {
    let Some(claim) = app.state::<Arc<ImportFlow>>().claim_picker() else {
        info!("import: a file picker is already open; ignoring the repeat request");
        return;
    };
    let app = app.clone();
    app.dialog()
        .file()
        .set_title("Import Servers")
        .add_filter("JSON", &["json"])
        .pick_file({
            let app = app.clone();
            move |path| {
                // Held until the import finishes, so the next click can't
                // open a picker while this one's file is still being read.
                let _claim = claim;
                let Some(path) = path else {
                    info!("import: file picker cancelled");
                    return;
                };
                match path.into_path() {
                    Ok(path) => import_and_report(&app, &[path]),
                    // Every other failure in this flow gets a dialog; this
                    // one must too, or the picker just closes and nothing
                    // visibly happens.
                    Err(e) => {
                        warn!(error = %e, "import: picked file has no filesystem path");
                        show_failure(
                            &app,
                            &FailureMessage {
                                title: "Could not import the file".to_string(),
                                body: "Hole could not read the location the file picker returned.".to_string(),
                            },
                        );
                    }
                }
            }
        });
}

/// Import each of `paths`, reporting failures as they happen. Blocks until
/// every file is done, so callers on the main thread must offload it.
pub fn import_and_report(app: &AppHandle, paths: &[PathBuf]) {
    if paths.is_empty() {
        return;
    }
    // Held for the whole flow, so a second import queues behind this one's
    // dialogs instead of raising its own on top of them.
    let flow = Arc::clone(app.state::<Arc<ImportFlow>>().inner());
    // A poisoned lock only means a previous import panicked mid-dialog; the
    // guard protects sequencing, not data, so carry on.
    let _running = flow.running.lock().unwrap_or_else(|e| e.into_inner());
    let state = app.state::<AppState>();
    // Lazy on purpose: each file is read, then its failure acknowledged,
    // before the next one starts.
    let outcome = aggregate(paths.iter().map(|path| import_file(&state, path)), |failure| {
        show_failure(app, &describe_failure(failure))
    });

    // Announced even when nothing was appended: `apply_import` heals the
    // selected server, so an all-duplicate import can still have changed —
    // and persisted — what the dashboard should be rendering.
    info!(
        appended = outcome.appended.len(),
        failed = outcome.failed,
        "import: finished"
    );
    // Best-effort: the servers are already persisted, so a dashboard that
    // misses this just shows them on its next config load.
    if let Err(e) = app.emit(EVENT_SERVERS_IMPORTED, &outcome) {
        warn!(error = %e, "import: failed to announce the imported servers");
    }
}

// Tauri commands ======================================================================================================

/// Open the import file picker. The dashboard's import zone calls this so
/// that clicking it and choosing File > Import are the same code path.
#[tauri::command]
pub fn import_from_dialog(app: AppHandle) {
    pick_and_import(&app);
}

/// Import files the user dropped onto the dashboard. Takes no
/// [`PickerClaim`], since no picker is involved — the paths come from the
/// drop — but it still serializes behind any running import via
/// [`ImportFlow`]'s `running` lock, so it can block for as long as another
/// import's dialogs stay unanswered.
#[tauri::command]
pub fn import_dropped_files(app: AppHandle, paths: Vec<PathBuf>) {
    tauri::async_runtime::spawn(async move {
        // `blocking_show` inside must not run on the main thread, and this
        // can sit through several dialogs the user has to answer. The handle
        // is awaited rather than dropped so a panic is reported, not lost.
        let done = tauri::async_runtime::spawn_blocking(move || import_and_report(&app, &paths));
        if let Err(e) = done.await {
            warn!(error = %e, "import: dropped-file import failed");
        }
    });
}

#[cfg(test)]
#[path = "import_dialog_tests.rs"]
mod import_dialog_tests;
