// System tray icon and menu.

use crate::commands::build_proxy_config;
use crate::state::AppState;
use hole::tray_icons;
use hole_common::config::StartupBehavior;
use hole_common::protocol::{BridgeRequest, BridgeResponse};
use serde::Serialize;
use tauri::menu::{CheckMenuItem, MenuEvent, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};
use tracing::{debug, error, info, warn};

// ToggleOutcome =======================================================================================================

/// Result of a `set_proxy_enabled` call, distinguishing an ordinary
/// state transition from a user-initiated cancellation of a Start.
/// The frontend maps these variants to its own state machine (see
/// `ui/connection-state.ts`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ToggleOutcome {
    /// Proxy is now running.
    Running,
    /// Proxy is now stopped.
    Stopped,
    /// The Start was cancelled via `cancel_proxy` before it could finish;
    /// proxy is back in the Stopped state. Never returned by
    /// `set_proxy_enabled(false)` — stop is not cancellable.
    Cancelled,
}

/// Marks a connect/disconnect operation as in flight. One transition at a
/// time: a concurrent opposite toggle is rejected instead of queuing a
/// contradictory Start/Stop behind the bridge lock (a user's cancel must
/// not be overtaken by a queued second Start). The target also drives the
/// tray's Connecting…/Disconnecting… rendering. Tauri-managed state,
/// registered in `main.rs` setup.
pub(crate) struct TransitionSlot {
    target: std::sync::Mutex<Option<bool>>,
}

impl TransitionSlot {
    pub(crate) fn new() -> Self {
        Self {
            target: std::sync::Mutex::new(None),
        }
    }

    /// Claim the slot for a transition toward `target`. False if another
    /// transition is already in flight.
    pub(crate) fn try_begin(&self, target: bool) -> bool {
        let mut slot = self.target.lock().unwrap();
        if slot.is_some() {
            return false;
        }
        *slot = Some(target);
        true
    }

    pub(crate) fn end(&self) {
        *self.target.lock().unwrap() = None;
    }

    pub(crate) fn target(&self) -> Option<bool> {
        *self.target.lock().unwrap()
    }
}

/// Decision derived from a Start/Stop exchange. Pure — the dialog and
/// elevation glue in `set_proxy_enabled` interprets `NeedsElevation`.
pub(crate) enum StartDecision {
    Outcome(ToggleOutcome),
    NeedsElevation,
    Fail(String),
}

/// Single producer of the user-facing bridge-error string, shared by the elevated
/// and non-elevated paths so they read identically. The bridge message is shown
/// raw: it is authored by the bridge running as a system account (LocalSystem /
/// root) with system-scoped paths, and `ProxyConfig` carries no path field, so it
/// cannot contain user PII (#475). A future change that threads a user path into a
/// bridge request and echoes it here must revisit this.
pub(crate) fn bridge_error_toast(message: &str) -> String {
    format!("Bridge error: {message}")
}

/// Toast shown for a concurrent-start rejection (409). Shared by the live-Connect
/// (`outcome_for_start_response`) and elevated (`elevate_and_confirm`) paths so the
/// two surfaces read identically.
pub(crate) const CONCURRENT_START_MESSAGE: &str = "Another start is already in progress.";

/// Final toast for a typed start failure, shared by the live-Connect and elevated
/// paths so they read identically. `NetworkBlocked` is host-free and self-contained
/// (shown raw); every other genuine failure is wrapped by [`bridge_error_toast`].
/// Cancelled/AlreadyRunning are routed to outcomes by callers and don't reach here;
/// if one does, log it and render a safe generic string rather than panic.
pub(crate) fn start_error_toast(kind: &hole_common::protocol::StartError) -> String {
    use hole_common::protocol::StartError;
    match kind {
        StartError::NetworkBlocked => hole_common::protocol::NETWORK_BLOCKED_MESSAGE.to_string(),
        StartError::Failed { message } => bridge_error_toast(message),
        StartError::Cancelled | StartError::AlreadyRunning => {
            warn!(?kind, "start_error_toast reached with a non-failure variant");
            bridge_error_toast("unexpected start outcome")
        }
    }
}

/// Toast for a transport failure observed AFTER a successful elevation — the
/// bridge is unreachable, which is not an elevation denial.
pub(crate) fn transport_after_elevation_toast(detail: &str) -> String {
    format!("Could not reach the Hole bridge after elevation. {detail} See gui.log for details.")
}

/// Toast shown when an externally-supervised bridge (`HOLE_BRIDGE_SOCKET`)
/// denies the connection. Hole will not elevate in this mode: the elevated
/// `hole bridge ipc-send` helper connects to the default production socket, not
/// this caller-provided one, so elevation would mis-target (#569). The
/// underlying permission error still lands in `gui.log`.
pub(crate) fn external_bridge_denied_toast() -> String {
    "Permission denied by the bridge. Hole does not elevate an externally-supervised bridge \
     (HOLE_BRIDGE_SOCKET); ensure your user was granted access to its socket. See gui.log for details."
        .into()
}

/// Resolution of a bridge `NeedsElevation` signal, before any UI. Pure so the
/// matrix (externally-supervised × prompts × disconnect) is unit-tested.
pub(crate) enum ElevationDecision {
    /// Run the elevated helper (interactive UAC/osascript).
    Elevate,
    /// Do not elevate; fail with this toast.
    Decline(String),
}

/// Decide whether a `NeedsElevation` should actually elevate.
/// - Externally supervised (`HOLE_BRIDGE_SOCKET`): never — the elevated helper
///   targets the default production socket, not this one (#569). Checked first,
///   so it overrides the disconnect/prompts rules below.
/// - Disconnect (when GUI-owned) is always interactive, so it may elevate.
/// - Connect may elevate only when prompts are allowed; an unattended startup
///   auto-connect (#458) fails passively instead of throwing UAC at a login.
pub(crate) fn decide_elevation(
    externally_supervised: bool,
    prompts: Prompts,
    is_disconnect: bool,
) -> ElevationDecision {
    if externally_supervised {
        return ElevationDecision::Decline(external_bridge_denied_toast());
    }
    if is_disconnect {
        return ElevationDecision::Elevate;
    }
    match prompts {
        Prompts::Allowed => ElevationDecision::Elevate,
        Prompts::Forbidden => {
            ElevationDecision::Decline("Connecting requires elevation, which is unavailable at startup.".into())
        }
    }
}

pub(crate) fn outcome_for_start_response(
    result: &Result<BridgeResponse, crate::bridge_client::ClientError>,
) -> StartDecision {
    use crate::bridge_client::ClientError;
    use hole_common::protocol::StartError;
    match result {
        Ok(BridgeResponse::Ack) => StartDecision::Outcome(ToggleOutcome::Running),
        Ok(BridgeResponse::StartFailed(e)) => match e {
            StartError::Cancelled => StartDecision::Outcome(ToggleOutcome::Cancelled),
            StartError::AlreadyRunning => StartDecision::Outcome(ToggleOutcome::Running),
            StartError::NetworkBlocked | StartError::Failed { .. } => StartDecision::Fail(start_error_toast(e)),
        },
        // An unexpected variant on the Start path is a same-build contract breach —
        // warn and fail gracefully (no panic), never silently treat it as success.
        Ok(other) => {
            warn!(?other, "unexpected bridge response on the start path");
            StartDecision::Fail("Unexpected response from bridge".into())
        }
        Err(ClientError::PermissionDenied) => StartDecision::NeedsElevation,
        Err(ClientError::ConcurrentStart) => StartDecision::Fail(CONCURRENT_START_MESSAGE.into()),
        Err(e) => StartDecision::Fail(format!("Failed to connect to bridge: {e}")),
    }
}

pub(crate) fn outcome_for_stop_response(
    result: &Result<BridgeResponse, crate::bridge_client::ClientError>,
) -> StartDecision {
    match result {
        Ok(BridgeResponse::Ack) => StartDecision::Outcome(ToggleOutcome::Stopped),
        Ok(BridgeResponse::Error { message }) => StartDecision::Fail(bridge_error_toast(message)),
        Ok(_) => StartDecision::Fail("Unexpected response from bridge".into()),
        Err(crate::bridge_client::ClientError::PermissionDenied) => StartDecision::NeedsElevation,
        Err(e) => StartDecision::Fail(format!("Failed to connect to bridge: {e}")),
    }
}

/// Sole writer of persisted `config.enabled` (#462): records the last user
/// intent the bridge honored. Read at launch by `startup_should_connect` for
/// `StartupBehavior::RestoreLastState` (#458); display and direction still come
/// from the `ProxyStateCell`, never this flag.
pub(crate) fn persist_intended_enabled(
    config: &std::sync::Mutex<hole_common::config::AppConfig>,
    store: &hole_common::config_store::ConfigStore,
    enabled: bool,
) {
    let mut config = config.lock().unwrap();
    if config.enabled == enabled {
        return;
    }
    config.enabled = enabled;
    if let Err(e) = store.save(&config) {
        warn!(error = %e, path = %store.path().display(), "failed to persist intended enabled state");
    }
}

/// Pure launch-time decision (#458): should the GUI auto-connect now?
/// `last_enabled` is the persisted last-honored intent (#462), read only here.
/// The exhaustive match makes a future `StartupBehavior` variant a compile error.
pub(crate) fn startup_should_connect(behavior: StartupBehavior, last_enabled: bool) -> bool {
    match behavior {
        StartupBehavior::DoNotConnect => false,
        StartupBehavior::RestoreLastState => last_enabled,
        StartupBehavior::AlwaysConnect => true,
    }
}

/// Install-gate decision (#569). The GUI prompts to install the production bridge
/// service only when it OWNS the bridge lifecycle. When the bridge is externally
/// supervised (`HOLE_BRIDGE_SOCKET` — dev-console / manual dev run) a live bridge
/// is already reachable on that socket and the production install state (launchd
/// plist / SCM service) is irrelevant, so the gate must never fire — otherwise
/// dev mode demands admin to install a service over an already-running bridge.
/// `status_fn` is lazy so the production status probe (a stat, and on macOS a
/// `launchctl` subprocess) is skipped entirely when externally supervised.
pub(crate) fn should_prompt_install(
    externally_supervised: bool,
    status_fn: impl FnOnce() -> crate::setup::BridgeInstallStatus,
) -> bool {
    !externally_supervised && status_fn() == crate::setup::BridgeInstallStatus::NotInstalled
}

// Menu IDs ============================================================================================================

// Tray menu -----------------------------------------------------------------------------------------------------------
const ID_STATUS: &str = "status";
const ID_CONNECT: &str = "connect";
const ID_DISCONNECT: &str = "disconnect";
const ID_AUTOSTART: &str = "autostart";
const ID_SETTINGS: &str = "settings";
const ID_EXIT: &str = "exit";
const ID_INSTALL_UPDATE: &str = "install_update";
const ID_LOCKDOWN: &str = "lockdown";
const ID_BLOCKED_RETRY: &str = "blocked_retry";

// Window menu ---------------------------------------------------------------------------------------------------------
const ID_WINDOW_IMPORT: &str = "window_import";
const ID_WINDOW_EXIT: &str = "window_exit";
#[cfg(target_os = "macos")]
const ID_UNINSTALL_HELPER: &str = "uninstall_helper";
const ID_ABOUT: &str = "about";
const ID_CHECK_UPDATE: &str = "check_update";
const ID_COLLECT_LOGS: &str = "window_collect_logs";

// Tray creation =======================================================================================================

/// Tray label for the lockdown toggle from the (enabled, active) snapshot.
/// `enabled && !active` is a warning state — never silent green (#527).
fn lockdown_menu_label(enabled: bool, active: bool) -> String {
    match (enabled, active) {
        (true, true) => "Lockdown: On".into(),
        (true, false) => "Lockdown: On (warning: not engaged)".into(),
        (false, _) => "Lockdown".into(),
    }
}

/// The status line + primary action a tray menu should render, from the observed
/// state. Pure so `tray_tests` cover the blocked-state UX without Tauri. `blocked`
/// (a covered start failed → host fail-closed while not running) is a distinct
/// state — never silent Disconnected — offering Retry (covered re-connect) plus a
/// Go-Offline that releases the cover. It applies only when not running and not
/// mid-transition (a live transition or a running proxy takes precedence).
struct TrayActions {
    status: &'static str,
    action_id: &'static str,
    action_text: &'static str,
    show_go_offline: bool,
}

fn tray_actions(running: bool, transition: Option<bool>, blocked: bool) -> TrayActions {
    if blocked && !running && transition.is_none() {
        return TrayActions {
            status: "Blocked — connect failed",
            action_id: ID_BLOCKED_RETRY,
            action_text: "Retry",
            show_go_offline: true,
        };
    }
    let status = match (transition, running) {
        (Some(true), _) => "Connecting...",
        (Some(false), _) => "Disconnecting...",
        (None, true) => "Connected",
        (None, false) => "Disconnected",
    };
    let (action_id, action_text) = if running {
        (ID_DISCONNECT, "Disconnect")
    } else {
        (ID_CONNECT, "Connect")
    };
    TrayActions {
        status,
        action_id,
        action_text,
        show_go_offline: false,
    }
}

/// Build the tray menu, optionally including an "Install Update" item.
///
/// `running` is the bridge's actual state (from the `ProxyStateCell`,
/// never persisted config — #462); `transition` is an in-flight
/// connect/disconnect target, rendered as Connecting…/Disconnecting…
/// with the action item disabled. `lockdown_enabled`/`lockdown_active` render
/// the standing kill-switch toggle (#527).
fn build_tray_menu(
    app: &AppHandle,
    update: Option<&hole::update::UpdateInfo>,
    running: bool,
    transition: Option<bool>,
    lockdown_enabled: bool,
    lockdown_active: bool,
    blocked: bool,
) -> Result<tauri::menu::Menu<tauri::Wry>, tauri::Error> {
    // The action item carries the intent its label displays: a click dispatches
    // on the item ID, with no state read at click time (#462).
    let acts = tray_actions(running, transition, blocked);

    let status = MenuItem::with_id(app, ID_STATUS, acts.status, false, None::<&str>)?;
    let connect = MenuItem::with_id(
        app,
        acts.action_id,
        acts.action_text,
        transition.is_none(),
        None::<&str>,
    )?;
    // Shown only in the blocked state: releases the fail-closed cover and goes
    // offline (unprotected) — the deliberate escape from a stay-blocked host.
    let go_offline = MenuItem::with_id(
        app,
        ID_DISCONNECT,
        "Go Offline (unblock)",
        transition.is_none(),
        None::<&str>,
    )?;
    let autostart = CheckMenuItem::with_id(app, ID_AUTOSTART, "Start at Login", true, false, None::<&str>)?;
    // Checked tracks intent; the warning label covers the enabled-but-inactive
    // state since a checkmark alone can't signal "armed but not engaged".
    let lockdown = CheckMenuItem::with_id(
        app,
        ID_LOCKDOWN,
        lockdown_menu_label(lockdown_enabled, lockdown_active),
        true,
        lockdown_enabled,
        None::<&str>,
    )?;
    let settings = MenuItem::with_id(app, ID_SETTINGS, "Dashboard...", true, None::<&str>)?;
    let sep1 = PredefinedMenuItem::separator(app)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let sep3 = PredefinedMenuItem::separator(app)?;
    let exit = MenuItem::with_id(app, ID_EXIT, "Exit", true, None::<&str>)?;
    let update_item = match update {
        Some(info) => Some(MenuItem::with_id(
            app,
            ID_INSTALL_UPDATE,
            format!("Install Update (v{})", info.version),
            true,
            None::<&str>,
        )?),
        None => None,
    };

    let mut items: Vec<&dyn tauri::menu::IsMenuItem<tauri::Wry>> = vec![&status, &connect];
    if acts.show_go_offline {
        items.push(&go_offline);
    }
    items.extend([
        &sep1 as &dyn tauri::menu::IsMenuItem<tauri::Wry>,
        &autostart,
        &lockdown,
        &settings,
        &sep2,
    ]);
    if let Some(ref u) = update_item {
        items.push(u);
        items.push(&sep3);
    }
    items.push(&exit);
    tauri::menu::Menu::with_items(app, &items)
}

/// Sync the autostart checkbox from the OS autostart registration. Status
/// and connect/disconnect text are baked into the menu at build time.
///
/// Must run on the main thread: the menu-item setters dispatch to the main
/// thread and block when called from anywhere else, so a caller holding a
/// lock here can deadlock the app.
fn sync_autostart_state(app: &AppHandle, menu: &tauri::menu::Menu<tauri::Wry>) {
    if let Some(item) = menu.get(ID_AUTOSTART) {
        if let Some(check) = item.as_check_menuitem() {
            use tauri_plugin_autostart::ManagerExt;
            let is_enabled = match app.autolaunch().is_enabled() {
                Ok(enabled) => enabled,
                Err(e) => {
                    // Unreadable state renders as unchecked; detail to gui.log.
                    warn!(error = %e, "failed to check autostart state during menu sync");
                    false
                }
            };
            if let Err(e) = check.set_checked(is_enabled) {
                warn!(error = %e, "failed to sync autostart checkmark");
            }
        }
    }
}

/// Create and register the system tray icon with its menu.
///
/// Renders from the `ProxyStateCell` (false until the first Status lands),
/// never from persisted config — a relaunch can no longer show "Connected"
/// over no tunnel (#462); the status reconciler's immediate first tick
/// corrects the genuine bridge-survived-a-GUI-crash case.
pub fn create_tray(app: &tauri::App) -> Result<TrayIcon, tauri::Error> {
    let snap = app.state::<AppState>().proxy_snapshot();
    let menu = build_tray_menu(
        app.handle(),
        None,
        snap.running,
        None,
        snap.lockdown_enabled,
        snap.lockdown_active,
        snap.blocked_until_connected,
    )?;
    let icon = tray_icons::tray_image(snap.running.into());

    #[allow(unused_mut)]
    let mut builder = TrayIconBuilder::with_id("main")
        .menu(&menu)
        .tooltip("Hole")
        .icon(icon)
        .show_menu_on_left_click(false)
        .on_menu_event(handle_tray_event)
        .on_tray_icon_event(handle_tray_icon_event);

    #[cfg(target_os = "macos")]
    {
        builder = builder.icon_as_template(true);
    }

    let tray = builder.build(app)?;

    sync_autostart_state(app.handle(), &menu);

    Ok(tray)
}

// Proxy state management ==============================================================================================

/// Rebuild the tray menu and icon to sync with the actual proxy state.
///
/// Preserves the "Install Update" item if an update is available.
///
/// The whole rebuild (state reads included) is dispatched to the main
/// thread: worker-thread callers would otherwise read state on one
/// thread and commit the menu later via a queued `set_menu`, letting a
/// stale menu overwrite a newer one (#473). The icon is committed inside
/// the same ordered closure for the same reason (#492 — a worker-thread
/// read paired with a queued `set_icon` can commit a stale icon).
/// `run_on_main_thread` executes inline when already on the main thread.
pub fn rebuild_tray_menu(app: &AppHandle) {
    let handle = app.clone();
    let dispatched = app.run_on_main_thread(move || {
        let Some(tray) = handle.tray_by_id("main") else {
            warn!("tray not found, skipping menu rebuild");
            return;
        };
        let update_state = handle.state::<hole::update::UpdateState>();
        let update_info = update_state.rx.borrow().clone();
        let snap = handle.state::<AppState>().proxy_snapshot();
        let transition = handle.state::<TransitionSlot>().target();
        match build_tray_menu(
            &handle,
            update_info.as_ref(),
            snap.running,
            transition,
            snap.lockdown_enabled,
            snap.lockdown_active,
            snap.blocked_until_connected,
        ) {
            Ok(menu) => {
                sync_autostart_state(&handle, &menu);
                // Sanctioned `set_menu` site: the one ordered commit point
                // (clippy.toml bans it everywhere else).
                #[allow(clippy::disallowed_methods)]
                if let Err(e) = tray.set_menu(Some(menu)) {
                    warn!(error = %e, "failed to set tray menu");
                }
            }
            Err(e) => warn!(error = %e, "failed to rebuild tray menu"),
        }
        // `true` mirrors the build-time `icon_as_template(true)`; on
        // non-macOS this falls back to plain `set_icon` (see #469).
        if let Err(e) = tray.set_icon_with_as_template(Some(tray_icons::tray_image(snap.running.into())), true) {
            warn!(error = %e, "failed to set tray icon");
        }
    });
    if let Err(e) = dispatched {
        warn!(error = %e, "failed to dispatch tray menu rebuild");
    }
}

/// Send a best-effort Stop to the bridge and exit the application.
///
/// Persisted `config.enabled` is deliberately untouched: it is the record of
/// the last honored intent (the `RestoreLastState` input read at next launch by
/// `startup_should_connect`, #458), and the tray renders from bridge Status,
/// never from that flag (#462).
async fn exit_app(app: AppHandle) {
    let state = app.state::<AppState>();
    let _ = state.bridge_send(BridgeRequest::Stop).await;
    app.exit(0);
}

/// RAII transition marker: registers the target so the tray renders
/// Connecting…/Disconnecting… (action item disabled), and a concurrent
/// opposite toggle is rejected instead of queuing a contradictory
/// Start/Stop behind the bridge lock (a user's cancel must not be
/// overtaken by a queued second Start).
struct TransitionGuard {
    app: AppHandle,
}

impl TransitionGuard {
    fn begin(app: &AppHandle, target: bool) -> Option<Self> {
        if !app.state::<TransitionSlot>().try_begin(target) {
            return None;
        }
        let guard = Self { app: app.clone() };
        rebuild_tray_menu(&guard.app);
        Some(guard)
    }
}

impl Drop for TransitionGuard {
    fn drop(&mut self) {
        self.app.state::<TransitionSlot>().end();
        rebuild_tray_menu(&self.app);
    }
}

/// Translate an elevated send into the final outcome, attributing failure
/// honestly: a propagated bridge error reads identically to the non-elevated
/// path, a post-elevation transport failure is not a denial, and only a real
/// `Cancelled`/`LaunchFailure` keeps the elevation framing.
///
/// On success, elevation bypassed the pooled bridge channel, so the actual state
/// is confirmed via a tracked Status: the commit (inside `BridgeLink::send`)
/// updates the tray and the webview, and the returned outcome — which the caller
/// persists as the last honored intent — is derived from that confirmed
/// snapshot, never from the elevated helper's claim of success.
async fn elevate_and_confirm(app: &AppHandle, request: BridgeRequest) -> Result<ToggleOutcome, String> {
    use crate::elevation::ElevationResult;
    match crate::elevation::prompt_elevation(app, request).await {
        ElevationResult::Success => {
            let state = app.state::<AppState>();
            let _ = state.bridge_send(BridgeRequest::Status).await;
            Ok(if state.proxy_snapshot().running {
                ToggleOutcome::Running
            } else {
                ToggleOutcome::Stopped
            })
        }
        ElevationResult::StartFailed(error) => Err(start_error_toast(&error)),
        ElevationResult::ConcurrentStart => Err(CONCURRENT_START_MESSAGE.into()),
        ElevationResult::BridgeError(message) => Err(bridge_error_toast(&message)),
        ElevationResult::Transport(detail) => Err(transport_after_elevation_toast(&detail)),
        ElevationResult::Cancelled => Err("Elevation was cancelled.".into()),
        ElevationResult::LaunchFailure => Err("The elevated helper could not start. See gui.log for details.".into()),
    }
}

/// Whether a connect attempt may surface UI that demands a human: the
/// bridge-install prompt, the UAC/elevation prompt, an error modal.
/// `Forbidden` is the unattended startup auto-connect path (#458) — it must
/// fail passively into the tray's Disconnected state, never block a login on a
/// modal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Prompts {
    Allowed,
    Forbidden,
}

/// Interactive connect/disconnect entry — the tray menu items and the
/// `start_proxy`/`stop_proxy` commands. Delegates with prompts allowed.
///
/// A manual action supersedes the boot-connect intent (#458): consume the latch
/// so a later reconciler tick can't override the user's explicit choice.
pub async fn set_proxy_enabled(app: &AppHandle, enable: bool, attempt_id: String) -> Result<ToggleOutcome, String> {
    app.state::<AppState>().take_pending_startup_connect();
    // A manual connect is fail-open (covered=false): the user clicked Connect and
    // is not yet protected; only the auto-connect intent stays blocked on failure.
    set_proxy_enabled_inner(app, enable, false, Prompts::Allowed, attempt_id).await
}

/// The sole non-interactive connect entry — startup auto-connect (#458).
/// Connect-only by construction (no `enable` param), so silent-disconnect is
/// unrepresentable; the shared #462 commit tail stays single-sourced. This is
/// the block-until-connected intent, so it starts covered (stays blocked on
/// failure).
async fn connect_silently(app: &AppHandle) -> Result<ToggleOutcome, String> {
    set_proxy_enabled_inner(app, true, true, Prompts::Forbidden, uuid::Uuid::new_v4().to_string()).await
}

/// Set the proxy to the given enabled state. Returns a `ToggleOutcome`
/// describing whether the proxy ended up Running, Stopped, or the Start
/// was Cancelled before it could complete (only when `enable == true`).
///
/// There is no optimistic state flip and no revert: the bridge exchange
/// itself commits the observed truth to the `ProxyStateCell` (inside the
/// client lock), the state-sync watcher repaints the tray and notifies
/// the webview, and persisted `config.enabled` records only an intent
/// the bridge actually honored. On failure, one follow-up Status commits
/// reality — a failed Disconnect can no longer re-assert "Connected"
/// over a stopped tunnel. Used by the tray menu items and the
/// `start_proxy`/`stop_proxy` commands.
///
/// `prompts` is consulted only on the enable path's two prompt sites (the
/// bridge-install gate and the elevation fallback): `Allowed` shows the UI;
/// `Forbidden` (unattended startup) suppresses both and fails passively. The
/// disconnect path is always interactive (startup never disconnects).
async fn set_proxy_enabled_inner(
    app: &AppHandle,
    enable: bool,
    covered: bool,
    prompts: Prompts,
    attempt_id: String,
) -> Result<ToggleOutcome, String> {
    let state = app.state::<AppState>();

    // Bridge install gate: when the GUI owns the bridge lifecycle and no
    // production service is installed, prompt to install BEFORE anything else.
    // An externally-supervised bridge (HOLE_BRIDGE_SOCKET, dev) skips this
    // entirely — it is already reachable on its own socket (#569).
    if enable
        && should_prompt_install(
            state.bridge_is_externally_supervised(),
            crate::setup::bridge_install_status,
        )
    {
        match prompts {
            Prompts::Allowed => {
                if !crate::setup::prompt_bridge_install(app.clone()).await {
                    return Err("The Hole bridge must be installed to connect.".into());
                }
            }
            // Startup must not throw an admin install wizard at a login.
            Prompts::Forbidden => return Err("The Hole bridge is not installed.".into()),
        }
    }

    // Resolve the start payload BEFORE claiming the transition slot — a
    // request that cannot proceed must not flash "Connecting..." in the
    // tray.
    let proxy_config = if enable {
        let config = state.config.lock().unwrap();
        match build_proxy_config(&config) {
            Some(pc) => Some(pc),
            None => {
                return Err("No server is selected. Open the Dashboard and select a server before connecting.".into())
            }
        }
    } else {
        None
    };

    let Some(_transition) = TransitionGuard::begin(app, enable) else {
        return Err("Another connect or disconnect is already in progress.".into());
    };

    let result: Result<ToggleOutcome, String> = if enable {
        let request = BridgeRequest::Start {
            config: proxy_config.expect("built above for the enable path"),
            attempt_id,
            covered,
        };
        let response = state.bridge_send(request.clone()).await;
        match outcome_for_start_response(&response) {
            StartDecision::Outcome(outcome) => {
                info!(?outcome, "proxy start settled");
                Ok(outcome)
            }
            StartDecision::NeedsElevation => {
                match decide_elevation(state.bridge_is_externally_supervised(), prompts, false) {
                    ElevationDecision::Elevate => elevate_and_confirm(app, request).await,
                    // Externally-supervised bridge or an unattended startup: no UAC;
                    // fail into Disconnected.
                    ElevationDecision::Decline(msg) => {
                        debug!("proxy start needs elevation but declining: {msg}");
                        Err(msg)
                    }
                }
            }
            StartDecision::Fail(msg) => {
                error!("proxy start failed: {msg}");
                Err(msg)
            }
        }
    } else {
        let request = BridgeRequest::Stop;
        let response = state.bridge_send(request.clone()).await;
        match outcome_for_stop_response(&response) {
            StartDecision::Outcome(outcome) => {
                info!(?outcome, "proxy stop settled");
                Ok(outcome)
            }
            StartDecision::NeedsElevation => {
                match decide_elevation(state.bridge_is_externally_supervised(), prompts, true) {
                    ElevationDecision::Elevate => elevate_and_confirm(app, request).await,
                    ElevationDecision::Decline(msg) => Err(msg),
                }
            }
            StartDecision::Fail(msg) => {
                error!("proxy stop failed: {msg}");
                Err(msg)
            }
        }
    };

    match &result {
        Ok(outcome) => {
            persist_intended_enabled(
                &state.config,
                &state.config_store,
                matches!(outcome, ToggleOutcome::Running),
            );
        }
        Err(_) => {
            // The failed exchange may have committed nothing (Stop+Error)
            // or a pessimistic false; one linearized Status commits truth.
            let _ = state.bridge_send(BridgeRequest::Status).await;
        }
    }

    result
}

// Tray event handler ==================================================================================================

/// Handle clicks on the tray icon itself (not menu items).
///
/// Left-click opens the dashboard. Right-click is left to the platform default,
/// which opens the context menu (we set `show_menu_on_left_click(false)` so
/// left-click does not also open the menu).
fn handle_tray_icon_event(tray: &TrayIcon, event: TrayIconEvent) {
    if let TrayIconEvent::Click {
        button: MouseButton::Left,
        button_state: MouseButtonState::Up,
        ..
    } = event
    {
        open_settings_window(tray.app_handle());
    }
}

/// Handle events from the tray menu.
///
/// Separated from `handle_window_menu_event` because Tauri v2 dispatches menu events globally
/// to all registered `on_menu_event` handlers. Without the split, clicking a tray item would
/// also invoke the window's handler (and vice versa), causing actions to fire twice.
fn handle_tray_event(app: &AppHandle, event: MenuEvent) {
    match event.id().as_ref() {
        // The clicked item's ID carries the user's intent — the intent the
        // displayed label offered, not a flip of any state read now (#462).
        id @ (ID_CONNECT | ID_DISCONNECT) => {
            let enable = id == ID_CONNECT;
            info!(enable, "tray: connect/disconnect clicked");
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                // Tray-initiated connect has no paired user Cancel, so a fresh
                // per-attempt id suffices (it will never be matched by a cancel).
                let attempt_id = uuid::Uuid::new_v4().to_string();
                match set_proxy_enabled(&app_handle, enable, attempt_id).await {
                    Ok(ToggleOutcome::Running) | Ok(ToggleOutcome::Stopped) => { /* watcher repaints */ }
                    Ok(ToggleOutcome::Cancelled) => {
                        // Tray never initiates Cancel itself, so this is an
                        // observer effect: the frontend cancelled while the
                        // tray-triggered Start was still in flight. The
                        // cancelled exchange already committed not-running.
                        info!("tray: start was cancelled externally");
                    }
                    Err(msg) => {
                        // blocking_show would park a core async worker here;
                        // use the blocking pool.
                        tauri::async_runtime::spawn_blocking(move || {
                            use tauri_plugin_dialog::DialogExt;
                            app_handle.dialog().message(msg).title("Error").blocking_show();
                        });
                    }
                }
            });
        }
        ID_BLOCKED_RETRY => {
            info!("tray: retry clicked from the blocked state");
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                // Covered retry: re-attempt under the held cover (stays blocked on failure).
                match connect_silently(&app_handle).await {
                    Ok(outcome) => info!(?outcome, "blocked-state retry settled"),
                    Err(reason) => info!(%reason, "blocked-state retry did not connect"),
                }
            });
        }
        ID_AUTOSTART => {
            info!("tray: autostart toggled");
            use tauri_plugin_autostart::ManagerExt;
            let result = crate::autostart::toggle(&*app.autolaunch());
            // muda flipped the checkmark before this handler ran; rebuilding
            // re-syncs it from the real autostart state — required on failure,
            // and on success too when the menu was stale.
            rebuild_tray_menu(app);
            match result {
                Ok(enabled) => info!("autostart {}", if enabled { "enabled" } else { "disabled" }),
                Err(e) => {
                    // Full detail (may embed the executable path) goes to
                    // gui.log; the dialog gets the PII-free summary.
                    error!("{e}");
                    let message = e.user_message();
                    let app_handle = app.clone();
                    // spawn_blocking: blocking_show must not run on the main
                    // thread and would park a core async worker if spawned.
                    tauri::async_runtime::spawn_blocking(move || {
                        use tauri_plugin_dialog::DialogExt;
                        app_handle.dialog().message(message).title("Error").blocking_show();
                    });
                }
            }
        }
        ID_SETTINGS => {
            info!("tray: opening settings");
            open_settings_window(app);
        }
        ID_EXIT => {
            info!("tray: exit requested");
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move { exit_app(app_handle).await });
        }
        ID_INSTALL_UPDATE => {
            info!("tray: install update requested");
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                handle_install_update_from_tray(app_handle).await;
            });
        }
        ID_LOCKDOWN => {
            // muda flipped the checkmark before this handler ran. The desired
            // intent is the inverse of the snapshot we rendered from. The
            // bridge is the authority (last-writer-wins); send intent, re-fetch
            // Status (which commits the new lockdown fields into the snapshot),
            // then rebuild from the authoritative reply.
            let desired = !app.state::<AppState>().proxy_snapshot().lockdown_enabled;
            info!(desired, "tray: lockdown toggled");
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let state = app_handle.state::<AppState>();
                if let Err(e) = state.bridge_send(BridgeRequest::SetLockdown { enabled: desired }).await {
                    error!(error = %e, "tray: SetLockdown failed");
                }
                let _ = state.bridge_send(BridgeRequest::Status).await; // commits new snapshot
                rebuild_tray_menu(&app_handle);
            });
        }
        _ => {}
    }
}

// Window event handler ================================================================================================

/// Handle events from the dashboard window menu bar. See `handle_tray_event` for why this is separate.
fn handle_window_menu_event(window: &tauri::Window, event: MenuEvent) {
    let app = window.app_handle();
    match event.id().as_ref() {
        ID_WINDOW_IMPORT => {
            info!("menu: import requested");
            use tauri::Emitter;
            // Emit to the menu's own window — no label lookup needed.
            window.emit("import-requested", ()).ok();
        }
        ID_WINDOW_EXIT => {
            info!("menu: exit requested");
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move { exit_app(app_handle).await });
        }
        ID_CHECK_UPDATE => {
            info!("menu: check for updates");
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                handle_check_for_updates(app_handle).await;
            });
        }
        ID_COLLECT_LOGS => {
            info!("menu: collect logs");
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                handle_collect_logs(app_handle).await;
            });
        }
        ID_ABOUT => {
            info!("menu: about dialog");
            use tauri_plugin_dialog::DialogExt;
            app.dialog()
                .message(format!("Hole {}", hole::version::VERSION))
                .title("About Hole")
                .blocking_show();
        }
        #[cfg(target_os = "macos")]
        ID_UNINSTALL_HELPER => {
            info!("menu: uninstall helper requested");
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                handle_uninstall_helper(app_handle).await;
            });
        }
        _ => {}
    }
}

#[cfg(target_os = "macos")]
async fn handle_uninstall_helper(app: AppHandle) {
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

    let confirmed = app
        .dialog()
        .message("This will stop and remove the Hole bridge service.\n\nContinue?")
        .title("Uninstall Helper")
        .buttons(MessageDialogButtons::OkCancelCustom(
            "Uninstall".into(),
            "Cancel".into(),
        ))
        .blocking_show();

    if !confirmed {
        return;
    }

    let exe = match crate::setup::bridge_binary_path() {
        Ok(p) => p,
        Err(e) => {
            error!("cannot resolve binary path: {e}");
            return;
        }
    };

    let result = tokio::task::spawn_blocking(move || crate::setup::run_elevated(&exe, &["bridge", "uninstall"])).await;

    match result {
        Ok(Ok(())) => {
            app.dialog()
                .message("Bridge helper has been uninstalled.")
                .title("Uninstall Helper")
                .blocking_show();
        }
        Ok(Err(crate::setup::SetupError::Cancelled)) => {
            info!("user cancelled uninstall elevation");
        }
        Ok(Err(e)) => {
            error!("uninstall failed: {e}");
            app.dialog()
                .message(format!("Uninstall failed: {e}"))
                .title("Error")
                .blocking_show();
        }
        Err(e) => {
            error!("spawn_blocking failed: {e}");
        }
    }
}

async fn handle_install_update_from_tray(app: AppHandle) {
    use tauri_plugin_dialog::DialogExt;

    // Get update info from update state.
    let update_state = app.state::<hole::update::UpdateState>();
    let update_info = update_state.rx.borrow().clone();

    let Some(info) = update_info else {
        warn!("install update clicked but no update info available");
        return;
    };

    let download_dir = match tempfile::TempDir::with_prefix("hole-update-") {
        Ok(d) => d,
        Err(e) => {
            error!("failed to create temp dir: {e}");
            return;
        }
    };
    let dest = download_dir.path().join(&info.asset_name);
    let asset_url = info.asset_url.clone();
    let dest_for_download = dest.clone();

    // Download on blocking thread.
    let download_result =
        tokio::task::spawn_blocking(move || hole::update::download_asset(&asset_url, &dest_for_download)).await;

    match download_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            error!("download failed: {e}");
            app.dialog()
                .message(format!("Download failed: {e}"))
                .title("Update Error")
                .blocking_show();
            return;
        }
        Err(e) => {
            error!("download task panicked: {e}");
            return;
        }
    }

    // Fetch the manifest + signature once; they feed BOTH the local verify and
    // the bridge's offline re-verify (the bridge must not re-fetch).
    let sha256sums_url = info.sha256sums_url.clone();
    let sha256sums_minisig_url = info.sha256sums_minisig_url.clone();
    let manifest_result =
        tokio::task::spawn_blocking(move || hole::update::fetch_manifest(&sha256sums_url, &sha256sums_minisig_url))
            .await;
    let (sha256sums, sha256sums_minisig) = match manifest_result {
        Ok(Ok(m)) => m,
        Ok(Err(e)) => {
            error!("manifest fetch failed: {e}");
            app.dialog()
                .message(format!("Update verification failed: {e}"))
                .title("Update Error")
                .blocking_show();
            return;
        }
        Err(e) => {
            error!("manifest fetch task panicked: {e}");
            return;
        }
    };

    // Verify integrity and authenticity locally before handing it to the bridge.
    let dest_for_verify = dest.clone();
    let asset_name = info.asset_name.clone();
    let sums_for_verify = sha256sums.clone();
    let minisig_for_verify = sha256sums_minisig.clone();
    let verify_result = tokio::task::spawn_blocking(move || {
        hole_common::verify::verify_payload_offline(
            &dest_for_verify,
            &asset_name,
            &sums_for_verify,
            &minisig_for_verify,
        )
    })
    .await;

    match verify_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            error!("verification failed: {e}");
            app.dialog()
                .message(format!("Update verification failed: {e}"))
                .title("Update Error")
                .blocking_show();
            return;
        }
        Err(e) => {
            error!("verify task panicked: {e}");
            return;
        }
    }

    // Hand the verified payload to the privileged bridge, which owns the cutover
    // (binary swap + service restart). The GUI does NOT exit — it self-heals onto
    // the new image via the version-lockstep relaunch once the bridge is back.
    // For PR2 the tray's existing user-initiated "install update" click is the
    // gate, so consent is passed true (PR3 wires an explicit dialog).
    let apply = BridgeRequest::ApplyUpdate {
        payload_path: dest.clone(),
        target_version: info.version.to_string(),
        consent: true,
        sha256sums,
        sha256sums_minisig,
        asset_name: info.asset_name.clone(),
        app_dest: hole::update::app_dest_hint(),
    };
    let result = app.state::<AppState>().bridge_send(apply).await;
    drop(download_dir);

    match result {
        Ok(BridgeResponse::Ack) => {}
        Ok(BridgeResponse::Error { message }) => {
            error!("bridge rejected update: {message}");
            app.dialog()
                .message(format!("Update failed: {message}"))
                .title("Update Error")
                .blocking_show();
        }
        Ok(other) => error!("unexpected bridge response to update apply: {other:?}"),
        Err(e) => {
            error!("update apply failed: {e}");
            app.dialog()
                .message(format!("Update failed: {e}"))
                .title("Update Error")
                .blocking_show();
        }
    }
}

async fn handle_collect_logs(app: AppHandle) {
    use tauri_plugin_dialog::DialogExt;

    let zip_result = tokio::task::spawn_blocking(crate::log_collector::collect_logs_to_zip).await;

    let zip_path = match zip_result {
        Ok(Ok(path)) => path,
        Ok(Err(e)) => {
            app.dialog().message(e).title("Collect Logs").blocking_show();
            return;
        }
        Err(e) => {
            error!("collect logs task panicked: {e}");
            return;
        }
    };

    // Show a save dialog so the user can choose where to save
    let dest = app
        .dialog()
        .file()
        .set_file_name("hole-logs.zip")
        .add_filter("ZIP Archive", &["zip"])
        .blocking_save_file();

    if let Some(dest) = dest {
        if let Err(e) = std::fs::copy(&zip_path, dest.as_path().unwrap()) {
            app.dialog()
                .message(format!("Failed to save: {e}"))
                .title("Collect Logs")
                .blocking_show();
        }
    }

    // Clean up temp file
    let _ = std::fs::remove_file(&zip_path);
    if let Some(parent) = zip_path.parent() {
        let _ = std::fs::remove_dir(parent);
    }
}

async fn handle_check_for_updates(app: AppHandle) {
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

    let result = tokio::task::spawn_blocking(hole::update::check_for_update).await;

    match result {
        Ok(Ok(Some(info))) => {
            let confirmed = app
                .dialog()
                .message(format!(
                    "Version {} is available.\n\nWould you like to install it now?",
                    info.version
                ))
                .title("Update Available")
                .buttons(MessageDialogButtons::OkCancelCustom("Install".into(), "Later".into()))
                .blocking_show();

            if confirmed {
                // Store the update info and reuse the install handler.
                let update_state = app.state::<hole::update::UpdateState>();
                update_state.tx.send_replace(Some(info));
                handle_install_update_from_tray(app).await;
            }
        }
        Ok(Ok(None)) => {
            app.dialog()
                .message(format!(
                    "You're running the latest version ({}).",
                    hole::version::VERSION
                ))
                .title("No Updates Available")
                .blocking_show();
        }
        Ok(Err(e)) => {
            app.dialog()
                .message(format!("Failed to check for updates: {e}"))
                .title("Update Error")
                .blocking_show();
        }
        Err(e) => {
            error!("update check task panicked: {e}");
        }
    }
}

/// Reveal the dashboard if one is open, otherwise build a fresh one. Called
/// by the tray click, the tray "Dashboard…" item, `--show-dashboard`, and the
/// single-instance callback.
pub(crate) fn open_settings_window(app: &AppHandle) {
    let dashboard = app.state::<crate::dashboard::DashboardWindow>();
    if let Some(label) = dashboard.current_label() {
        if let Some(window) = app.get_webview_window(&label) {
            reveal(&window);
            #[cfg(target_os = "macos")]
            crate::platform::show_dock_icon(app);
            return;
        }
        // `current` named a window that no longer exists; build a fresh one.
        // `allocate` below overwrites the stale generation.
    }
    build_dashboard(app, &dashboard);
}

/// Bring an existing dashboard to the foreground. Best-effort: the window is
/// known to exist and these calls are cosmetic.
fn reveal(window: &tauri::WebviewWindow) {
    let _ = window.unminimize();
    let _ = window.show();
    let _ = window.set_focus();
}

/// Build a fresh dashboard window with a unique label and wire its close
/// handler.
fn build_dashboard(app: &AppHandle, dashboard: &crate::dashboard::DashboardWindow) {
    let (generation, label) = dashboard.allocate();

    let mut builder = WebviewWindowBuilder::new(app, &label, WebviewUrl::default())
        .title("Hole Dashboard")
        .inner_size(800.0, 600.0)
        .min_inner_size(800.0, 200.0)
        .max_inner_size(800.0, 4096.0)
        .resizable(true)
        .maximizable(false)
        // Devtools enabled unconditionally (incl. release) so users can
        // self-diagnose webview issues. F12 opens it on Windows; macOS via
        // Safari → Develop. Adds an "Inspect" context-menu item.
        .devtools(true);

    // Menu bar (all platforms) ----------------------------------------------------------------------------------------
    {
        use tauri::menu::{Menu, Submenu};

        // File menu
        let import_item = MenuItem::with_id(app, ID_WINDOW_IMPORT, "Import...", true, Some("CmdOrCtrl+O"))
            .expect("failed to create menu item");
        let file_sep = PredefinedMenuItem::separator(app).expect("failed to create separator");
        let exit_item = MenuItem::with_id(app, ID_WINDOW_EXIT, "Exit", true, Some("CmdOrCtrl+Q"))
            .expect("failed to create menu item");
        let file_submenu = Submenu::with_items(app, "File", true, &[&import_item, &file_sep, &exit_item])
            .expect("failed to create submenu");

        // Help menu
        let check_update_item = MenuItem::with_id(app, ID_CHECK_UPDATE, "Check for Updates...", true, None::<&str>)
            .expect("failed to create menu item");
        let collect_logs_item = MenuItem::with_id(app, ID_COLLECT_LOGS, "Collect Logs...", true, None::<&str>)
            .expect("failed to create menu item");
        let about_item =
            MenuItem::with_id(app, ID_ABOUT, "About Hole", true, None::<&str>).expect("failed to create menu item");
        let help_submenu = Submenu::with_items(
            app,
            "Help",
            true,
            &[&check_update_item, &collect_logs_item, &about_item],
        )
        .expect("failed to create submenu");

        #[cfg(not(target_os = "macos"))]
        let menu = Menu::with_items(app, &[&file_submenu, &help_submenu]).expect("failed to create menu");

        #[cfg(target_os = "macos")]
        let menu = {
            let uninstall_item = MenuItem::with_id(app, ID_UNINSTALL_HELPER, "Uninstall Helper...", true, None::<&str>)
                .expect("failed to create menu item");
            let hole_submenu =
                Submenu::with_items(app, "Hole", true, &[&uninstall_item]).expect("failed to create submenu");
            Menu::with_items(app, &[&hole_submenu, &file_submenu, &help_submenu]).expect("failed to create menu")
        };

        builder = builder.menu(menu).on_menu_event(|window, event| {
            handle_window_menu_event(window, event);
        });
    }

    match builder.build() {
        Ok(window) => {
            // Stop tracking this generation on close; don't prevent the close,
            // so the webview is destroyed and freed. The generation tag stops a
            // late close from forgetting a newer dashboard.
            let close_handle = app.clone();
            window.on_window_event(move |event| {
                if let tauri::WindowEvent::CloseRequested { .. } = event {
                    close_handle
                        .state::<crate::dashboard::DashboardWindow>()
                        .forget(generation);
                }
            });
            #[cfg(target_os = "macos")]
            crate::platform::show_dock_icon(app);
        }
        Err(e) => {
            error!(error = %e, "failed to open dashboard window");
            dashboard.forget(generation);
        }
    }
}

// Tauri commands ======================================================================================================

/// Start the proxy. The caller transmits explicit intent — direction is
/// decided by the state the user SAW, never re-derived backend-side from
/// possibly-stale state (#462); the bridge's idempotence ("already
/// running" → Running) absorbs a stale view instead of inverting the
/// user's intent. Returns a `ToggleOutcome` (Running / Stopped /
/// Cancelled); the frontend distinguishes the three cases in its
/// connection state machine.
#[tauri::command]
pub async fn start_proxy(app: AppHandle, attempt_id: String) -> Result<ToggleOutcome, String> {
    set_proxy_enabled(&app, true, attempt_id).await
}

/// Stop the proxy. See [`start_proxy`]. Stop carries no attempt id (it is not
/// cancellable), so a fresh placeholder satisfies the shared signature.
#[tauri::command]
pub async fn stop_proxy(app: AppHandle) -> Result<ToggleOutcome, String> {
    set_proxy_enabled(&app, false, String::new()).await
}

/// Cancel an in-flight proxy start. Uses `bridge_send_oneshot` so the
/// cancel can race an in-flight `start_proxy` on the main pooled
/// bridge connection. The `attempt_id` (minted by the frontend for this
/// connect attempt and shared with `start_proxy`) scopes the cancel to that
/// exact attempt (#465). Always returns `Ok(())` on a successful bridge
/// round-trip — the bridge's `/v1/cancel` route is idempotent.
#[tauri::command]
pub async fn cancel_proxy(state: tauri::State<'_, AppState>, attempt_id: String) -> Result<(), String> {
    match state.bridge_send_oneshot(BridgeRequest::Cancel { attempt_id }).await {
        Ok(BridgeResponse::Ack) => Ok(()),
        Ok(other) => {
            warn!("unexpected response to Cancel: {other:?}");
            Err("Unexpected response from bridge".into())
        }
        Err(e) => {
            error!("failed to send cancel: {e}");
            Err(format!("Failed to cancel: {e}"))
        }
    }
}

// Autostart (OS login-item) ===========================================================================================

/// Read whether the GUI is registered to start at OS login. The OS registration
/// (Windows Run key / macOS LaunchAgent) is the single source of truth; the
/// dashboard renders this live rather than from config (#457).
#[tauri::command]
pub fn get_autostart(app: AppHandle) -> Result<bool, String> {
    use tauri_plugin_autostart::ManagerExt;
    crate::autostart::is_enabled(&*app.autolaunch()).map_err(|e| {
        // Full detail (may embed the executable path) → gui.log; the dashboard
        // toast gets only the PII-free summary.
        error!("{e}");
        e.user_message().to_string()
    })
}

/// Register or unregister GUI start-at-login through the same `crate::autostart`
/// seam this tray uses, then re-sync the tray checkmark from the new OS state.
/// Returns the live OS state (#457).
#[tauri::command]
pub fn set_autostart(app: AppHandle, enabled: bool) -> Result<bool, String> {
    use tauri_plugin_autostart::ManagerExt;
    let manager = app.autolaunch();
    crate::autostart::set(&*manager, enabled).map_err(|e| {
        error!("{e}");
        e.user_message().to_string()
    })?;
    // A successful flip must re-derive the tray checkmark from live OS state, or
    // the two surfaces disagree (the inverse of the bug). rebuild_tray_menu
    // marshals onto the main thread itself.
    rebuild_tray_menu(&app);
    // Report live OS state, not the intent — the OS is the single source of truth.
    // A successful set establishes `enabled` (enable()/disable()'s post-condition),
    // so a failed read-back falls back to it rather than lying.
    Ok(crate::autostart::is_enabled(&*manager).unwrap_or_else(|e| {
        warn!("autostart read-back after set failed: {e}");
        enabled
    }))
}

// Proxy state sync ====================================================================================================

/// Forward every committed proxy-state change to the tray and the
/// webview. Single sequential consumer of the `ProxyStateCell` watch
/// channel, so emit order equals commit order; the rebuild re-reads the
/// cell inside its main-thread closure, so the last queued rebuild always
/// renders the newest state.
pub fn spawn_proxy_state_sync(app: &AppHandle) {
    use tauri::Emitter;
    let app = app.clone();
    let mut rx = app.state::<AppState>().subscribe_proxy_state();
    tauri::async_runtime::spawn(async move {
        loop {
            if rx.changed().await.is_err() {
                return; // cell dropped — app teardown
            }
            // `watch` coalesces to the latest snapshot. A death (running=false,
            // error=sentinel) loses its error before this wakes only if a later
            // commit overwrites it AND flips running back to true — which comes
            // solely from a Start (slow, user/startup I/O; there is no
            // auto-reconnect on death), so it cannot land in the wake window. A
            // coalesced lockdown-only re-commit keeps running=false and the
            // sticky error, so the death still reaches the webview (#470).
            // clone: ProxySnapshot owns a String and is no longer Copy.
            let snap = rx.borrow_and_update().clone();
            rebuild_tray_menu(&app);
            if let Err(e) = app.emit("proxy-state-changed", snap) {
                warn!(error = %e, "failed to emit proxy-state-changed");
            }
        }
    });
}

/// Keep the GUI's view of the bridge honest when the dashboard is closed
/// (no webview poll): an external stop, a bridge crash, or `hole proxy
/// stop` must reach the tray (#462).
///
/// Sanctioned timing exception (CONTRIBUTING.md test-invariants, the
/// "external process whose state changes out-of-band" class): this polls
/// a SEPARATE PROCESS for presentation reconciliation — the same class as
/// the webview's 5s status poll — and synchronizes nothing in-process
/// (`BridgeLink::send` commits synchronously; no code waits on this
/// loop). The immediate first tick doubles as the startup reconcile.
///
/// Beyond presentation, each tick's Status result drives the one-shot
/// startup-connect intent (#458): the recorded intent is applied (connect) at
/// most once — the first time the bridge proves reachable — and never again.
pub fn spawn_status_reconciler(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            // The commit happens inside send; the result also drives the
            // one-shot startup-connect intent (#458).
            let result = app.state::<AppState>().bridge_send(BridgeRequest::Status).await;
            apply_pending_startup_connect(&app, &result);
        }
    });
}

/// Arm the one-shot startup-connect intent (#458) from the persisted
/// `on_startup` policy. The status reconciler applies it the first time the
/// bridge is reachable, so a cold-boot race — the bridge service and the GUI
/// start as independent OS units with no ordering edge, and the GUI can reach
/// here before the bridge has bound its socket — can't drop the connect. Runs
/// once per live GUI instance. Snapshots the two Copy config fields under the
/// lock and drops the guard.
pub fn arm_startup_auto_connect(app: &AppHandle) {
    let state = app.state::<AppState>();
    let (behavior, last_enabled) = {
        let cfg = state.config.lock().unwrap();
        (cfg.on_startup, cfg.enabled)
    };
    if startup_should_connect(behavior, last_enabled) {
        state.arm_pending_startup_connect();
    }
}

/// What the status reconciler should do with a pending startup-connect intent
/// (#458), given a Status exchange result. The bridge service and the GUI start
/// as independent OS units with no ordering edge, so the boot connect can race
/// the bridge's socket bind; this lets the reconciler apply the recorded intent
/// the first time the bridge proves reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingAction {
    /// Bridge reachable and idle — connect now and consume the intent.
    Apply,
    /// Bridge reachable and already running — intent satisfied; consume it.
    Drop,
    /// Readiness unproven (still booting, or a hiccup that says nothing about
    /// reachability) — keep the intent for a later tick.
    Retain,
}

/// Decide the pending startup-connect action from a reconciler `Status` result.
/// Only a reachable bridge reporting its run state is conclusive; a transport
/// failure means "not bound yet", and a DACL/version hiccup says nothing about
/// readiness — both retain so a later tick can apply the intent. A host left
/// fail-closed by a failed covered start (`blocked_until_connected`) is NOT idle
/// to re-apply against: the bridge holds that blocked state independently of any
/// GUI, so a fresh GUI instance re-arming the latch could otherwise observe a
/// deliberately-blocked host as idle and auto-fire against it. Retain instead.
pub(crate) fn should_apply_pending(
    result: &Result<BridgeResponse, crate::bridge_client::ClientError>,
) -> PendingAction {
    match result {
        Ok(BridgeResponse::Status {
            running: false,
            blocked_until_connected: true,
            ..
        }) => PendingAction::Retain,
        Ok(BridgeResponse::Status { running: false, .. }) => PendingAction::Apply,
        Ok(BridgeResponse::Status { running: true, .. }) => PendingAction::Drop,
        _ => PendingAction::Retain,
    }
}

/// Apply the one-shot startup-connect intent (#458) against a reconciler Status
/// result: connect once the bridge is first reachable, drop the intent if it is
/// already running, retain it while the bridge is still booting. Spawns the
/// silent connect (the latch is consumed first, so it fires at most once).
fn apply_pending_startup_connect(app: &AppHandle, status: &Result<BridgeResponse, crate::bridge_client::ClientError>) {
    let state = app.state::<AppState>();
    match should_apply_pending(status) {
        PendingAction::Apply => {
            if state.take_pending_startup_connect() {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    // Both arms log at info: failing into the tray's Disconnected
                    // state is the contract, not an error.
                    match connect_silently(&app).await {
                        Ok(outcome) => info!(?outcome, "startup auto-connect settled"),
                        Err(e) => info!(reason = %e, "startup auto-connect did not connect"),
                    }
                });
            }
        }
        // Already running: consume the intent so a later user disconnect can't
        // be undone by a stale latch.
        PendingAction::Drop => {
            state.take_pending_startup_connect();
        }
        PendingAction::Retain => {}
    }
}

#[cfg(test)]
#[path = "tray_tests.rs"]
mod tray_tests;
