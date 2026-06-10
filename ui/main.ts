// Hole Dashboard — main entry point.
//
// State management, Tauri IPC integration, polling setup, and event listeners.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { attachConsole, error as logError, warn as logWarn } from "@tauri-apps/plugin-log";
import "flag-icons/css/flag-icons.min.css";
import { OverlayScrollbars } from "overlayscrollbars";
import "overlayscrollbars/overlayscrollbars.css";
import { initFilters, renderFilters } from "./filters";
import { postImportSummary } from "./import-summary";
import { initSections } from "./sections";
import {
  clearImportZoneHighlight,
  importFromDialog,
  initServers,
  renderServers,
  showImportFailureDialog,
} from "./servers";
import { initSettings, renderSettings } from "./settings";
import { initSidebar, updateDiagnostics, updateMetrics, updateProxyStatus, updatePublicIp } from "./sidebar";
import { showToast } from "./toast";
import type { Config, DiagnosticsData, Metrics, ProxyStatus, Server } from "./types";

/// Maximum number of concurrent server tests during bulk auto-test (e.g.
/// after a JSON import). 50 concurrent plugin processes is non-trivial
/// RAM and looks like a port scan from one IP to commercial SS providers.
export const TEST_CONCURRENCY = 5;

// Test seam: webdriver's `before` hook calls this to park until
// `init()` has completed (success or failure). `withGlobalTauri: false`
// strips `window.__TAURI__` from injected scripts, so this typed
// global is the documented entry point. See
// `crates/hole/src/ui_ready.rs`.
declare global {
  interface Window {
    __holeUiReady?: () => Promise<{ ok: boolean; error: string | null }>;
  }
}
window.__holeUiReady = () => invoke<{ ok: boolean; error: string | null }>("wait_ui_ready");

// State ===============================================================================================================

/** The current application config, loaded from the backend. */
export let config: Config | null = null;

/** Whether the config has unsaved changes. */
let dirty = false;

// Config management ===================================================================================================

/** Fetch the config from the backend and broadcast it to all UI sections. */
export async function loadConfig() {
  try {
    config = await invoke<Config>("get_config");
    dirty = false;
    renderServers();
    renderFilters();
    renderSettings();
    // Diagnostics dots depend on the selected server's persisted
    // validation state, which lives on `config`. Recompute on every
    // config reload.
    updateDiagnostics();
  } catch (err) {
    console.error("loadConfig failed:", err);
    showToast(`Failed to load config: ${err}`, "error");
  }
}

/** Save the current config to the backend. */
export async function saveConfig() {
  if (!config) return;
  try {
    await invoke("save_config", { config });
    dirty = false;
  } catch (err) {
    console.error("saveConfig failed:", err);
    showToast(`Failed to save config: ${err}`, "error");
  }
}

/** Mark the config as having unsaved changes. */
export function setDirty() {
  dirty = true;
}

/** Whether the config has unsaved changes. */
export function isDirty() {
  return dirty;
}

// Polling =============================================================================================================

/** Poll proxy status every 5 seconds. */
async function pollProxyStatus() {
  try {
    const status = await invoke<ProxyStatus>("get_proxy_status");
    const result = updateProxyStatus(status);
    // The poll only reconciles state when the bridge disagrees with the
    // UI (e.g. an external disconnect). Click-driven transitions fire
    // `mark_validated_by_proxy_start` themselves from the click handler
    // — the poll never observes the `connecting` intermediate state, so
    // it cannot distinguish "user just connected" from "bridge was
    // already connected when the GUI started".
    if (result.changed) {
      updatePublicIp();
    }
  } catch (err) {
    console.error("get_proxy_status failed:", err);
  }
}

/** Poll metrics every 1 second. */
async function pollMetrics() {
  try {
    const metrics = await invoke<Metrics>("get_metrics");
    updateMetrics(metrics);
  } catch (err) {
    console.error("get_metrics failed:", err);
  }
}

/** Poll diagnostics every 5 seconds. */
async function pollDiagnostics() {
  try {
    const data = await invoke<DiagnosticsData>("get_diagnostics");
    updateDiagnostics(data);
  } catch (err) {
    console.error("get_diagnostics failed:", err);
  }
}

// Bounded-concurrency auto-test =======================================================================================

/// Run `test_server` for each ID, capping in-flight calls at `maxInFlight`.
/// Each completion is fire-and-forget from the caller's perspective; the
/// `validation-changed` listener picks up the result and triggers a
/// rerender. Used by both single-server-add and bulk-import flows.
export async function runTestsBounded(ids: string[], maxInFlight: number) {
  let i = 0;
  const workers = Array.from({ length: Math.min(maxInFlight, ids.length) }, async () => {
    while (i < ids.length) {
      const myIdx = i++;
      const id = ids[myIdx];
      try {
        await invoke("test_server", { entryId: id });
      } catch (err) {
        console.error(`auto-test failed for ${id}:`, err);
      }
    }
  });
  await Promise.all(workers);
}

// Event listeners =====================================================================================================

function setupEventListeners(): Promise<unknown> {
  // File > Import menu action (tray emits () as payload — open dialog).
  const importReady = listen("import-requested", () => importFromDialog());

  // WebView2 (Windows) shows the OS "forbidden" cursor on file drags
  // unless JS calls `preventDefault()` on the `dragover` event — even
  // though Tauri's native drop handler is what actually delivers the
  // file paths via `tauri://drag-drop`. Without these two lines, the
  // user gets a red-crossed-circle cursor and the drop is rejected at
  // the OS layer before Tauri sees it. The handlers are window-scoped
  // because Tauri's drop handler is also window-scoped.
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => e.preventDefault());

  // Drag-and-drop file import. The user may drop one or many files;
  // iterate, showing a BLOCKING error dialog per failure (sequential —
  // the user must acknowledge each), and aggregate any successes into
  // a single end-of-loop toast. Per-failure errors use blocking dialogs
  // (not auto-dismiss toasts) so they can't be missed.
  const dropReady = listen<{ paths?: string[] }>("tauri://drag-drop", async (event) => {
    // A successful drop may not fire `dragleave` on the import zone —
    // remove the visual highlight unconditionally before processing
    // (the no-op case where the zone wasn't highlighted is harmless).
    clearImportZoneHighlight();
    const paths = event.payload?.paths ?? [];
    if (paths.length === 0) return;

    let totalAppended = 0;
    let totalFailed = 0;
    const newIds: string[] = [];
    for (const path of paths) {
      try {
        const newServers = await invoke<Server[]>("import_servers_from_file", { path });
        totalAppended += newServers.length;
        for (const s of newServers) newIds.push(s.id);
      } catch (err) {
        totalFailed++;
        console.error(`import failed for ${path}:`, err);
        // Sequential, modal — `await` here parks the loop until the
        // user dismisses the dialog before moving on to the next file.
        await showImportFailureDialog(err);
      }
    }

    // Skip the config reload when nothing was appended — the config
    // didn't change, and a reload of an unchanged config would only
    // risk a spurious "Failed to load config" dialog on top of the
    // per-file error dialog(s) we already showed.
    if (totalAppended > 0) {
      await loadConfig();
      // Auto-test the newly imported servers in parallel (bounded).
      // Fire and forget — the validation-changed listener handles repaint.
      runTestsBounded(newIds, TEST_CONCURRENCY);
    }

    // Errors were already delivered via blocking dialogs inside the
    // per-file `catch`. The post-loop summary covers only success/info
    // outcomes — and explicitly names any failure count in the partial
    // case so the toast doesn't lie.
    const summary = postImportSummary(totalAppended, totalFailed);
    if (summary !== null) showToast(summary.message, summary.kind);
  });

  // Persisted validation changed (from `test_server` or
  // `mark_validated_by_proxy_start`). Pull fresh config and rerender.
  const validationReady = listen<string>("validation-changed", async () => {
    await loadConfig();
  });

  // Joined so init() can await registration before the UI becomes
  // interactive — an emit landing before listen() resolves is silently
  // lost. Rejection is deliberately fatal to init: a dashboard without
  // its listeners is broken in exactly the silent way this guards.
  return Promise.all([importReady, dropReady, validationReady]);
}

// Initialization ======================================================================================================

/// Format a single console-argument for the relay: include the stack on
/// Errors so `gui.log` keeps the diagnostic; plain `String(a)` for everything
/// else (matches console's own toString behavior for non-Error args).
function formatRelayArg(a: unknown): string {
  return a instanceof Error ? `${a.message}\n${a.stack ?? ""}` : String(a);
}

/// Forward JS `console.error` / `console.warn` calls through
/// `@tauri-apps/plugin-log` so they land in `gui.log`. Toast presentation is
/// per-call-site (deliberate, contextual messages); this relay is log-only.
///
/// Reentrancy guard: a throwing `logError` / `logWarn` would re-enter the
/// relay and recurse. `inRelay` short-circuits the recursion; failures
/// surface via the original (unpatched) `console.error` so a misconfigured
/// plugin-log capability is loud rather than silent.
function installConsoleRelay() {
  let inRelay = false;
  const origError = console.error.bind(console);
  console.error = (...args: unknown[]) => {
    origError(...args);
    if (inRelay) return;
    inRelay = true;
    try {
      void logError(args.map(formatRelayArg).join(" ")).catch((e) => {
        origError("console.error relay failed:", e);
      });
    } finally {
      inRelay = false;
    }
  };
  const origWarn = console.warn.bind(console);
  console.warn = (...args: unknown[]) => {
    origWarn(...args);
    if (inRelay) return;
    inRelay = true;
    try {
      void logWarn(args.map(formatRelayArg).join(" ")).catch((e) => {
        // Use origError, not origWarn — a relay failure is an Error.
        origError("console.warn relay failed:", e);
      });
    } finally {
      inRelay = false;
    }
  };
}

async function init() {
  // Install the JS→Rust console relay BEFORE anything else so the
  // subsequent `console.error` / `console.warn` calls in this `init`
  // (and the window-level error / unhandledrejection handlers) end up in
  // `gui.log`. The relay only logs; it does NOT toast. Toast presentation
  // is per-call-site so blanket capture doesn't flood the UI.
  installConsoleRelay();

  let result: { ok: boolean; error: string | null };
  try {
    // Mirror Rust log events into the JS console (the OPPOSITE direction
    // from the relay above). Wrapped in try/catch so a future capability
    // misconfiguration on `tauri-plugin-log` doesn't silently break the
    // whole dashboard. The plugin is registered on the Rust side in
    // main.rs with `.skip_logger()` so JS log events flow through
    // `log` → `tracing-log::LogTracer` → `gui.log`.
    try {
      await attachConsole();
    } catch (e) {
      console.warn("attachConsole failed:", e);
    }

    window.addEventListener("error", (e) => {
      console.error(`window.error: ${e.message} at ${e.filename}:${e.lineno}:${e.colno}`);
    });
    window.addEventListener("unhandledrejection", (e) => {
      const reason = e.reason instanceof Error ? `${e.reason.message}\n${e.reason.stack ?? ""}` : String(e.reason);
      console.error(`unhandledrejection: ${reason}`);
    });

    // Initialize UI modules.
    initSections();
    initServers();
    initFilters();
    initSettings();
    initSidebar();

    // Register Rust→JS event listeners BEFORE the first paint-driving
    // fetches: the menu and drop targets are live from the first frame,
    // and an emit before listen() resolves is dropped with no error.
    await setupEventListeners();

    // Replace native scrollbars with fade-in/out overlay scrollbars.
    const main = document.querySelector<HTMLElement>(".main");
    if (main) {
      OverlayScrollbars(main, {
        scrollbars: { theme: "os-theme-hole", autoHide: "scroll", autoHideDelay: 800 },
      });
    }
    const sbContent = document.querySelector<HTMLElement>(".sb-content");
    if (sbContent) {
      OverlayScrollbars(sbContent, {
        scrollbars: { theme: "os-theme-hole", autoHide: "scroll", autoHideDelay: 800 },
      });
    }

    // Load config from backend.
    await loadConfig();

    // Initial data fetches (all in parallel).
    await Promise.allSettled([pollProxyStatus(), pollMetrics(), pollDiagnostics(), updatePublicIp()]);

    // Start polling intervals.
    setInterval(pollProxyStatus, 5000);
    setInterval(pollMetrics, 1000);
    setInterval(pollDiagnostics, 5000);

    result = { ok: true, error: null };
  } catch (err) {
    const msg = err instanceof Error ? `${err.message}\n${err.stack ?? ""}` : String(err);
    // `console.error` routes to gui.log via the relay installed above.
    console.error(`init failed: ${msg}`);
    result = { ok: false, error: msg };
    // Toast may not be ready if init failed in its first two lines (before
    // the OverlayScrollbars/load steps). Show the toast; on failure, fall
    // back to a synchronous `alert()`. Both happen AFTER `signal_ui_ready`
    // below — `alert()` is modal-blocking on Windows WebView2, and parking
    // the JS event loop here would prevent the webdriver-side
    // `wait_ui_ready` from observing the result.
    queueMicrotask(() => {
      try {
        showToast(`Dashboard failed to initialize: ${msg}`, "error", 30_000);
      } catch {
        alert(`Hole dashboard failed to initialize: ${msg}`);
      }
    });
  }

  // Always signal — even on init failure — so the webdriver test
  // surfaces a real error instead of hanging on the watch channel.
  // This MUST run before any modal UI (toast/alert) in the failure
  // path; otherwise an alert dialog would park the JS event loop and
  // wedge the webdriver session indefinitely.
  try {
    await invoke("signal_ui_ready", { result });
  } catch (signalErr) {
    // If the invoke itself fails the Tauri runtime is broken, which
    // is an external-event-might-never-happen scenario. The webdriver
    // test surfaces this via its framework timeout — there is no
    // intra-process recovery available here.
    logError(`signal_ui_ready failed: ${signalErr}`);
  }
}

// Test seam: init() never rejects (its body is fully try/caught and the
// trailing signal_ui_ready failure is logged, not thrown), so awaiting
// this is a plain rendezvous on startup completion.
export const initDone = init();
