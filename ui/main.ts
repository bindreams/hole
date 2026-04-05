// Hole Dashboard — main entry point.
//
// State management, Tauri IPC integration, polling setup, and event listeners.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { initFilters, renderFilters } from "./filters";
import { initSections } from "./sections";
import { importFromDialog, initServers, renderServers } from "./servers";
import { initSettings, renderSettings } from "./settings";
import { initSidebar, updateDiagnostics, updateMetrics, updateProxyStatus, updatePublicIp } from "./sidebar";
import type { Config, DiagnosticsData, Metrics, ProxyStatus } from "./types";

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
  } catch (err) {
    console.error("loadConfig failed:", err);
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
    if (result.changed) {
      // Connection state changed — refresh IP.
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

// Event listeners =====================================================================================================

/** Handle file import (from menu or drag-and-drop). */
async function importFile(path: string) {
  try {
    await invoke("import_servers_from_file", { path });
    // Reload config so the UI picks up the new servers.
    await loadConfig();
  } catch (err) {
    console.error("import failed:", err);
  }
}

function setupEventListeners() {
  // File > Import menu action (tray emits () as payload — open dialog).
  listen("import-requested", () => importFromDialog());

  // Drag-and-drop file import.
  listen<{ paths?: string[] }>("tauri://drag-drop", async (event) => {
    const paths = event.payload?.paths;
    if (paths && paths.length > 0) {
      // Import the first dropped file.
      await importFile(paths[0]);
    }
  });
}

// Initialization ======================================================================================================

async function init() {
  // Initialize UI modules.
  initSections();
  initServers();
  initFilters();
  initSettings();
  initSidebar();

  // Load config from backend.
  await loadConfig();

  // Initial data fetches (all in parallel).
  await Promise.allSettled([pollProxyStatus(), pollMetrics(), pollDiagnostics(), updatePublicIp()]);

  // Start polling intervals.
  setInterval(pollProxyStatus, 5000);
  setInterval(pollMetrics, 1000);
  setInterval(pollDiagnostics, 5000);

  // Wire up event listeners.
  setupEventListeners();
}

init();
