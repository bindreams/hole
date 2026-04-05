// Hole Dashboard — main entry point.
//
// State management, Tauri IPC integration, polling setup, and event listeners.

import { initSections } from "./sections.js";
import { initServers, renderServers } from "./servers.js";
import { initFilters, renderFilters } from "./filters.js";
import {
  initSidebar,
  updateMetrics,
  updateDiagnostics,
  updateProxyStatus,
  updatePublicIp,
} from "./sidebar.js";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

// State =====

/** The current application config, loaded from the backend. */
export let config = null;

/** Whether the config has unsaved changes. */
let dirty = false;

// Config management =====

/** Fetch the config from the backend and broadcast it to all UI sections. */
export async function loadConfig() {
  try {
    config = await invoke("get_config");
    dirty = false;
    renderServers();
    renderFilters();
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

// Polling =====

/** Poll proxy status every 5 seconds. */
async function pollProxyStatus() {
  try {
    const status = await invoke("get_proxy_status");
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
    const metrics = await invoke("get_metrics");
    updateMetrics(metrics);
  } catch (err) {
    console.error("get_metrics failed:", err);
  }
}

/** Poll diagnostics every 5 seconds. */
async function pollDiagnostics() {
  try {
    const data = await invoke("get_diagnostics");
    updateDiagnostics(data);
  } catch (err) {
    console.error("get_diagnostics failed:", err);
  }
}

// Event listeners =====

/** Handle file import (from menu or drag-and-drop). */
async function importFile(path) {
  try {
    await invoke("import_servers_from_file", { path });
    // Reload config so the UI picks up the new servers.
    await loadConfig();
  } catch (err) {
    console.error("import failed:", err);
  }
}

function setupEventListeners() {
  // File > Import menu action.
  listen("import-requested", async (event) => {
    const path = event.payload;
    if (path) await importFile(path);
  });

  // Drag-and-drop file import.
  listen("tauri://drag-drop", async (event) => {
    const paths = event.payload?.paths;
    if (paths && paths.length > 0) {
      // Import the first dropped file.
      await importFile(paths[0]);
    }
  });
}

// Initialization =====

async function init() {
  // Initialize UI modules.
  initSections();
  initServers();
  initFilters();
  initSidebar();

  // Load config from backend.
  await loadConfig();

  // Initial data fetches (all in parallel).
  await Promise.allSettled([
    pollProxyStatus(),
    pollMetrics(),
    pollDiagnostics(),
    updatePublicIp(),
  ]);

  // Start polling intervals.
  setInterval(pollProxyStatus, 5000);
  setInterval(pollMetrics, 1000);
  setInterval(pollDiagnostics, 5000);

  // Wire up event listeners.
  setupEventListeners();
}

init();
