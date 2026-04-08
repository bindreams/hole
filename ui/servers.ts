// Servers section: rendering server cards, selection, deletion, file import.

import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { config, loadConfig, runTestsBounded, saveConfig, TEST_CONCURRENCY } from "./main";
import { updateDiagnostics } from "./sidebar";
import { LATENCY_VALIDATED_ON_CONNECT, type ServerTestOutcome, type ValidationState } from "./types";

// DOM references ======================================================================================================

const serverList = document.getElementById("server-list")!;
const importZone = document.getElementById("import-zone")!;

// Validation-state helpers ============================================================================================

function statusClassFor(v: ValidationState | null | undefined): "untested" | "ok" | "fail" {
  if (!v) return "untested";
  return v.outcome.kind === "reachable" ? "ok" : "fail";
}

function userMessageFor(o: ServerTestOutcome): string {
  switch (o.kind) {
    case "reachable":
      return o.latency_ms === LATENCY_VALIDATED_ON_CONNECT
        ? "Validated by a recent successful connect."
        : `Reachable. Round-trip ${o.latency_ms} ms.`;
    case "dns_failed":
      return "DNS resolution failed.";
    case "tcp_refused":
      return "Connection refused by the server.";
    case "tcp_timeout":
      return "No response from the server.";
    case "plugin_start_failed":
      return `Plugin failed to start: ${o.detail}`;
    case "tunnel_handshake_failed":
      return "Server rejected the connection (wrong password, cipher, or plugin config).";
    case "server_cannot_reach_internet":
      return "Server cannot reach the public internet.";
    case "sentinel_mismatch":
      return `Unexpected response from the test sentinel: ${o.detail}`;
    case "internal_error":
      return `Internal error: ${o.detail}`;
  }
}

/// Render a relative duration like "5s ago" / "12m ago" / "3h ago" / "2d ago"
/// using `Intl.RelativeTimeFormat`. Clamps a negative delta (system clock
/// running backwards) to 0 to avoid "in 1s" weirdness.
function formatRelativeTime(rfc3339: string): string {
  const parsed = Date.parse(rfc3339);
  if (Number.isNaN(parsed)) return "just now";
  const deltaSecs = Math.max(0, Math.floor((Date.now() - parsed) / 1000));
  const fmt = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (deltaSecs < 60) return fmt.format(-deltaSecs, "second");
  if (deltaSecs < 3600) return fmt.format(-Math.floor(deltaSecs / 60), "minute");
  if (deltaSecs < 86400) return fmt.format(-Math.floor(deltaSecs / 3600), "hour");
  return fmt.format(-Math.floor(deltaSecs / 86400), "day");
}

export function statusTooltipFor(v: ValidationState | null | undefined): string {
  if (!v) return "Untested. Click Test to validate.";
  return `${userMessageFor(v.outcome)} Tested ${formatRelativeTime(v.tested_at)}.`;
}

async function runServerTest(id: string, btn: HTMLButtonElement, status: HTMLElement) {
  btn.disabled = true;
  btn.classList.add("loading");
  status.className = "srv-status testing";
  try {
    await invoke("test_server", { entryId: id });
    // The validation-changed listener will rerender via loadConfig().
  } catch (err) {
    console.error("test_server failed:", err);
  } finally {
    btn.disabled = false;
    btn.classList.remove("loading");
  }
}

// Rendering ===========================================================================================================

/**
 * Re-render all server cards based on the current config.
 * Call this whenever `config` changes (load, selection, deletion, import).
 */
export function renderServers() {
  if (!config) return;

  serverList.innerHTML = "";

  const servers = config.servers || [];

  if (servers.length === 0) {
    serverList.style.display = "none";
  } else {
    serverList.style.display = "";

    for (const server of servers) {
      const isActive = config.selected_server === server.id;

      const card = document.createElement("div");
      card.className = isActive ? "srv active" : "srv";
      card.dataset.serverId = server.id;

      const radio = document.createElement("div");
      radio.className = "radio";
      card.appendChild(radio);

      const sname = document.createElement("span");
      sname.className = "sname";
      sname.textContent = server.name;
      card.appendChild(sname);

      const saddr = document.createElement("span");
      saddr.className = "saddr";
      saddr.textContent = `${server.server}:${server.server_port}`;
      card.appendChild(saddr);

      if (server.plugin) {
        const badge = document.createElement("span");
        badge.className = "plugin-badge";
        badge.textContent = server.plugin;
        card.appendChild(badge);
      }

      // Persisted validation status indicator (gray/green/red dot).
      const statusDot = document.createElement("span");
      statusDot.className = `srv-status ${statusClassFor(server.validation)}`;
      statusDot.title = statusTooltipFor(server.validation);
      card.appendChild(statusDot);

      // Test button — runs a one-shot test against this server.
      const testBtn = document.createElement("button");
      testBtn.type = "button";
      testBtn.className = "srv-test";
      testBtn.textContent = "Test";
      testBtn.addEventListener("click", (e) => {
        e.stopPropagation(); // do not trigger card selection
        runServerTest(server.id, testBtn, statusDot);
      });
      card.appendChild(testBtn);

      const del = document.createElement("span");
      del.className = "srv-del";
      del.textContent = "\u2715";
      card.appendChild(del);

      // Selection: click on card (but not the delete or test controls).
      card.addEventListener("click", (e) => {
        if (e.target === del || e.target === testBtn || e.target === statusDot) return;
        selectServer(server.id);
      });

      // Deletion: click on the X button.
      del.addEventListener("click", () => {
        deleteServer(server.id);
      });

      serverList.appendChild(card);
    }
  }
}

// Actions =============================================================================================================

/** Select a server by ID — updates config, re-renders, and saves. */
async function selectServer(id: string) {
  if (!config) return;
  config.selected_server = id;
  renderServers();
  // The diagnostics dots depend on the *selected* server's validation
  // state — recompute them whenever the selection changes. (Note: the
  // pollDiagnostics path also calls updateDiagnostics(); both flow through
  // the same function so the cached bridge data is reused.)
  updateDiagnostics();
  await saveConfig();
}

/** Delete a server by ID — removes it from config, clears selection if needed, re-renders, saves. */
async function deleteServer(id: string) {
  if (!config) return;
  config.servers = config.servers.filter((s) => s.id !== id);
  if (config.selected_server === id) {
    // Auto-select the first remaining server, or null if none left.
    config.selected_server = config.servers.length > 0 ? config.servers[0].id : null;
  }
  renderServers();
  await saveConfig();
}

// File import =========================================================================================================

/** Open a file dialog and import servers from the selected JSON file. */
export async function importFromDialog() {
  try {
    const path = await open({
      filters: [{ name: "JSON", extensions: ["json"] }],
      multiple: false,
    });
    if (!path) return;
    const newServers = await invoke<{ id: string }[]>("import_servers_from_file", { path });
    await loadConfig();
    // Auto-test imported servers in parallel (bounded). Fire and forget.
    runTestsBounded(
      newServers.map((s) => s.id),
      TEST_CONCURRENCY,
    );
  } catch (err) {
    console.error("import from dialog failed:", err);
  }
}

// Initialization ======================================================================================================

/** Set up event listeners for the servers section. Called once from main.ts. */
export function initServers() {
  importZone.addEventListener("click", importFromDialog);
}
