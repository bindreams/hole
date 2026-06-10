// Servers section: rendering server cards, selection, deletion, file import.

import { invoke } from "@tauri-apps/api/core";
import { message, open } from "@tauri-apps/plugin-dialog";
import { describeUnknownImportError } from "./import-failure";
import { config, loadConfig, runTestsBounded, saveConfig, TEST_CONCURRENCY } from "./main";
import { updateDiagnostics } from "./sidebar";
import { showToast } from "./toast";
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

  // External re-renders (e.g. validation-changed -> loadConfig) destroy the
  // focused control with the rest of the list; remember which server's
  // button had focus so the rebuild can put it back.
  const active = document.activeElement;
  let restore: { serverId: string; selector: string } | null = null;
  if (active instanceof HTMLElement && serverList.contains(active)) {
    const serverId = (active.closest(".srv") as HTMLElement | null)?.dataset.serverId;
    const selector = active.classList.contains("srv-test")
      ? ".srv-test"
      : active.classList.contains("srv-del")
        ? ".srv-del"
        : null;
    if (serverId && selector) restore = { serverId, selector };
  }

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

      const del = document.createElement("button");
      del.type = "button";
      del.className = "srv-del";
      del.textContent = "\u2715";
      del.setAttribute("aria-label", `Delete ${server.name}`);
      card.appendChild(del);

      // Selection: click on the card. The Test and delete buttons stop
      // propagation themselves; the status dot is inert but must not
      // select either.
      card.addEventListener("click", (e) => {
        if (e.target === statusDot) return;
        selectServer(server.id);
      });

      // Deletion: click on the X button. Stop propagation so the card's
      // selection handler never races the delete (keyboard activation
      // synthesizes a bubbling click).
      del.addEventListener("click", (e) => {
        e.stopPropagation();
        deleteServer(server.id);
      });

      serverList.appendChild(card);
    }
  }

  if (restore) {
    // Match by dataset rather than an interpolated attribute selector so
    // the server id needs no CSS escaping.
    for (const card of serverList.querySelectorAll<HTMLElement>(".srv")) {
      if (card.dataset.serverId === restore.serverId) {
        card.querySelector<HTMLElement>(restore.selector)?.focus();
        break;
      }
    }
  }
}

// Actions =============================================================================================================

/** Select a server by ID — updates config, re-renders, and saves. */
async function selectServer(id: string) {
  if (!config) return;
  config.selected_server = id;
  renderServers();
  // The diagnostics dots depend on the selected server's validation
  // state — recompute on selection change.
  updateDiagnostics();
  await saveConfig();
}

/** Delete a server by ID — removes it from config, clears selection if needed, re-renders, saves. */
async function deleteServer(id: string) {
  if (!config) return;
  const idx = config.servers.findIndex((s) => s.id === id);
  // The re-render destroys the focused delete button; remember whether
  // focus was inside the list so we can keep a keyboard user in place.
  const hadFocusInList = serverList.contains(document.activeElement);
  config.servers = config.servers.filter((s) => s.id !== id);
  if (config.selected_server === id) {
    // Auto-select the first remaining server, or null if none left.
    config.selected_server = config.servers.length > 0 ? config.servers[0].id : null;
  }
  renderServers();
  if (hadFocusInList) {
    const dels = serverList.querySelectorAll<HTMLElement>(".srv-del");
    (dels[Math.min(idx, dels.length - 1)] ?? importZone).focus();
  }
  await saveConfig();
}

// File import =========================================================================================================

/**
 * Show a blocking error dialog for an import failure. The dialog
 * pauses the JS event loop until the user clicks OK — chosen
 * deliberately so import errors can't be missed (a toast that
 * auto-dismisses in 10s is easy to overlook). See bindreams/hole#385.
 *
 * Accepts `unknown` because the Tauri invoke rejection type is unknown:
 * the structured `ImportFailure` is the happy path, but a transport-
 * layer failure (channel closed mid-call) delivers a string/Error.
 * `describeUnknownImportError` handles both shapes uniformly.
 */
export async function showImportFailureDialog(failure: unknown): Promise<void> {
  const { title, body } = describeUnknownImportError(failure);
  await message(body, { title, kind: "error" });
}

/** Open a file dialog and import servers from the selected JSON file. */
export async function importFromDialog() {
  let path: string | null;
  try {
    path = await open({
      filters: [{ name: "JSON", extensions: ["json"] }],
      multiple: false,
    });
  } catch (err) {
    console.error("file dialog failed:", err);
    showToast(`Could not open file dialog: ${err}`, "error");
    return;
  }
  if (!path) return; // user cancelled

  let newServers: { id: string }[];
  try {
    newServers = await invoke<{ id: string }[]>("import_servers_from_file", { path });
  } catch (err) {
    // Rust `ImportFailure` enum (happy path) or a transport-layer
    // string/Error; `showImportFailureDialog` handles both.
    console.error("import from dialog failed:", err);
    await showImportFailureDialog(err);
    return;
  }

  await loadConfig();

  if (newServers.length === 0) {
    showToast("No new servers — already in the list.", "info");
    return;
  }
  showToast(`Imported ${newServers.length} server(s).`, "success");

  // Auto-test imported servers in parallel (bounded). Fire and forget.
  runTestsBounded(
    newServers.map((s) => s.id),
    TEST_CONCURRENCY,
  );
}

/**
 * Clear the drag-over highlight on the import zone. Called by the
 * `tauri://drag-drop` listener in main.ts because the OS does not
 * always fire a final `dragleave` after a successful drop, so relying
 * on `dragleave` alone leaves the zone stuck highlighted.
 */
export function clearImportZoneHighlight(): void {
  importZone.classList.remove("drag-over");
}

// Initialization ======================================================================================================

/** Set up event listeners for the servers section. Called once from main.ts. */
export function initServers() {
  importZone.addEventListener("click", importFromDialog);

  // Visual feedback during a file drag. The actual drop is delivered by
  // Tauri's native handler via `tauri://drag-drop` (wired in main.ts);
  // these HTML5 events run in parallel and only drive the styling.
  importZone.addEventListener("dragenter", () => importZone.classList.add("drag-over"));
  importZone.addEventListener("dragleave", () => importZone.classList.remove("drag-over"));
}
