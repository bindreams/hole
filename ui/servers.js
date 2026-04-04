// Servers section: rendering server cards, selection, deletion, file import.

import { config, loadConfig, saveConfig } from "./main.js";

const { invoke } = window.__TAURI__.core;

// DOM references =====

const serverList = document.getElementById("server-list");
const importZone = document.getElementById("import-zone");

// Rendering =====

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
      saddr.textContent = server.server + ":" + server.server_port;
      card.appendChild(saddr);

      if (server.plugin) {
        const badge = document.createElement("span");
        badge.className = "plugin-badge";
        badge.textContent = server.plugin;
        card.appendChild(badge);
      }

      const del = document.createElement("span");
      del.className = "srv-del";
      del.textContent = "\u2715";
      card.appendChild(del);

      // Selection: click on card (but not the delete button).
      card.addEventListener("click", (e) => {
        if (e.target === del) return;
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

// Actions =====

/** Select a server by ID — updates config, re-renders, and saves. */
async function selectServer(id) {
  if (!config) return;
  config.selected_server = id;
  renderServers();
  await saveConfig();
}

/** Delete a server by ID — removes it from config, clears selection if needed, re-renders, saves. */
async function deleteServer(id) {
  if (!config) return;
  config.servers = config.servers.filter((s) => s.id !== id);
  if (config.selected_server === id) {
    config.selected_server = null;
  }
  renderServers();
  await saveConfig();
}

// File import =====

/** Open a file dialog and import servers from the selected JSON file. */
async function importFromDialog() {
  try {
    const path = await window.__TAURI__.dialog.open({
      filters: [{ name: "JSON", extensions: ["json"] }],
      multiple: false,
    });
    if (!path) return;
    await invoke("import_servers_from_file", { path });
    await loadConfig();
  } catch (err) {
    console.error("import from dialog failed:", err);
  }
}

// Initialization =====

/** Set up event listeners for the servers section. Called once from main.js. */
export function initServers() {
  importZone.addEventListener("click", importFromDialog);
}
