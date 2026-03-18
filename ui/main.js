const { invoke } = window.__TAURI__.core;

// State =====

let config = null;

// DOM refs =====

const serverList = document.getElementById("server-list");
const emptyMessage = document.getElementById("empty-message");
const localPortInput = document.getElementById("local-port");
const btnImport = document.getElementById("btn-import");
const btnSave = document.getElementById("btn-save");
const saveStatus = document.getElementById("save-status");
const statusBadge = document.getElementById("status");

// Rendering =====

function renderServers() {
  serverList.innerHTML = "";

  if (!config || config.servers.length === 0) {
    emptyMessage.style.display = "";
    return;
  }
  emptyMessage.style.display = "none";

  for (const server of config.servers) {
    const tr = document.createElement("tr");
    if (server.id === config.selected_server) {
      tr.classList.add("selected");
    }

    // Radio
    const tdRadio = document.createElement("td");
    const radio = document.createElement("input");
    radio.type = "radio";
    radio.name = "selected-server";
    radio.checked = server.id === config.selected_server;
    radio.addEventListener("change", () => {
      config.selected_server = server.id;
      renderServers();
    });
    tdRadio.appendChild(radio);
    tr.appendChild(tdRadio);

    // Name
    const tdName = document.createElement("td");
    tdName.textContent = server.name;
    tr.appendChild(tdName);

    // Address
    const tdAddr = document.createElement("td");
    tdAddr.textContent = `${server.server}:${server.server_port}`;
    tr.appendChild(tdAddr);

    // Method
    const tdMethod = document.createElement("td");
    tdMethod.textContent = server.method;
    tr.appendChild(tdMethod);

    // Plugin
    const tdPlugin = document.createElement("td");
    if (server.plugin) {
      const badge = document.createElement("span");
      badge.className = "plugin-badge";
      badge.textContent = server.plugin;
      tdPlugin.appendChild(badge);
    }
    tr.appendChild(tdPlugin);

    // Delete
    const tdDelete = document.createElement("td");
    const btnDel = document.createElement("button");
    btnDel.className = "btn-delete";
    btnDel.textContent = "Delete";
    btnDel.addEventListener("click", () => {
      config.servers = config.servers.filter((s) => s.id !== server.id);
      if (config.selected_server === server.id) {
        config.selected_server = null;
      }
      renderServers();
    });
    tdDelete.appendChild(btnDel);
    tr.appendChild(tdDelete);

    serverList.appendChild(tr);
  }
}

// Actions =====

async function loadConfig() {
  config = await invoke("get_config");
  localPortInput.value = config.local_port;
  renderServers();
}

async function saveConfig() {
  config.local_port = parseInt(localPortInput.value, 10) || 4073;
  try {
    await invoke("save_config", { config });
    saveStatus.textContent = "Saved.";
    setTimeout(() => { saveStatus.textContent = ""; }, 2000);
  } catch (e) {
    saveStatus.textContent = `Error: ${e}`;
  }
}

async function importServers() {
  try {
    const result = await window.__TAURI__.dialog.open({
      filters: [{ name: "JSON", extensions: ["json"] }],
      multiple: false,
    });
    if (!result) return;

    await invoke("import_servers_from_file", { path: result });
    await loadConfig();
    saveStatus.textContent = "Servers imported.";
    setTimeout(() => { saveStatus.textContent = ""; }, 2000);
  } catch (e) {
    saveStatus.textContent = `Import error: ${e}`;
  }
}

async function checkDaemonStatus() {
  try {
    const status = await invoke("get_proxy_status");
    statusBadge.textContent = status.running ? "Daemon: running" : "Daemon: stopped";
    statusBadge.className = `status ${status.running ? "connected" : "disconnected"}`;
  } catch {
    statusBadge.textContent = "Daemon: disconnected";
    statusBadge.className = "status disconnected";
  }
}

// Events =====

btnSave.addEventListener("click", saveConfig);
btnImport.addEventListener("click", importServers);

// Init =====

loadConfig();
checkDaemonStatus();
