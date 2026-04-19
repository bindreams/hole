// Settings section: toggle switches, custom dropdowns, theme switching, proxy config.

import { config, saveConfig } from "./main";
import type { DnsConfig, DnsProtocol } from "./types";

const DNS_DEFAULT: DnsConfig = {
  enabled: true,
  servers: ["1.1.1.1", "1.0.0.1"],
  protocol: "https",
  intercept_udp53: true,
};

// Theme management ====================================================================================================

const systemThemeQuery = window.matchMedia("(prefers-color-scheme: dark)");
let systemThemeListener: (() => void) | null = null;

/**
 * Apply a theme to the document. When `value` is "system", a media-query
 * listener is installed so the theme follows the OS preference live.
 * @param {string} value - "light", "dark", or "system"
 */
function applyTheme(value: string) {
  // Always clean up a previous system-theme listener first.
  if (systemThemeListener) {
    systemThemeQuery.removeEventListener("change", systemThemeListener);
    systemThemeListener = null;
  }

  if (value === "system") {
    const setFromOs = () => {
      document.documentElement.dataset.theme = systemThemeQuery.matches ? "dark" : "light";
    };
    setFromOs();
    systemThemeListener = setFromOs;
    systemThemeQuery.addEventListener("change", systemThemeListener);
  } else {
    document.documentElement.dataset.theme = value;
  }
}

// Proxy muting ========================================================================================================

const proxyNested = document.getElementById("proxy-nested")!;
const dnsNested = document.getElementById("dns-nested")!;

function updateProxyMuting() {
  if (!config) return;
  if (config.proxy_server_enabled) {
    proxyNested.classList.remove("muted");
  } else {
    proxyNested.classList.add("muted");
  }
}

function currentDns(): DnsConfig {
  return (config?.dns as DnsConfig | undefined) ?? DNS_DEFAULT;
}

function updateDnsMuting() {
  const dns = currentDns();
  if (dns.enabled) {
    dnsNested.classList.remove("muted");
  } else {
    dnsNested.classList.add("muted");
  }
}

function patchDns(partial: Partial<DnsConfig>) {
  if (!config) return;
  const next: DnsConfig = { ...currentDns(), ...partial };
  config.dns = next;
  updateDnsMuting();
  saveConfig();
}

// Toggle component ====================================================================================================

/**
 * Wire a toggle switch element.
 * @param {string} id        - Element ID of the `.toggle` div.
 * @param {string} configKey - Key in `config` to read/write (boolean).
 * @param {Function} [onToggle] - Optional callback after state changes.
 */
function wireToggle(id: string, configKey: string, onToggle?: (on: boolean) => void) {
  const el = document.getElementById(id)!;
  el.addEventListener("click", () => {
    if (!config) return;
    const on = !el.classList.contains("on");
    el.classList.toggle("on", on);
    config[configKey] = on;
    if (onToggle) onToggle(on);
    saveConfig();
  });
}

// Dropdown component ==================================================================================================

/**
 * Convert a kebab-case data-value from the DOM to the snake_case config value.
 * @param {string} kebab - e.g. "do-not-connect"
 * @returns {string} e.g. "do_not_connect"
 */
function kebabToSnake(kebab: string): string {
  return kebab.replace(/-/g, "_");
}

/**
 * Convert a snake_case config value to the kebab-case data-value used in DOM.
 * @param {string} snake - e.g. "do_not_connect"
 * @returns {string} e.g. "do-not-connect"
 */
function snakeToKebab(snake: string): string {
  return snake.replace(/_/g, "-");
}

/**
 * Wire a custom dropdown.
 * @param {string} btnId     - Element ID of `.custom-select-btn`.
 * @param {string} menuId    - Element ID of `.custom-select-menu`.
 * @param {string} configKey - Key in `config` to read/write (string).
 * @param {Function} [onChange] - Optional callback after selection changes.
 */
function wireDropdown(btnId: string, menuId: string, configKey: string, onChange?: (value: string) => void) {
  const btn = document.getElementById(btnId)!;
  const menu = document.getElementById(menuId)!;

  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    // Close any other open menus first.
    for (const m of document.querySelectorAll(".custom-select-menu.open")) {
      if (m !== menu) m.classList.remove("open");
    }
    menu.classList.toggle("open");
  });

  for (const opt of menu.querySelectorAll<HTMLElement>(".custom-select-opt")) {
    opt.addEventListener("click", (e) => {
      e.stopPropagation();
      if (!config) return;

      // Update selected state.
      for (const o of menu.querySelectorAll(".custom-select-opt")) {
        o.classList.remove("selected");
      }
      opt.classList.add("selected");

      // Update button text and close menu.
      btn.textContent = opt.textContent;
      menu.classList.remove("open");

      // Update config.
      const value = kebabToSnake(opt.dataset.value ?? "");
      config[configKey] = value;
      if (onChange) onChange(value);
      saveConfig();
    });
  }
}

// Port input ==========================================================================================================

const portInput = document.getElementById("input-port") as HTMLInputElement;
const portHttpInput = document.getElementById("input-port-http") as HTMLInputElement;
const rowPortHttp = document.getElementById("row-port-http")!;

function wirePortInput() {
  portInput.addEventListener("change", () => {
    if (!config) return;
    const parsed = parseInt(portInput.value, 10);
    if (!Number.isNaN(parsed) && parsed > 0 && parsed <= 65535) {
      config.local_port = parsed;
      saveConfig();
    } else {
      // Revert to current config value on invalid input.
      portInput.value = String(config.local_port ?? "");
    }
    updatePortConflictMarkers();
  });
}

function wireHttpPortInput() {
  portHttpInput.addEventListener("change", () => {
    if (!config) return;
    const parsed = parseInt(portHttpInput.value, 10);
    if (!Number.isNaN(parsed) && parsed > 0 && parsed <= 65535) {
      config.local_port_http = parsed;
      saveConfig();
    } else {
      portHttpInput.value = String(config.local_port_http ?? "");
    }
    updatePortConflictMarkers();
  });
}

/**
 * Hide/show the HTTP port row to match the HTTP toggle. The bridge
 * ignores `local_port_http` when `proxy_http` is false, but we mirror
 * that in the UI so users can't set a value they don't see applied.
 */
function updateHttpPortVisibility() {
  if (!config) return;
  rowPortHttp.hidden = !config.proxy_http;
}

/**
 * Mark both port inputs as `invalid` when SOCKS5 and HTTP are both
 * enabled and their ports collide. The bridge is the authoritative
 * validator (see `ProxyError::DuplicateListenerPort`) — this is only a
 * UX affordance so the user sees the problem before hitting Start.
 */
function updatePortConflictMarkers() {
  if (!config) return;
  const bothOn = !!config.proxy_socks5 && !!config.proxy_http;
  const collide = bothOn && config.local_port === config.local_port_http;
  portInput.classList.toggle("invalid", collide);
  portHttpInput.classList.toggle("invalid", collide);
}

// Click-outside handler ===============================================================================================

function handleClickOutside() {
  document.addEventListener("click", () => {
    for (const menu of document.querySelectorAll(".custom-select-menu.open")) {
      menu.classList.remove("open");
    }
  });
}

// Public API ==========================================================================================================

/**
 * Wire up all settings event listeners. Called once from main.ts.
 */
export function initSettings() {
  // Toggles.
  wireToggle("toggle-start-on-login", "start_on_login");
  wireToggle("toggle-proxy-server", "proxy_server_enabled", () => {
    updateProxyMuting();
  });
  wireToggle("toggle-socks5", "proxy_socks5", () => {
    updatePortConflictMarkers();
  });
  wireToggle("toggle-http", "proxy_http", () => {
    updateHttpPortVisibility();
    updatePortConflictMarkers();
  });

  // Dropdowns.
  wireDropdown("select-on-startup", "menu-on-startup", "on_startup");
  wireDropdown("select-theme", "menu-theme", "theme", (value) => {
    applyTheme(value);
  });

  // Port inputs.
  wirePortInput();
  wireHttpPortInput();

  // DNS forwarder controls.
  wireDnsControls();

  // Close dropdowns on click outside.
  handleClickOutside();
}

/**
 * Wire the DNS forwarder UI. The sub-setting group (`#dns-nested`) mirrors
 * the proxy-server muting pattern: when the enable toggle is off, the
 * nested controls are visually greyed.
 */
function wireDnsControls() {
  const enabledEl = document.getElementById("toggle-dns-enabled")!;
  enabledEl.addEventListener("click", () => {
    const on = !enabledEl.classList.contains("on");
    enabledEl.classList.toggle("on", on);
    patchDns({ enabled: on });
  });

  const interceptEl = document.getElementById("toggle-dns-intercept")!;
  interceptEl.addEventListener("click", () => {
    const on = !interceptEl.classList.contains("on");
    interceptEl.classList.toggle("on", on);
    patchDns({ intercept_udp53: on });
  });

  // DNS protocol dropdown — kebab-to-snake with the same helper used by
  // the theme/on-startup dropdowns; maps "plain-udp" → "plain_udp", etc.
  const btn = document.getElementById("select-dns-protocol")!;
  const menu = document.getElementById("menu-dns-protocol")!;
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    for (const m of document.querySelectorAll(".custom-select-menu.open")) {
      if (m !== menu) m.classList.remove("open");
    }
    menu.classList.toggle("open");
  });
  for (const opt of menu.querySelectorAll<HTMLElement>(".custom-select-opt")) {
    opt.addEventListener("click", (e) => {
      e.stopPropagation();
      for (const o of menu.querySelectorAll(".custom-select-opt")) o.classList.remove("selected");
      opt.classList.add("selected");
      btn.textContent = opt.textContent;
      menu.classList.remove("open");
      patchDns({ protocol: kebabToSnake(opt.dataset.value ?? "") as DnsProtocol });
    });
  }
}

/**
 * Sync all settings controls to match the current config. Called from main.ts
 * whenever the config is loaded or reloaded.
 */
export function renderSettings() {
  if (!config) return;

  // Toggles.
  document.getElementById("toggle-start-on-login")!.classList.toggle("on", !!config.start_on_login);
  document.getElementById("toggle-proxy-server")!.classList.toggle("on", !!config.proxy_server_enabled);
  document.getElementById("toggle-socks5")!.classList.toggle("on", !!config.proxy_socks5);
  document.getElementById("toggle-http")!.classList.toggle("on", !!config.proxy_http);

  // Dropdowns.
  syncDropdown("select-on-startup", "menu-on-startup", config.on_startup ?? "do_not_connect");
  syncDropdown("select-theme", "menu-theme", config.theme ?? "dark");

  // Port inputs.
  portInput.value = String(config.local_port ?? "");
  portHttpInput.value = String(config.local_port_http ?? "");
  updateHttpPortVisibility();
  updatePortConflictMarkers();

  // Proxy muting.
  updateProxyMuting();

  // DNS forwarder state.
  const dns = currentDns();
  document.getElementById("toggle-dns-enabled")!.classList.toggle("on", dns.enabled);
  document.getElementById("toggle-dns-intercept")!.classList.toggle("on", dns.intercept_udp53);
  syncDropdown("select-dns-protocol", "menu-dns-protocol", dns.protocol);
  updateDnsMuting();

  // Theme.
  applyTheme(config.theme ?? "dark");
}

/**
 * Sync a dropdown's button text and selected option to match a config value.
 * @param {string} btnId     - Element ID of `.custom-select-btn`.
 * @param {string} menuId    - Element ID of `.custom-select-menu`.
 * @param {string} configVal - Current config value (snake_case).
 */
function syncDropdown(btnId: string, menuId: string, configVal: string) {
  const btn = document.getElementById(btnId)!;
  const menu = document.getElementById(menuId)!;
  const dataVal = snakeToKebab(configVal);

  for (const opt of menu.querySelectorAll<HTMLElement>(".custom-select-opt")) {
    if (opt.dataset.value === dataVal) {
      opt.classList.add("selected");
      btn.textContent = opt.textContent;
    } else {
      opt.classList.remove("selected");
    }
  }
}
