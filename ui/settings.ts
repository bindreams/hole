// Settings section: toggle switches, custom dropdowns, theme switching, proxy config.

import { config, saveConfig } from "./main";

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

function updateProxyMuting() {
  if (!config) return;
  if (config.proxy_server_enabled) {
    proxyNested.classList.remove("muted");
  } else {
    proxyNested.classList.add("muted");
  }
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
  });
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
  wireToggle("toggle-socks5", "proxy_socks5");
  wireToggle("toggle-http", "proxy_http");

  // Dropdowns.
  wireDropdown("select-on-startup", "menu-on-startup", "on_startup");
  wireDropdown("select-theme", "menu-theme", "theme", (value) => {
    applyTheme(value);
  });

  // Port input.
  wirePortInput();

  // Close dropdowns on click outside.
  handleClickOutside();
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

  // Port input.
  portInput.value = String(config.local_port ?? "");

  // Proxy muting.
  updateProxyMuting();

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
