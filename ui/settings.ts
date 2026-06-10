// Settings section: toggle switches, custom dropdowns, theme switching, proxy + DNS forwarder config.

import { config, saveConfig } from "./main";
import { menuKeydown } from "./menu-keys";
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

/** Apply toggle visual + ARIA state in one place. */
function setToggleState(el: HTMLElement, on: boolean) {
  el.classList.toggle("on", on);
  el.setAttribute("aria-checked", String(on));
}

/**
 * Wire a toggle switch button.
 * @param {string} id - Element ID of the `.toggle` button.
 * @param {Function} apply - Persists the new state (writes config and saves).
 */
function wireToggle(id: string, apply: (on: boolean) => void) {
  const el = document.getElementById(id)!;
  el.addEventListener("click", () => {
    if (!config) return;
    const on = !el.classList.contains("on");
    setToggleState(el, on);
    apply(on);
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
 * Close every open dropdown menu, syncing its trigger's aria-expanded.
 * The trigger button is the menu's previous sibling inside
 * `.custom-select-wrap`.
 * @param {Element} [except] - Menu to leave open.
 */
function closeAllMenus(except?: Element) {
  for (const m of document.querySelectorAll(".custom-select-menu.open")) {
    if (m === except) continue;
    m.classList.remove("open");
    m.previousElementSibling?.setAttribute("aria-expanded", "false");
  }
}

/**
 * Wire a custom dropdown (trigger button + listbox menu of option buttons).
 * Keyboard: Enter/Space/click toggles; ArrowDown/ArrowUp on the closed
 * trigger opens; arrows/Home/End rove focus in the menu; Enter/Space picks
 * the focused option (native button click); Escape/Tab closes.
 * @param {string} btnId  - Element ID of the `.custom-select-btn` button.
 * @param {string} menuId - Element ID of the `.custom-select-menu` listbox.
 * @param {Function} apply - Persists the snake_case value (writes config and saves).
 */
function wireDropdown(btnId: string, menuId: string, apply: (value: string) => void) {
  const btn = document.getElementById(btnId)!;
  const menu = document.getElementById(menuId)!;
  const options = [...menu.querySelectorAll<HTMLElement>(".custom-select-opt")];

  const setOpen = (open: boolean) => {
    menu.classList.toggle("open", open);
    btn.setAttribute("aria-expanded", String(open));
  };

  const openAndFocus = () => {
    closeAllMenus(menu);
    setOpen(true);
    (menu.querySelector<HTMLElement>(".custom-select-opt.selected") ?? options[0])?.focus();
  };

  const close = () => {
    setOpen(false);
    btn.focus();
  };

  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    if (menu.classList.contains("open")) {
      // close() (not bare setOpen): focus may be on a now-hidden option.
      close();
    } else {
      openAndFocus();
    }
  });

  btn.addEventListener("keydown", (e) => {
    if ((e.key === "ArrowDown" || e.key === "ArrowUp") && !menu.classList.contains("open")) {
      e.preventDefault();
      openAndFocus();
    } else if (e.key === "Escape" && menu.classList.contains("open")) {
      close();
    }
  });

  menu.addEventListener("keydown", (e) => menuKeydown(e, options, close));

  for (const opt of options) {
    opt.addEventListener("click", (e) => {
      e.stopPropagation();
      if (!config) return;

      // Update selected state.
      for (const o of options) {
        o.classList.remove("selected");
        o.setAttribute("aria-selected", "false");
      }
      opt.classList.add("selected");
      opt.setAttribute("aria-selected", "true");

      // Update button text, close, and return focus to the trigger.
      btn.textContent = opt.textContent;
      close();

      apply(kebabToSnake(opt.dataset.value ?? ""));
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
  document.addEventListener("click", () => closeAllMenus());
}

// Public API ==========================================================================================================

/**
 * Wire up all settings event listeners. Called once from main.ts.
 */
export function initSettings() {
  // Toggles.
  wireToggle("toggle-start-on-login", (on) => {
    config!.start_on_login = on;
    saveConfig();
  });
  wireToggle("toggle-proxy-server", (on) => {
    config!.proxy_server_enabled = on;
    updateProxyMuting();
    saveConfig();
  });
  wireToggle("toggle-socks5", (on) => {
    config!.proxy_socks5 = on;
    updatePortConflictMarkers();
    saveConfig();
  });
  wireToggle("toggle-http", (on) => {
    config!.proxy_http = on;
    updateHttpPortVisibility();
    updatePortConflictMarkers();
    saveConfig();
  });

  // Dropdowns.
  wireDropdown("select-on-startup", "menu-on-startup", (value) => {
    config!.on_startup = value;
    saveConfig();
  });
  wireDropdown("select-theme", "menu-theme", (value) => {
    config!.theme = value;
    applyTheme(value);
    saveConfig();
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
 * Wire the DNS forwarder controls (enable + intercept toggles and the
 * protocol dropdown). All three persist through `patchDns` because they
 * live in the nested `config.dns` object, not top-level config keys. The
 * sub-setting group (`#dns-nested`) mirrors the proxy-server muting
 * pattern: when the enable toggle is off, the nested controls are
 * visually greyed.
 */
function wireDnsControls() {
  wireToggle("toggle-dns-enabled", (on) => patchDns({ enabled: on }));
  wireToggle("toggle-dns-intercept", (on) => patchDns({ intercept_udp53: on }));

  // The protocol dropdown patches config.dns rather than a top-level key;
  // the apply callback absorbs that difference.
  wireDropdown("select-dns-protocol", "menu-dns-protocol", (value) => {
    patchDns({ protocol: value as DnsProtocol });
  });
}

/**
 * Sync all settings controls to match the current config. Called from main.ts
 * whenever the config is loaded or reloaded.
 */
export function renderSettings() {
  if (!config) return;

  // Toggles.
  setToggleState(document.getElementById("toggle-start-on-login")!, !!config.start_on_login);
  setToggleState(document.getElementById("toggle-proxy-server")!, !!config.proxy_server_enabled);
  setToggleState(document.getElementById("toggle-socks5")!, !!config.proxy_socks5);
  setToggleState(document.getElementById("toggle-http")!, !!config.proxy_http);

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
  setToggleState(document.getElementById("toggle-dns-enabled")!, dns.enabled);
  setToggleState(document.getElementById("toggle-dns-intercept")!, dns.intercept_udp53);
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
    const selected = opt.dataset.value === dataVal;
    opt.classList.toggle("selected", selected);
    opt.setAttribute("aria-selected", String(selected));
    if (selected) btn.textContent = opt.textContent;
  }
}
