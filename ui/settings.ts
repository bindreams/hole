// Settings section: toggle switches, custom dropdowns, theme switching, proxy + DNS forwarder config.

import { config, getAutostart, saveConfig, setAutostart } from "./main";
import { menuKeydown } from "./menu-keys";
import { showToast } from "./toast";
import type { DnsConfig, DnsProtocol } from "./types";

const DNS_DEFAULT: DnsConfig = {
  enabled: true,
  servers: ["1.1.1.1", "1.0.0.1"],
  protocol: "https",
  allow_insecure_bootstrap: false,
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
  updateCustomRowVisibility();
  saveConfig();
}

// DNS resolver provider ===============================================================================================

const customRow = document.getElementById("row-dns-custom")!;
const dnsServersInput = document.getElementById("input-dns-servers") as HTMLInputElement;

/** Provider key → resolver IP preset. Mirrors crates/common/src/dns_providers.rs. */
const DNS_PROVIDERS: Record<string, string[]> = {
  cloudflare: ["1.1.1.1", "1.0.0.1"],
  google: ["8.8.8.8", "8.8.4.4"],
  quad9: ["9.9.9.9", "149.112.112.112"],
  opendns: ["208.67.222.222", "208.67.220.220"],
  adguard: ["94.140.14.14", "94.140.15.15"],
};

/** Reverse-map a server list to a provider key, or "custom" if it matches none. */
function providerOf(servers: string[]): string {
  const key = [...servers].sort().join(",");
  for (const [name, ips] of Object.entries(DNS_PROVIDERS)) {
    if ([...ips].sort().join(",") === key) return name;
  }
  return "custom";
}

/**
 * Parse a comma/whitespace-separated resolver list into a validated IP array.
 * Returns null if empty or any token is not a valid IPv4/IPv6 literal — the
 * caller reverts the field on null (mirrors the port-input revert pattern).
 * The bridge is the authoritative validator; this is a UX affordance.
 */
function parseResolvers(raw: string): string[] | null {
  const tokens = raw
    .split(/[,\s]+/)
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
  if (tokens.length === 0) return null;
  for (const t of tokens) {
    if (!isIpLiteral(t)) return null;
  }
  return tokens;
}

/** Accept dotted-quad IPv4 or a colon-bearing IPv6 literal (loose; bridge is authoritative). */
function isIpLiteral(s: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (m) return m.slice(1).every((o) => Number(o) <= 255);
  return s.includes(":") && /^[0-9a-fA-F:]+$/.test(s);
}

/** Show the custom-IP row only when the active provider is "custom". */
function updateCustomRowVisibility() {
  customRow.hidden = providerOf(currentDns().servers) !== "custom";
}

function wireDnsServersInput() {
  dnsServersInput.addEventListener("change", () => {
    if (!config) return;
    const parsed = parseResolvers(dnsServersInput.value);
    if (parsed) {
      patchDns({ servers: parsed });
      dnsServersInput.value = parsed.join(", ");
    } else {
      dnsServersInput.value = currentDns().servers.join(", ");
    }
  });
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

// OS autostart toggle =================================================================================================

const AUTOSTART_TOGGLE_ID = "toggle-start-on-login";

/**
 * Flip the "Start Hole on login" toggle to `target` OS autostart state (#457).
 * The OS is the single source of truth: optimistic flip, `set_autostart` through
 * the same `crate::autostart` seam the tray uses, then commit the state the
 * backend reports; on failure revert and toast the PII-free reason.
 */
export async function applyAutostart(target: boolean): Promise<void> {
  const el = document.getElementById(AUTOSTART_TOGGLE_ID);
  if (!el) return;
  const previous = el.classList.contains("on");
  setToggleState(el, target); // optimistic
  try {
    setToggleState(el, await setAutostart(target));
  } catch (err) {
    setToggleState(el, previous); // revert to the true prior state, not an assumed !target
    showToast(`${err}`, "error");
  }
}

/** Wire the toggle click to flip OS autostart. */
function wireAutostartToggle() {
  const el = document.getElementById(AUTOSTART_TOGGLE_ID)!;
  el.addEventListener("click", () => void applyAutostart(!el.classList.contains("on")));
}

/** Render the toggle from live OS autostart state; unreadable renders unchecked (mirrors the tray). */
export async function syncAutostartToggle(): Promise<void> {
  const el = document.getElementById(AUTOSTART_TOGGLE_ID);
  if (!el) return;
  try {
    setToggleState(el, await getAutostart());
  } catch (err) {
    setToggleState(el, false);
    console.error(`getAutostart failed: ${err}`);
  }
}

// Re-read live OS autostart state when the dashboard gains focus/visibility. The
// handler is stashed on `window` so a repeat initSettings() replaces it instead of
// stacking (prod runs initSettings once per webview; tests share one jsdom).
declare global {
  interface Window {
    __holeAutostartResync?: () => void;
  }
}

function installAutostartResync() {
  if (window.__holeAutostartResync) {
    window.removeEventListener("focus", window.__holeAutostartResync);
    document.removeEventListener("visibilitychange", window.__holeAutostartResync);
  }
  const resync = () => {
    if (document.visibilityState !== "hidden") void syncAutostartToggle();
  };
  window.__holeAutostartResync = resync;
  window.addEventListener("focus", resync);
  document.addEventListener("visibilitychange", resync);
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
    const raw = portInput.value.trim();
    // Strict digits-only: parseInt would silently accept "8080abc" while
    // the field keeps showing the unparsed text.
    const parsed = /^\d+$/.test(raw) ? parseInt(raw, 10) : NaN;
    if (!Number.isNaN(parsed) && parsed > 0 && parsed <= 65535) {
      config.local_port = parsed;
      portInput.value = String(parsed);
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
    const raw = portHttpInput.value.trim();
    const parsed = /^\d+$/.test(raw) ? parseInt(raw, 10) : NaN;
    if (!Number.isNaN(parsed) && parsed > 0 && parsed <= 65535) {
      config.local_port_http = parsed;
      portHttpInput.value = String(parsed);
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
  wireAutostartToggle();
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

  // Autostart reflects live OS state — read once, then re-read on focus/visibility
  // so a tray- or System-Settings-side change shows up (user-driven events, not a timer).
  void syncAutostartToggle();
  installAutostartResync();

  // Close dropdowns on click outside.
  handleClickOutside();
}

/**
 * Wire the DNS forwarder controls (enable toggle and the protocol
 * dropdown). Both persist through `patchDns` because they
 * live in the nested `config.dns` object, not top-level config keys. The
 * sub-setting group (`#dns-nested`) mirrors the proxy-server muting
 * pattern: when the enable toggle is off, the nested controls are
 * visually greyed.
 */
function wireDnsControls() {
  // wireToggle/wireDropdown guard `config` before any visual change,
  // covering the guards the hand-wired versions carried.
  wireToggle("toggle-dns-enabled", (on) => patchDns({ enabled: on }));
  wireToggle("toggle-dns-insecure", (on) => patchDns({ allow_insecure_bootstrap: on }));

  // The protocol dropdown patches config.dns rather than a top-level key;
  // the apply callback absorbs that difference.
  wireDropdown("select-dns-protocol", "menu-dns-protocol", (value) => {
    patchDns({ protocol: value as DnsProtocol });
  });

  // Provider dropdown: a preset key applies its IP set; "custom" reveals the
  // free-form input without clobbering the current servers. patchDns refreshes
  // the custom-row visibility for both arms.
  wireDropdown("select-dns-provider", "menu-dns-provider", (value) => {
    if (value === "custom") {
      updateCustomRowVisibility();
    } else {
      patchDns({ servers: DNS_PROVIDERS[value] });
      dnsServersInput.value = currentDns().servers.join(", ");
    }
  });

  // Free-form resolver list (validated, revert-on-invalid) — port-input pattern.
  wireDnsServersInput();
}

/**
 * Sync all settings controls to match the current config. Called from main.ts
 * whenever the config is loaded or reloaded.
 */
export function renderSettings() {
  if (!config) return;

  // Toggles. (The login toggle is OS-backed — see syncAutostartToggle, not config.)
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
  setToggleState(document.getElementById("toggle-dns-insecure")!, dns.allow_insecure_bootstrap);
  syncDropdown("select-dns-protocol", "menu-dns-protocol", dns.protocol);
  syncDropdown("select-dns-provider", "menu-dns-provider", providerOf(dns.servers));
  dnsServersInput.value = dns.servers.join(", ");
  updateCustomRowVisibility();
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
