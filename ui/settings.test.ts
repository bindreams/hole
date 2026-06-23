import { beforeEach, describe, expect, it, vi } from "vitest";

// settings.ts captures `window.matchMedia(...)` at import time, but jsdom
// does not implement matchMedia — stub the MediaQueryList surface the theme
// code uses before the dynamic import runs.
vi.stubGlobal(
  "matchMedia",
  (media: string): MediaQueryList =>
    ({
      media,
      matches: false,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    }) as MediaQueryList,
);

const mainMock: {
  config: Record<string, unknown> | null;
  saveConfig: ReturnType<typeof vi.fn<(...args: unknown[]) => void>>;
  getAutostart: ReturnType<typeof vi.fn<() => Promise<boolean>>>;
  setAutostart: ReturnType<typeof vi.fn<(enabled: boolean) => Promise<boolean>>>;
} = {
  config: null,
  saveConfig: vi.fn<(...args: unknown[]) => void>(),
  getAutostart: vi.fn<() => Promise<boolean>>(),
  setAutostart: vi.fn<(enabled: boolean) => Promise<boolean>>(),
};
vi.mock("./main", () => ({
  get config() {
    return mainMock.config;
  },
  saveConfig: (...args: unknown[]) => mainMock.saveConfig(...args),
  getAutostart: () => mainMock.getAutostart(),
  setAutostart: (enabled: boolean) => mainMock.setAutostart(enabled),
}));

const toastMock = vi.fn();
vi.mock("./toast", () => ({ showToast: (...args: unknown[]) => toastMock(...args) }));

const SETTINGS_DOM = `
  <span class="setting-label" id="lbl-start-on-login">Start Hole on login</span>
  <button type="button" class="toggle" id="toggle-start-on-login" role="switch" aria-checked="false" aria-labelledby="lbl-start-on-login"></button>

  <span class="setting-label" id="lbl-on-startup">On startup</span>
  <div class="custom-select-wrap">
    <button type="button" class="custom-select-btn" id="select-on-startup" aria-haspopup="listbox" aria-expanded="false" aria-labelledby="lbl-on-startup select-on-startup">Do not connect</button>
    <div class="custom-select-menu" id="menu-on-startup" role="listbox" aria-labelledby="lbl-on-startup">
      <button type="button" class="custom-select-opt selected" role="option" tabindex="-1" aria-selected="true" data-value="do-not-connect">Do not connect</button>
      <button type="button" class="custom-select-opt" role="option" tabindex="-1" aria-selected="false" data-value="restore-last-state">Restore last state</button>
      <button type="button" class="custom-select-opt" role="option" tabindex="-1" aria-selected="false" data-value="always-connect">Always connect</button>
    </div>
  </div>

  <span class="setting-label" id="lbl-theme">Theme</span>
  <div class="custom-select-wrap">
    <button type="button" class="custom-select-btn" id="select-theme" aria-haspopup="listbox" aria-expanded="false" aria-labelledby="lbl-theme select-theme">Dark</button>
    <div class="custom-select-menu" id="menu-theme" role="listbox" aria-labelledby="lbl-theme">
      <button type="button" class="custom-select-opt" role="option" tabindex="-1" aria-selected="false" data-value="light">Light</button>
      <button type="button" class="custom-select-opt selected" role="option" tabindex="-1" aria-selected="true" data-value="dark">Dark</button>
      <button type="button" class="custom-select-opt" role="option" tabindex="-1" aria-selected="false" data-value="system">System</button>
    </div>
  </div>

  <span class="setting-label" id="lbl-proxy-server">Local proxy server</span>
  <button type="button" class="toggle" id="toggle-proxy-server" role="switch" aria-checked="false" aria-labelledby="lbl-proxy-server"></button>
  <div class="setting-nested" id="proxy-nested">
    <span class="setting-label" id="lbl-socks5">SOCKS5</span>
    <button type="button" class="toggle" id="toggle-socks5" role="switch" aria-checked="false" aria-labelledby="lbl-socks5"></button>
    <span class="setting-label" id="lbl-http">HTTP</span>
    <button type="button" class="toggle" id="toggle-http" role="switch" aria-checked="false" aria-labelledby="lbl-http"></button>
    <input class="field-input" id="input-port" type="text" value="4073">
    <div id="row-port-http" hidden>
      <input class="field-input" id="input-port-http" type="text" value="4074">
    </div>
  </div>

  <span class="setting-label" id="lbl-dns-enabled">DNS forwarder</span>
  <button type="button" class="toggle" id="toggle-dns-enabled" role="switch" aria-checked="false" aria-labelledby="lbl-dns-enabled"></button>
  <div class="setting-nested" id="dns-nested">
    <span class="setting-label" id="lbl-dns-protocol">Protocol</span>
    <div class="custom-select-wrap">
      <button type="button" class="custom-select-btn" id="select-dns-protocol" aria-haspopup="listbox" aria-expanded="false" aria-labelledby="lbl-dns-protocol select-dns-protocol">DNS over HTTPS</button>
      <div class="custom-select-menu" id="menu-dns-protocol" role="listbox" aria-labelledby="lbl-dns-protocol">
        <button type="button" class="custom-select-opt" role="option" tabindex="-1" aria-selected="false" data-value="plain-udp">Plain UDP</button>
        <button type="button" class="custom-select-opt" role="option" tabindex="-1" aria-selected="false" data-value="plain-tcp">Plain TCP</button>
        <button type="button" class="custom-select-opt" role="option" tabindex="-1" aria-selected="false" data-value="tls">DNS over TLS</button>
        <button type="button" class="custom-select-opt selected" role="option" tabindex="-1" aria-selected="true" data-value="https">DNS over HTTPS</button>
      </div>
    </div>
    <span class="setting-label" id="lbl-dns-provider">Resolver</span>
    <div class="custom-select-wrap">
      <button type="button" class="custom-select-btn" id="select-dns-provider" aria-haspopup="listbox" aria-expanded="false" aria-labelledby="lbl-dns-provider select-dns-provider">Cloudflare</button>
      <div class="custom-select-menu" id="menu-dns-provider" role="listbox" aria-labelledby="lbl-dns-provider">
        <button type="button" class="custom-select-opt selected" role="option" tabindex="-1" aria-selected="true" data-value="cloudflare">Cloudflare</button>
        <button type="button" class="custom-select-opt" role="option" tabindex="-1" aria-selected="false" data-value="google">Google</button>
        <button type="button" class="custom-select-opt" role="option" tabindex="-1" aria-selected="false" data-value="quad9">Quad9</button>
        <button type="button" class="custom-select-opt" role="option" tabindex="-1" aria-selected="false" data-value="opendns">OpenDNS</button>
        <button type="button" class="custom-select-opt" role="option" tabindex="-1" aria-selected="false" data-value="adguard">AdGuard</button>
        <button type="button" class="custom-select-opt" role="option" tabindex="-1" aria-selected="false" data-value="custom">Custom&hellip;</button>
      </div>
    </div>
    <div class="setting-row" id="row-dns-custom" hidden>
      <input class="field-input" id="input-dns-servers" type="text" value="1.1.1.1, 1.0.0.1">
    </div>
    <span class="setting-label" id="lbl-dns-insecure">Allow insecure bootstrap</span>
    <button type="button" class="toggle" id="toggle-dns-insecure" role="switch" aria-checked="false" aria-labelledby="lbl-dns-insecure"></button>
  </div>
`;

function freshConfig(): Record<string, unknown> {
  return {
    proxy_server_enabled: true,
    proxy_socks5: true,
    proxy_http: false,
    local_port: 4073,
    local_port_http: 4074,
    on_startup: "do_not_connect",
    theme: "dark",
    dns: { enabled: true, servers: ["1.1.1.1"], protocol: "https", allow_insecure_bootstrap: false },
  };
}

async function setup() {
  const mod = await import("./settings");
  mod.initSettings();
  mod.renderSettings();
  return mod;
}

beforeEach(() => {
  mainMock.saveConfig.mockReset();
  mainMock.getAutostart.mockReset();
  mainMock.getAutostart.mockResolvedValue(false);
  mainMock.setAutostart.mockReset();
  mainMock.setAutostart.mockImplementation((enabled: boolean) => Promise.resolve(enabled));
  toastMock.mockReset();
  mainMock.config = freshConfig();
  document.body.innerHTML = SETTINGS_DOM;
  vi.resetModules();
});

describe("settings toggles", () => {
  it("renderSettings syncs .on and aria-checked from config (proxy; login is OS-backed)", async () => {
    await setup();
    const proxy = document.getElementById("toggle-proxy-server")!;
    expect(proxy.classList.contains("on")).toBe(true);
    expect(proxy.getAttribute("aria-checked")).toBe("true");
  });

  it("proxy-server toggle drives nested muting", async () => {
    await setup();
    const proxy = document.getElementById("toggle-proxy-server")!;
    const nested = document.getElementById("proxy-nested")!;
    expect(nested.classList.contains("muted")).toBe(false);
    proxy.click();
    expect(mainMock.config!.proxy_server_enabled).toBe(false);
    expect(nested.classList.contains("muted")).toBe(true);
  });

  it("DNS enabled toggle patches config.dns and syncs aria-checked", async () => {
    await setup();
    const enabled = document.getElementById("toggle-dns-enabled")!;
    expect(enabled.getAttribute("aria-checked")).toBe("true");
    enabled.click();
    expect((mainMock.config!.dns as { enabled: boolean }).enabled).toBe(false);
    expect(enabled.getAttribute("aria-checked")).toBe("false");
    expect(document.getElementById("dns-nested")!.classList.contains("muted")).toBe(true);
  });
});

describe("autostart toggle (OS-backed, #457)", () => {
  it("click drives set_autostart with the flipped target, never saveConfig", async () => {
    await setup();
    const login = document.getElementById("toggle-start-on-login")!;
    login.click(); // set_autostart(true) is called synchronously before the await
    expect(mainMock.setAutostart).toHaveBeenCalledWith(true);
    expect(mainMock.saveConfig).not.toHaveBeenCalled();
  });

  it("applyAutostart commits the OS state the backend returns", async () => {
    mainMock.setAutostart.mockResolvedValue(true);
    const { applyAutostart } = await setup();
    const login = document.getElementById("toggle-start-on-login")!;
    await applyAutostart(true);
    expect(login.classList.contains("on")).toBe(true);
    expect(login.getAttribute("aria-checked")).toBe("true");
  });

  it("applyAutostart reverts the toggle and toasts on failure", async () => {
    mainMock.setAutostart.mockRejectedValue("Failed to enable Start at Login. See gui.log for details.");
    const { applyAutostart } = await setup();
    const login = document.getElementById("toggle-start-on-login")!;
    await applyAutostart(true);
    expect(login.classList.contains("on")).toBe(false);
    expect(login.getAttribute("aria-checked")).toBe("false");
    expect(toastMock).toHaveBeenCalledWith(expect.stringContaining("Start at Login"), "error");
  });

  it("applyAutostart reverts to the true prior state (not !target) on failure", async () => {
    mainMock.setAutostart.mockRejectedValue("boom");
    const { applyAutostart } = await setup();
    const login = document.getElementById("toggle-start-on-login")!;
    login.classList.add("on"); // prior state = on
    login.setAttribute("aria-checked", "true");
    await applyAutostart(true); // target == current; an assumed !target would wrongly flip to off
    expect(login.classList.contains("on")).toBe(true);
    expect(login.getAttribute("aria-checked")).toBe("true");
  });

  it("syncAutostartToggle reflects the live OS state", async () => {
    mainMock.getAutostart.mockResolvedValue(true);
    const { syncAutostartToggle } = await setup();
    const login = document.getElementById("toggle-start-on-login")!;
    await syncAutostartToggle();
    expect(login.classList.contains("on")).toBe(true);
    expect(login.getAttribute("aria-checked")).toBe("true");
  });

  it("syncAutostartToggle renders unchecked when OS state is unreadable", async () => {
    const { syncAutostartToggle } = await setup();
    const login = document.getElementById("toggle-start-on-login")!;
    login.classList.add("on");
    login.setAttribute("aria-checked", "true");
    mainMock.getAutostart.mockRejectedValue("registry denied");
    await syncAutostartToggle();
    expect(login.classList.contains("on")).toBe(false);
    expect(login.getAttribute("aria-checked")).toBe("false");
  });

  it("re-init does not stack the focus/visibility re-sync listener", async () => {
    await setup(); // init #1 registers the resync handler
    await setup(); // init #2 must REPLACE it, not add a second
    mainMock.getAutostart.mockClear();
    window.dispatchEvent(new Event("focus"));
    expect(mainMock.getAutostart).toHaveBeenCalledTimes(1); // not 2
  });
});

function pressOn(el: Element, key: string) {
  el.dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true, cancelable: true }));
}

describe("settings dropdowns", () => {
  it("trigger click opens the menu, sets aria-expanded, focuses the selected option", async () => {
    await setup();
    const btn = document.getElementById("select-theme")!;
    const menu = document.getElementById("menu-theme")!;
    btn.click();
    expect(menu.classList.contains("open")).toBe(true);
    expect(btn.getAttribute("aria-expanded")).toBe("true");
    expect(document.activeElement).toBe(menu.querySelector('[data-value="dark"]'));
  });

  it("ArrowDown on the closed trigger opens and focuses the selected option", async () => {
    await setup();
    const btn = document.getElementById("select-theme")!;
    const menu = document.getElementById("menu-theme")!;
    pressOn(btn, "ArrowDown");
    expect(menu.classList.contains("open")).toBe(true);
    expect(document.activeElement).toBe(menu.querySelector('[data-value="dark"]'));
  });

  it("arrows move focus between options; Escape closes and refocuses the trigger", async () => {
    await setup();
    const btn = document.getElementById("select-theme")!;
    const menu = document.getElementById("menu-theme")!;
    btn.click();
    pressOn(document.activeElement!, "ArrowDown");
    expect(document.activeElement).toBe(menu.querySelector('[data-value="system"]'));
    pressOn(document.activeElement!, "ArrowUp");
    pressOn(document.activeElement!, "ArrowUp");
    expect(document.activeElement).toBe(menu.querySelector('[data-value="light"]'));
    pressOn(document.activeElement!, "Escape");
    expect(menu.classList.contains("open")).toBe(false);
    expect(btn.getAttribute("aria-expanded")).toBe("false");
    expect(document.activeElement).toBe(btn);
  });

  it("option click selects: classes, aria-selected, button text, config, focus return", async () => {
    await setup();
    const btn = document.getElementById("select-theme")!;
    const menu = document.getElementById("menu-theme")!;
    btn.click();
    (menu.querySelector('[data-value="light"]') as HTMLElement).click();
    expect(mainMock.config!.theme).toBe("light");
    expect(document.documentElement.dataset.theme).toBe("light"); // applyTheme onChange ran
    expect(btn.textContent).toBe("Light");
    expect(menu.classList.contains("open")).toBe(false);
    expect(btn.getAttribute("aria-expanded")).toBe("false");
    const light = menu.querySelector('[data-value="light"]')!;
    const dark = menu.querySelector('[data-value="dark"]')!;
    expect(light.classList.contains("selected")).toBe(true);
    expect(light.getAttribute("aria-selected")).toBe("true");
    expect(dark.getAttribute("aria-selected")).toBe("false");
    expect(document.activeElement).toBe(btn);
    expect(mainMock.saveConfig).toHaveBeenCalled();
  });

  it("DNS protocol dropdown goes through the same path and patches config.dns", async () => {
    await setup();
    const btn = document.getElementById("select-dns-protocol")!;
    const menu = document.getElementById("menu-dns-protocol")!;
    btn.click();
    expect(document.activeElement).toBe(menu.querySelector('[data-value="https"]'));
    (menu.querySelector('[data-value="plain-udp"]') as HTMLElement).click();
    expect((mainMock.config!.dns as { protocol: string }).protocol).toBe("plain_udp");
    expect(btn.textContent).toBe("Plain UDP");
    expect(btn.getAttribute("aria-expanded")).toBe("false");
  });

  it("opening one menu closes others and resets their trigger's aria-expanded", async () => {
    await setup();
    const themeBtn = document.getElementById("select-theme")!;
    const themeMenu = document.getElementById("menu-theme")!;
    const startBtn = document.getElementById("select-on-startup")!;
    themeBtn.click();
    startBtn.click();
    expect(themeMenu.classList.contains("open")).toBe(false);
    expect(themeBtn.getAttribute("aria-expanded")).toBe("false");
    expect(document.getElementById("menu-on-startup")!.classList.contains("open")).toBe(true);
  });

  it("outside click closes menus without stealing focus", async () => {
    await setup();
    const btn = document.getElementById("select-theme")!;
    const menu = document.getElementById("menu-theme")!;
    btn.click();
    document.body.click();
    expect(menu.classList.contains("open")).toBe(false);
    expect(btn.getAttribute("aria-expanded")).toBe("false");
    expect(document.activeElement).not.toBe(btn);
  });

  it("renderSettings syncs aria-selected from config", async () => {
    mainMock.config!.theme = "system";
    await setup();
    const menu = document.getElementById("menu-theme")!;
    expect(menu.querySelector('[data-value="system"]')!.getAttribute("aria-selected")).toBe("true");
    expect(menu.querySelector('[data-value="dark"]')!.getAttribute("aria-selected")).toBe("false");
    expect(document.getElementById("select-theme")!.textContent).toBe("System");
  });
});

// Merged from main's settings.test.ts (#482) — port validation and
// null-config guards, adapted to this file's fixture and mock names.

function changePort(id: string, value: string) {
  const input = document.getElementById(id) as HTMLInputElement;
  input.value = value;
  input.dispatchEvent(new Event("change"));
}

describe("port input validation", () => {
  it("rejects trailing garbage and reverts the field", async () => {
    const { initSettings } = await import("./settings");
    initSettings();
    changePort("input-port", "8080abc");
    expect(mainMock.config!.local_port).toBe(4073);
    expect((document.getElementById("input-port") as HTMLInputElement).value).toBe("4073");
    expect(mainMock.saveConfig).not.toHaveBeenCalled();
  });

  it("normalizes accepted input back into the field", async () => {
    const { initSettings } = await import("./settings");
    initSettings();
    changePort("input-port", "0080");
    expect(mainMock.config!.local_port).toBe(80);
    expect((document.getElementById("input-port") as HTMLInputElement).value).toBe("80");
  });

  it("rejects trailing garbage on the HTTP port and reverts", async () => {
    const { initSettings } = await import("./settings");
    initSettings();
    changePort("input-port-http", "9090xy");
    expect(mainMock.config!.local_port_http).toBe(4074);
    expect((document.getElementById("input-port-http") as HTMLInputElement).value).toBe("4074");
    expect(mainMock.saveConfig).not.toHaveBeenCalled();
  });
});

describe("DNS controls with no config loaded", () => {
  it("dns-enabled toggle does not flip its visual state when config is null", async () => {
    mainMock.config = null;
    const { initSettings } = await import("./settings");
    initSettings();
    const el = document.getElementById("toggle-dns-enabled")!;
    el.click();
    expect(el.classList.contains("on")).toBe(false);
    expect(el.getAttribute("aria-checked")).toBe("false");
  });

  it("dns protocol option does not flip selection when config is null", async () => {
    mainMock.config = null;
    const { initSettings } = await import("./settings");
    initSettings();
    const opt = document.querySelector<HTMLElement>("#menu-dns-protocol .custom-select-opt")!;
    opt.click();
    expect(opt.classList.contains("selected")).toBe(false);
  });
});

describe("DNS resolver provider dropdown + custom-IP entry + insecure toggle", () => {
  it("a known provider IP set selects that provider and hides the custom row", async () => {
    mainMock.config = freshConfig();
    mainMock.config!.dns = {
      enabled: true,
      servers: ["8.8.8.8", "8.8.4.4"],
      protocol: "https",
      allow_insecure_bootstrap: false,
    };
    await setup();
    expect(document.getElementById("select-dns-provider")!.textContent).toBe("Google");
    expect((document.getElementById("row-dns-custom") as HTMLElement).hidden).toBe(true);
  });

  it("an unrecognized IP set selects Custom and reveals the typed IPs", async () => {
    mainMock.config = freshConfig();
    mainMock.config!.dns = {
      enabled: true,
      servers: ["203.0.113.7"],
      protocol: "https",
      allow_insecure_bootstrap: false,
    };
    await setup();
    expect(document.getElementById("select-dns-provider")!.textContent).toBe("Custom…");
    expect((document.getElementById("row-dns-custom") as HTMLElement).hidden).toBe(false);
    expect((document.getElementById("input-dns-servers") as HTMLInputElement).value).toBe("203.0.113.7");
  });

  it("picking a provider sets dns.servers to its preset and saves", async () => {
    await setup();
    const opt = document.querySelector('#menu-dns-provider [data-value="quad9"]') as HTMLElement;
    opt.click();
    expect((mainMock.config!.dns as { servers: string[] }).servers).toEqual(["9.9.9.9", "149.112.112.112"]);
    expect((document.getElementById("row-dns-custom") as HTMLElement).hidden).toBe(true);
    expect(mainMock.saveConfig).toHaveBeenCalled();
  });

  it("picking Custom reveals the input without clobbering servers", async () => {
    await setup();
    const opt = document.querySelector('#menu-dns-provider [data-value="custom"]') as HTMLElement;
    opt.click();
    expect((document.getElementById("row-dns-custom") as HTMLElement).hidden).toBe(false);
    expect((mainMock.config!.dns as { servers: string[] }).servers).toEqual(["1.1.1.1"]);
  });

  it("a valid custom edit parses into dns.servers and saves", async () => {
    await setup();
    (document.querySelector('#menu-dns-provider [data-value="custom"]') as HTMLElement).click();
    changePort("input-dns-servers", "9.9.9.9 , 1.1.1.1");
    expect((mainMock.config!.dns as { servers: string[] }).servers).toEqual(["9.9.9.9", "1.1.1.1"]);
    expect((document.getElementById("input-dns-servers") as HTMLInputElement).value).toBe("9.9.9.9, 1.1.1.1");
    expect(mainMock.saveConfig).toHaveBeenCalled();
  });

  it("an empty custom list is rejected and the field reverts", async () => {
    mainMock.config = freshConfig();
    mainMock.config!.dns = {
      enabled: true,
      servers: ["203.0.113.7"],
      protocol: "https",
      allow_insecure_bootstrap: false,
    };
    await setup();
    changePort("input-dns-servers", "   ");
    expect((mainMock.config!.dns as { servers: string[] }).servers).toEqual(["203.0.113.7"]);
    expect((document.getElementById("input-dns-servers") as HTMLInputElement).value).toBe("203.0.113.7");
    expect(mainMock.saveConfig).not.toHaveBeenCalled();
  });

  it("a malformed custom IP is rejected and the field reverts", async () => {
    mainMock.config = freshConfig();
    mainMock.config!.dns = {
      enabled: true,
      servers: ["203.0.113.7"],
      protocol: "https",
      allow_insecure_bootstrap: false,
    };
    await setup();
    changePort("input-dns-servers", "1.1.1.1, not-an-ip");
    expect((mainMock.config!.dns as { servers: string[] }).servers).toEqual(["203.0.113.7"]);
    expect(mainMock.saveConfig).not.toHaveBeenCalled();
  });

  it("renders the insecure toggle from config and patches dns on click", async () => {
    await setup();
    const tog = document.getElementById("toggle-dns-insecure")!;
    expect(tog.getAttribute("aria-checked")).toBe("false");
    tog.click();
    expect((mainMock.config!.dns as { allow_insecure_bootstrap: boolean }).allow_insecure_bootstrap).toBe(true);
    expect(tog.getAttribute("aria-checked")).toBe("true");
    expect(mainMock.saveConfig).toHaveBeenCalled();
  });

  it("insecure toggle does not flip when config is null", async () => {
    mainMock.config = null;
    const { initSettings } = await import("./settings");
    initSettings();
    const tog = document.getElementById("toggle-dns-insecure")!;
    tog.click();
    expect(tog.classList.contains("on")).toBe(false);
  });
});
