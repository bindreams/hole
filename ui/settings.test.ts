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
} = {
  config: null,
  saveConfig: vi.fn<(...args: unknown[]) => void>(),
};
vi.mock("./main", () => ({
  get config() {
    return mainMock.config;
  },
  saveConfig: (...args: unknown[]) => mainMock.saveConfig(...args),
}));

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
    <span class="setting-label" id="lbl-dns-intercept">Intercept UDP/53 to other servers</span>
    <button type="button" class="toggle" id="toggle-dns-intercept" role="switch" aria-checked="false" aria-labelledby="lbl-dns-intercept"></button>
  </div>
`;

function freshConfig(): Record<string, unknown> {
  return {
    start_on_login: false,
    proxy_server_enabled: true,
    proxy_socks5: true,
    proxy_http: false,
    local_port: 4073,
    local_port_http: 4074,
    on_startup: "do_not_connect",
    theme: "dark",
    dns: { enabled: true, servers: ["1.1.1.1"], protocol: "https", intercept_udp53: true },
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
  mainMock.config = freshConfig();
  document.body.innerHTML = SETTINGS_DOM;
  vi.resetModules();
});

describe("settings toggles", () => {
  it("renderSettings syncs .on and aria-checked from config", async () => {
    await setup();
    const proxy = document.getElementById("toggle-proxy-server")!;
    const login = document.getElementById("toggle-start-on-login")!;
    expect(proxy.classList.contains("on")).toBe(true);
    expect(proxy.getAttribute("aria-checked")).toBe("true");
    expect(login.classList.contains("on")).toBe(false);
    expect(login.getAttribute("aria-checked")).toBe("false");
  });

  it("click flips class, aria-checked, config, and saves", async () => {
    await setup();
    const login = document.getElementById("toggle-start-on-login")!;
    login.click();
    expect(login.classList.contains("on")).toBe(true);
    expect(login.getAttribute("aria-checked")).toBe("true");
    expect(mainMock.config!.start_on_login).toBe(true);
    expect(mainMock.saveConfig).toHaveBeenCalledTimes(1);
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

  it("DNS toggles patch config.dns and sync aria-checked", async () => {
    await setup();
    const enabled = document.getElementById("toggle-dns-enabled")!;
    expect(enabled.getAttribute("aria-checked")).toBe("true");
    enabled.click();
    expect((mainMock.config!.dns as { enabled: boolean }).enabled).toBe(false);
    expect(enabled.getAttribute("aria-checked")).toBe("false");
    expect(document.getElementById("dns-nested")!.classList.contains("muted")).toBe(true);

    const intercept = document.getElementById("toggle-dns-intercept")!;
    intercept.click();
    expect((mainMock.config!.dns as { intercept_udp53: boolean }).intercept_udp53).toBe(false);
    expect(intercept.getAttribute("aria-checked")).toBe("false");
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
