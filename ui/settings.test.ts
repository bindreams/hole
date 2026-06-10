import { beforeEach, describe, expect, it, vi } from "vitest";

const saveConfigMock = vi.fn();
let mockConfig: Record<string, unknown> | null;

vi.mock("./main", () => ({
  get config() {
    return mockConfig;
  },
  saveConfig: (...args: unknown[]) => saveConfigMock(...args),
}));

function scaffold() {
  document.body.innerHTML = `
    <div id="toggle-start-on-login" class="toggle"></div>
    <div id="toggle-proxy-server" class="toggle"></div>
    <div id="proxy-nested">
      <div id="toggle-socks5" class="toggle"></div>
      <div id="toggle-http" class="toggle"></div>
      <input id="input-port" type="text" value="4073">
      <div class="setting-row" id="row-port-http" hidden>
        <input id="input-port-http" type="text" value="4074">
      </div>
    </div>
    <div class="custom-select-btn" id="select-on-startup"></div>
    <div class="custom-select-menu" id="menu-on-startup"><div class="custom-select-opt" data-value="do-not-connect"></div></div>
    <div class="custom-select-btn" id="select-theme"></div>
    <div class="custom-select-menu" id="menu-theme"><div class="custom-select-opt" data-value="dark"></div></div>
    <div id="toggle-dns-enabled" class="toggle"></div>
    <div id="dns-nested">
      <div class="custom-select-btn" id="select-dns-protocol"></div>
      <div class="custom-select-menu" id="menu-dns-protocol"><div class="custom-select-opt" data-value="https"></div></div>
      <div id="toggle-dns-intercept" class="toggle"></div>
    </div>`;
}

beforeEach(() => {
  saveConfigMock.mockReset();
  saveConfigMock.mockResolvedValue(undefined);
  mockConfig = { local_port: 4073, local_port_http: 4074, proxy_socks5: true, proxy_http: false };
  // settings.ts calls window.matchMedia at module load; provide it if the
  // jsdom build lacks one (the real implementation wins when present).
  if (typeof window.matchMedia !== "function") {
    Object.assign(window, {
      matchMedia: () => ({
        matches: false,
        addEventListener: () => {},
        removeEventListener: () => {},
      }),
    });
  }
  scaffold();
  vi.resetModules();
});

function changePort(value: string) {
  const input = document.getElementById("input-port") as HTMLInputElement;
  input.value = value;
  input.dispatchEvent(new Event("change"));
}

describe("port input validation", () => {
  it("rejects trailing garbage and reverts the field", async () => {
    const { initSettings } = await import("./settings");
    initSettings();
    changePort("8080abc");
    expect(mockConfig!.local_port).toBe(4073);
    expect((document.getElementById("input-port") as HTMLInputElement).value).toBe("4073");
    expect(saveConfigMock).not.toHaveBeenCalled();
  });

  it("normalizes accepted input back into the field", async () => {
    const { initSettings } = await import("./settings");
    initSettings();
    changePort("0080");
    expect(mockConfig!.local_port).toBe(80);
    expect((document.getElementById("input-port") as HTMLInputElement).value).toBe("80");
  });

  it("rejects trailing garbage on the HTTP port and reverts", async () => {
    const { initSettings } = await import("./settings");
    initSettings();
    const input = document.getElementById("input-port-http") as HTMLInputElement;
    input.value = "9090xy";
    input.dispatchEvent(new Event("change"));
    expect(mockConfig!.local_port_http).toBe(4074);
    expect(input.value).toBe("4074");
    expect(saveConfigMock).not.toHaveBeenCalled();
  });
});

describe("DNS controls with no config loaded", () => {
  it("dns-enabled toggle does not flip its visual state when config is null", async () => {
    mockConfig = null;
    const { initSettings } = await import("./settings");
    initSettings();
    const el = document.getElementById("toggle-dns-enabled")!;
    el.click();
    expect(el.classList.contains("on")).toBe(false);
  });

  it("dns-intercept toggle does not flip its visual state when config is null", async () => {
    mockConfig = null;
    const { initSettings } = await import("./settings");
    initSettings();
    const el = document.getElementById("toggle-dns-intercept")!;
    el.click();
    expect(el.classList.contains("on")).toBe(false);
  });

  it("dns protocol option does not flip selection when config is null", async () => {
    mockConfig = null;
    const { initSettings } = await import("./settings");
    initSettings();
    const opt = document.querySelector<HTMLElement>("#menu-dns-protocol .custom-select-opt")!;
    opt.click();
    expect(opt.classList.contains("selected")).toBe(false);
  });
});
