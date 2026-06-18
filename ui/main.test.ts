import { beforeEach, describe, expect, it, vi } from "vitest";

/// Records the interleaving of listen() registrations and invoke() calls
/// so the test can assert listeners are registered before the first
/// config fetch (the point where the UI becomes interactive).
const callOrder: string[] = [];
const defaultInvokeImpl = (cmd: string, _args?: unknown) => {
  callOrder.push(`invoke:${cmd}`);
  if (cmd === "get_config") return Promise.resolve({ servers: [], filters: [] });
  if (cmd === "get_proxy_status") return Promise.resolve({ running: false, state_seq: 0 });
  if (cmd === "get_metrics")
    return Promise.resolve({ bytes_in: 0, bytes_out: 0, speed_in_bps: 0, speed_out_bps: 0, uptime_secs: 0 });
  if (cmd === "get_diagnostics") return Promise.resolve({});
  return Promise.resolve(null);
};
const invokeMock = vi.fn(defaultInvokeImpl);
const listenMock = vi.fn((event: string, _handler?: unknown) => {
  callOrder.push(`listen:${event}`);
  return Promise.resolve(() => {});
});

vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a: [string, unknown?]) => invokeMock(...a) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: (...a: [string, unknown]) => listenMock(...a) }));
vi.mock("@tauri-apps/plugin-log", () => ({
  attachConsole: vi.fn().mockResolvedValue(undefined),
  error: vi.fn().mockResolvedValue(undefined),
  warn: vi.fn().mockResolvedValue(undefined),
}));
vi.mock("overlayscrollbars", () => ({ OverlayScrollbars: vi.fn() }));
vi.mock("flag-icons/css/flag-icons.min.css", () => ({}));
vi.mock("overlayscrollbars/overlayscrollbars.css", () => ({}));
vi.mock("./filters", () => ({ initFilters: vi.fn(), renderFilters: vi.fn() }));
vi.mock("./import-summary", () => ({ postImportSummary: vi.fn().mockReturnValue(null) }));
vi.mock("./sections", () => ({ initSections: vi.fn() }));
vi.mock("./servers", () => ({
  clearImportZoneHighlight: vi.fn(),
  importFromDialog: vi.fn(),
  initServers: vi.fn(),
  renderServers: vi.fn(),
  showImportFailureDialog: vi.fn(),
}));
vi.mock("./settings", () => ({ initSettings: vi.fn(), renderSettings: vi.fn() }));
vi.mock("./sidebar", () => ({
  applyProxyStateObservation: vi.fn().mockReturnValue({ state: "disconnected", changed: false }),
  initSidebar: vi.fn(),
  updateDiagnostics: vi.fn(),
  updateMetrics: vi.fn(),
  updateProxyStatus: vi.fn().mockReturnValue({ state: "disconnected", changed: false }),
  updatePublicIp: vi.fn().mockResolvedValue(undefined),
  startPublicIpAutoRefresh: vi.fn(),
}));
vi.mock("./toast", () => ({ showToast: vi.fn() }));

beforeEach(() => {
  callOrder.length = 0;
  // Reset to the default implementation (a test may substitute its own)
  // and clear call logs so per-test assertions don't match a previous
  // test's invocations.
  invokeMock.mockReset();
  invokeMock.mockImplementation(defaultInvokeImpl);
  listenMock.mockClear();
  // init() starts real polling intervals; stub so they don't keep
  // firing in the worker after the test completes.
  vi.stubGlobal("setInterval", vi.fn());
  vi.resetModules();
});

describe("init ordering", () => {
  it("registers all event listeners before the first config fetch", async () => {
    const { initDone } = await import("./main");
    await initDone; // init's own promise — deterministic rendezvous, no polling

    const firstConfig = callOrder.indexOf("invoke:get_config");
    expect(firstConfig).toBeGreaterThan(-1);
    for (const ev of ["import-requested", "tauri://drag-drop", "validation-changed", "proxy-state-changed"]) {
      const idx = callOrder.indexOf(`listen:${ev}`);
      expect(idx, `listener ${ev} must be registered before get_config`).toBeGreaterThan(-1);
      expect(idx).toBeLessThan(firstConfig);
    }
  });

  it("starts the visibility-gated public-IP refresh during init", async () => {
    const sidebar = await import("./sidebar");
    // The mock persists across tests; clear prior tests' init calls so the
    // count reflects this init only.
    vi.mocked(sidebar.startPublicIpAutoRefresh).mockClear();
    const { initDone } = await import("./main");
    await initDone;
    expect(sidebar.startPublicIpAutoRefresh).toHaveBeenCalledTimes(1);
  });

  it("sends only UI-owned keys and strips server validation on save", async () => {
    invokeMock.mockImplementation((cmd: string, _args?: unknown) => {
      callOrder.push(`invoke:${cmd}`);
      if (cmd === "get_config")
        return Promise.resolve({
          servers: [
            {
              id: "a",
              name: "A",
              server: "1.2.3.4",
              server_port: 8388,
              method: "aes-256-gcm",
              password: "pw",
              validation: { tested_at: "2026-01-01T00:00:00Z", outcome: { kind: "reachable", latency_ms: 5 } },
            },
          ],
          selected_server: "a",
          filters: [],
          local_port: 4073,
          local_port_http: 4074,
          start_on_login: false,
          proxy_server_enabled: true,
          proxy_socks5: true,
          proxy_http: false,
          on_startup: "restore_last_state",
          theme: "dark",
          dns: { enabled: true, servers: ["1.1.1.1"], protocol: "https" },
          diagnostic_plugin_tap: false,
          // Backend-owned fields present in the snapshot — must NOT round-trip.
          enabled: true,
          elevation_prompt_shown: true,
        });
      if (cmd === "get_proxy_status") return Promise.resolve({ running: false, state_seq: 0 });
      if (cmd === "get_metrics")
        return Promise.resolve({ bytes_in: 0, bytes_out: 0, speed_in_bps: 0, speed_out_bps: 0, uptime_secs: 0 });
      if (cmd === "get_diagnostics") return Promise.resolve({});
      return Promise.resolve(null);
    });
    const { initDone, saveConfig } = await import("./main");
    await initDone;
    await saveConfig();

    const call = invokeMock.mock.calls.find(([cmd]) => cmd === "save_config");
    expect(call).toBeDefined();
    const { settings } = call![1] as { settings: Record<string, unknown> };
    expect(Object.keys(settings).sort()).toEqual([
      "diagnostic_plugin_tap",
      "dns",
      "filters",
      "local_port",
      "local_port_http",
      "on_startup",
      "proxy_http",
      "proxy_server_enabled",
      "proxy_socks5",
      "selected_server",
      "servers",
      "start_on_login",
      "theme",
    ]);
    for (const s of settings.servers as Record<string, unknown>[]) {
      expect(s).not.toHaveProperty("validation");
    }
  });

  it("a listener registration failure fails init loudly", async () => {
    listenMock.mockImplementationOnce((event: string) => {
      callOrder.push(`listen:${event}`);
      return Promise.reject(new Error("capability missing"));
    });
    const { initDone } = await import("./main");
    await initDone;

    // init reported the failure through the ui-ready handshake…
    const signal = invokeMock.mock.calls.find(([cmd]) => cmd === "signal_ui_ready");
    expect(signal).toBeDefined();
    expect((signal![1] as { result: { ok: boolean } }).result.ok).toBe(false);
    // …and never proceeded to the config fetch.
    expect(callOrder).not.toContain("invoke:get_config");
  });
});
