import { beforeEach, describe, expect, it, vi } from "vitest";

/// Records the interleaving of listen() registrations and invoke() calls
/// so the test can assert listeners are registered before the first
/// config fetch (the point where the UI becomes interactive).
const callOrder: string[] = [];
const invokeMock = vi.fn((cmd: string, _args?: unknown) => {
  callOrder.push(`invoke:${cmd}`);
  if (cmd === "get_config") return Promise.resolve({ servers: [], filters: [] });
  if (cmd === "get_proxy_status") return Promise.resolve({ running: false });
  if (cmd === "get_metrics")
    return Promise.resolve({ bytes_in: 0, bytes_out: 0, speed_in_bps: 0, speed_out_bps: 0, uptime_secs: 0 });
  if (cmd === "get_diagnostics") return Promise.resolve({});
  return Promise.resolve(null);
});
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
  initSidebar: vi.fn(),
  updateDiagnostics: vi.fn(),
  updateMetrics: vi.fn(),
  updateProxyStatus: vi.fn().mockReturnValue({ state: "disconnected", changed: false }),
  updatePublicIp: vi.fn().mockResolvedValue(undefined),
}));
vi.mock("./toast", () => ({ showToast: vi.fn() }));

beforeEach(() => {
  callOrder.length = 0;
  vi.resetModules();
});

describe("init ordering", () => {
  it("registers all event listeners before the first config fetch", async () => {
    const { initDone } = await import("./main");
    await initDone; // init's own promise — deterministic rendezvous, no polling

    const firstConfig = callOrder.indexOf("invoke:get_config");
    expect(firstConfig).toBeGreaterThan(-1);
    for (const ev of ["import-requested", "tauri://drag-drop", "validation-changed"]) {
      const idx = callOrder.indexOf(`listen:${ev}`);
      expect(idx, `listener ${ev} must be registered before get_config`).toBeGreaterThan(-1);
      expect(idx).toBeLessThan(firstConfig);
    }
  });
});
