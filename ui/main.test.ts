import { beforeEach, describe, expect, it, vi } from "vitest";
import * as filters from "./filters";
import * as servers from "./servers";
import * as sidebar from "./sidebar";
import * as toast from "./toast";

/// Records the interleaving of listen() registrations and invoke() calls
/// so the test can assert listeners are registered before the first
/// config fetch (the point where the UI becomes interactive).
const callOrder: string[] = [];
const defaultInvokeImpl = (cmd: string, _args?: unknown): Promise<unknown> => {
  callOrder.push(`invoke:${cmd}`);
  if (cmd === "get_config") return Promise.resolve({ servers: [], filters: [] });
  if (cmd === "get_proxy_status")
    return Promise.resolve({
      running: false,
      state_seq: 0,
      uptime_secs: 0,
      error: null,
      invalid_filters: [],
      udp_proxy_available: null,
      ipv6_bypass_available: null,
    });
  if (cmd === "get_metrics")
    return Promise.resolve({ bytes_in: 0, bytes_out: 0, speed_in_bps: 0, speed_out_bps: 0, uptime_secs: 0 });
  if (cmd === "get_diagnostics") return Promise.resolve({});
  return Promise.resolve(null);
};
const invokeMock = vi.fn(defaultInvokeImpl);
const defaultListenImpl = (event: string, _handler?: unknown) => {
  callOrder.push(`listen:${event}`);
  return Promise.resolve(() => {});
};
const listenMock = vi.fn(defaultListenImpl);

/// A promise plus its resolver, so a test can await the exact event it cares
/// about (a specific invoke landing) instead of a fixed number of microtask
/// turns, which would silently start passing vacuously if the code under
/// test grew one more `await`.
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

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
vi.mock("./filters", () => ({
  initFilters: vi.fn(),
  renderFilters: vi.fn(),
  setInvalidFilters: vi.fn(),
  filtersEpoch: vi.fn().mockReturnValue(0),
}));
// `./import-summary` is deliberately NOT mocked: it is pure, and the toast
// copy it produces is what the import tests below assert on.
vi.mock("./sections", () => ({ initSections: vi.fn() }));
vi.mock("./servers", () => ({
  clearImportZoneHighlight: vi.fn(),
  importFromDialog: vi.fn(),
  initServers: vi.fn(),
  renderServers: vi.fn(),
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
  setCapabilityFlags: vi.fn(),
}));
vi.mock("./toast", () => ({ showToast: vi.fn() }));

beforeEach(() => {
  callOrder.length = 0;
  // Reset to the default implementation (a test may substitute its own)
  // and clear call logs so per-test assertions don't match a previous
  // test's invocations.
  invokeMock.mockReset();
  invokeMock.mockImplementation(defaultInvokeImpl);
  // Reset, not just clear: `mockClear` leaves a per-test `mockImplementation`
  // installed, so one test's stub would silently serve every later test.
  listenMock.mockReset();
  listenMock.mockImplementation(defaultListenImpl);
  // `vi.resetModules()` does not re-run a `vi.mock` factory, so a factory
  // mock's call history and implementation both outlive the test that set
  // them. `clearAllMocks` drops the history — without it an assertion as
  // loose as `toHaveBeenCalled()` can be satisfied by an earlier test — but
  // NOT the implementations, so every default a test may override is
  // re-installed below.
  vi.clearAllMocks();
  vi.mocked(toast.showToast).mockReturnValue(document.createElement("div"));
  vi.mocked(servers.importFromDialog).mockResolvedValue(undefined);
  vi.mocked(filters.filtersEpoch).mockReturnValue(0);
  vi.mocked(sidebar.applyProxyStateObservation).mockReturnValue({ state: "disconnected", changed: false });
  vi.mocked(sidebar.updateProxyStatus).mockReturnValue({ state: "disconnected", changed: false });
  vi.mocked(sidebar.updatePublicIp).mockResolvedValue(undefined);
  // init() starts real polling intervals; stub so they don't keep
  // firing in the worker after the test completes.
  vi.stubGlobal("setInterval", vi.fn());
  vi.resetModules();
});

/// Capture the handlers `setupEventListeners` registers, so a test can
/// deliver an event to the code under test the way Tauri would.
function captureListeners(): Record<string, (event: unknown) => Promise<void>> {
  const handlers: Record<string, (event: unknown) => Promise<void>> = {};
  listenMock.mockImplementation((event: string, handler?: unknown) => {
    callOrder.push(`listen:${event}`);
    handlers[event] = async (e: unknown) => {
      await (handler as (e: unknown) => unknown)(e);
    };
    return Promise.resolve(() => {});
  });
  return handlers;
}

describe("init ordering", () => {
  it("registers all event listeners before the first config fetch", async () => {
    const { initDone } = await import("./main");
    await initDone; // init's own promise — deterministic rendezvous, no polling

    const firstConfig = callOrder.indexOf("invoke:get_config");
    expect(firstConfig).toBeGreaterThan(-1);
    for (const ev of ["servers-imported", "tauri://drag-drop", "validation-changed", "proxy-state-changed"]) {
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
          proxy_server_enabled: true,
          proxy_socks5: true,
          proxy_http: false,
          on_startup: "restore_last_state",
          theme: "dark",
          dns: { enabled: true, servers: ["1.1.1.1"], protocol: "https", allow_insecure_bootstrap: false },
          diagnostic_plugin_tap: false,
          // Backend-owned fields present in the snapshot — must NOT round-trip.
          enabled: true,
          elevation_prompt_shown: true,
        });
      if (cmd === "get_proxy_status")
        return Promise.resolve({
          running: false,
          state_seq: 0,
          uptime_secs: 0,
          error: null,
          invalid_filters: [],
          udp_proxy_available: null,
          ipv6_bypass_available: null,
        });
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

    // init reported the failure through the ui-ready handshake…
    await expect(initDone).resolves.toMatchObject({ ok: false });
    // …and never proceeded to the config fetch.
    expect(callOrder).not.toContain("invoke:get_config");
  });

  it("refreshes, summarizes and auto-tests when the backend reports an import", async () => {
    // The backend has already done the import; this listener is the
    // dashboard catching up with it.
    const handlers = captureListeners();
    const { initDone } = await import("./main");
    await initDone;
    const configsBefore = callOrder.filter((c) => c === "invoke:get_config").length;

    await handlers["servers-imported"]({
      payload: { appended: [{ id: "a" }, { id: "b" }], failed: 0 },
    });

    expect(callOrder.filter((c) => c === "invoke:get_config").length).toBe(configsBefore + 1);
    expect(toast.showToast).toHaveBeenCalledWith(expect.stringContaining("2 server(s)"), "success");
    // Both new servers get auto-tested, by id.
    const tested = invokeMock.mock.calls.filter(([cmd]) => cmd === "test_server").map(([, args]) => args);
    expect(tested).toEqual([{ entryId: "a" }, { entryId: "b" }]);
  });

  it("does not toast when every dropped file failed", async () => {
    // The user already acknowledged a blocking dialog per failure, so a
    // toast on top would be noise. The refresh still happens: a file that
    // failed late can have left persisted changes behind it.
    const handlers = captureListeners();
    const { initDone } = await import("./main");
    await initDone;

    await handlers["servers-imported"]({ payload: { appended: [], failed: 2 } });

    expect(toast.showToast).not.toHaveBeenCalled();
  });

  it("refreshes even when an import appended nothing", async () => {
    // An all-duplicate import appends nothing but still heals and persists
    // the selected server, which is why the backend announces it at all.
    const handlers = captureListeners();
    const { initDone } = await import("./main");
    await initDone;
    const configsBefore = callOrder.filter((c) => c === "invoke:get_config").length;

    await handlers["servers-imported"]({ payload: { appended: [], failed: 0 } });

    expect(callOrder.filter((c) => c === "invoke:get_config").length).toBe(configsBefore + 1);
    // …and says so, rather than leaving the click looking ignored.
    expect(toast.showToast).toHaveBeenCalledWith(expect.stringContaining("No new servers"), "info");
  });

  it("names the failure count when an import only partly succeeded", async () => {
    const handlers = captureListeners();
    const { initDone } = await import("./main");
    await initDone;

    await handlers["servers-imported"]({ payload: { appended: [{ id: "a" }], failed: 1 } });

    // The toast must not read as a clean run.
    expect(toast.showToast).toHaveBeenCalledWith(expect.stringContaining("1 file(s) failed"), "success");
  });

  it("hands dropped paths to the backend instead of importing them here", async () => {
    // One import pipeline: the drop path must not parse or dialog on its
    // own, or its failures would be reported differently from the picker's.
    const handlers = captureListeners();
    const { initDone } = await import("./main");
    await initDone;

    await handlers["tauri://drag-drop"]({ payload: { paths: ["/a.json", "/b.json"] } });

    expect(invokeMock).toHaveBeenCalledWith("import_dropped_files", { paths: ["/a.json", "/b.json"] });
    expect(servers.clearImportZoneHighlight).toHaveBeenCalledTimes(1);
  });

  it("ignores an empty drop", async () => {
    const handlers = captureListeners();
    const { initDone } = await import("./main");
    await initDone;

    await handlers["tauri://drag-drop"]({ payload: { paths: [] } });

    expect(invokeMock).not.toHaveBeenCalledWith("import_dropped_files", expect.anything());
  });

  it("surfaces a drop that the backend could not accept", async () => {
    // The invoke is fire-and-forget, so without this the rejection would
    // only reach the console relay.
    const handlers = captureListeners();
    const toasted = deferred();
    invokeMock.mockImplementation((cmd: string, args?: unknown) => {
      if (cmd === "import_dropped_files") return Promise.reject(new Error("ipc gone"));
      return defaultInvokeImpl(cmd, args);
    });
    vi.mocked(toast.showToast).mockImplementationOnce(() => {
      toasted.resolve();
      return document.createElement("div");
    });
    const { initDone } = await import("./main");
    await initDone;

    await handlers["tauri://drag-drop"]({ payload: { paths: ["/a.json"] } });
    // Wait on the toast itself, not on a guessed number of microtask turns.
    await toasted.promise;

    expect(toast.showToast).toHaveBeenCalledWith(expect.stringContaining("ipc gone"), "error");
  });

  it("publishes the ui-ready bridge on the document that ran init", async () => {
    const { initDone } = await import("./main");

    // The webdriver readiness gate's only entry point. It must resolve off
    // THIS document's init, so a reload cannot serve a stale result.
    expect(typeof window.__holeUiReady).toBe("function");
    await expect(window.__holeUiReady!()).resolves.toEqual(await initDone);
  });
});
