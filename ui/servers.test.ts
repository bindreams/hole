import { beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.fn();
const showToastMock = vi.fn();
let mockConfig: Record<string, unknown> | null;

vi.mock("@tauri-apps/api/core", () => ({ invoke: (...args: unknown[]) => invokeMock(...args) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ message: vi.fn(), open: vi.fn() }));
vi.mock("./toast", () => ({ showToast: (...args: unknown[]) => showToastMock(...args) }));
vi.mock("./sidebar", () => ({ updateDiagnostics: vi.fn() }));
vi.mock("./main", () => ({
  get config() {
    return mockConfig;
  },
  loadConfig: vi.fn().mockResolvedValue(undefined),
  saveConfig: vi.fn().mockResolvedValue(undefined),
  runTestsBounded: vi.fn(),
  TEST_CONCURRENCY: 5,
}));

beforeEach(() => {
  invokeMock.mockReset();
  showToastMock.mockReset();
  mockConfig = {
    servers: [{ id: "srv-1", name: "S1", server: "1.2.3.4", server_port: 443, validation: null }],
    selected_server: "srv-1",
  };
  document.body.innerHTML = `<div id="server-list"></div><div id="import-zone"></div>`;
  vi.resetModules();
});

describe("server test failure handling", () => {
  it("resets the dot and toasts when test_server rejects", async () => {
    let rejectTest!: (reason: unknown) => void;
    invokeMock.mockReturnValueOnce(
      new Promise((_, reject) => {
        rejectTest = reject;
      }),
    );
    const { renderServers } = await import("./servers");
    renderServers();

    const btn = document.querySelector<HTMLButtonElement>(".srv-test")!;
    btn.click();
    await Promise.resolve();
    // In flight: dot pulses, button disabled.
    expect(document.querySelector(".srv-status")!.className).toContain("testing");
    expect(btn.disabled).toBe(true);

    rejectTest("bridge unreachable");
    await Promise.resolve();
    await Promise.resolve();

    // Dot restored from persisted state (null validation -> untested), error surfaced.
    expect(document.querySelector(".srv-status")!.className).toContain("untested");
    expect(document.querySelector(".srv-status")!.className).not.toContain("testing");
    expect(document.querySelector<HTMLButtonElement>(".srv-test")!.disabled).toBe(false);
    expect(showToastMock).toHaveBeenCalledWith(expect.stringContaining("bridge unreachable"), "error");
  });

  it("a test settling after config lost its servers list does not throw", async () => {
    let rejectTest!: (reason: unknown) => void;
    invokeMock.mockReturnValueOnce(
      new Promise((_, reject) => {
        rejectTest = reject;
      }),
    );
    const { renderServers } = await import("./servers");
    renderServers();
    document.querySelector<HTMLButtonElement>(".srv-test")!.click();
    await Promise.resolve();

    // Config reloaded without a servers key while the card is still live.
    mockConfig = {};
    rejectTest("bridge unreachable");
    await Promise.resolve();
    await Promise.resolve();

    // The finally repaint falls back to "untested" instead of throwing.
    expect(document.querySelector(".srv-status")!.className).toContain("untested");
    expect(showToastMock).toHaveBeenCalledWith(expect.stringContaining("bridge unreachable"), "error");
  });

  it("a test settling after its server was removed is a no-op repaint", async () => {
    let rejectTest!: (reason: unknown) => void;
    invokeMock.mockReturnValueOnce(
      new Promise((_, reject) => {
        rejectTest = reject;
      }),
    );
    const { renderServers } = await import("./servers");
    renderServers();
    document.querySelector<HTMLButtonElement>(".srv-test")!.click();
    await Promise.resolve();

    // Server deleted + re-render while the test is in flight.
    (mockConfig as { servers: unknown[] }).servers = [];
    renderServers();

    rejectTest("bridge unreachable");
    await Promise.resolve();
    await Promise.resolve();

    // No card to repaint — must not throw; the error still surfaces.
    expect(showToastMock).toHaveBeenCalledWith(expect.stringContaining("bridge unreachable"), "error");
  });

  it("re-render during an in-flight test repaints the testing state", async () => {
    invokeMock.mockReturnValueOnce(new Promise(() => {}));
    const { renderServers } = await import("./servers");
    renderServers();
    document.querySelector<HTMLButtonElement>(".srv-test")!.click();
    await Promise.resolve();

    renderServers(); // e.g. another server's validation-changed landed

    expect(document.querySelector(".srv-status")!.className).toContain("testing");
    expect(document.querySelector<HTMLButtonElement>(".srv-test")!.disabled).toBe(true);
  });
});
