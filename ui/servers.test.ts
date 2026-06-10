import { beforeEach, describe, expect, it, vi } from "vitest";

const mainMock: {
  config: Record<string, unknown> | null;
  saveConfig: ReturnType<typeof vi.fn<(...args: unknown[]) => Promise<void>>>;
} = {
  config: null,
  saveConfig: vi.fn().mockResolvedValue(undefined),
};
const updateDiagnostics = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ message: vi.fn(), open: vi.fn() }));
vi.mock("./main", () => ({
  get config() {
    return mainMock.config;
  },
  saveConfig: (...args: unknown[]) => mainMock.saveConfig(...args),
  loadConfig: vi.fn(),
  runTestsBounded: vi.fn(),
  TEST_CONCURRENCY: 3,
}));
vi.mock("./sidebar", () => ({ updateDiagnostics: (...args: unknown[]) => updateDiagnostics(...args) }));
vi.mock("./toast", () => ({ showToast: vi.fn() }));

function server(id: string, name: string) {
  return { id, name, server: `${id}.example.com`, server_port: 8388, validation: null };
}

beforeEach(() => {
  mainMock.saveConfig.mockClear();
  updateDiagnostics.mockClear();
  mainMock.config = {
    servers: [server("a", "Alpha"), server("b", "Beta"), server("c", "Gamma")],
    selected_server: "a",
  };
  document.body.innerHTML = `
    <div class="server-list" id="server-list"></div>
    <button type="button" class="add-zone" id="import-zone">+ Import servers from file</button>
  `;
  vi.resetModules();
});

describe("server delete control", () => {
  it("is a button with an accessible name", async () => {
    const { renderServers } = await import("./servers");
    renderServers();
    const dels = document.querySelectorAll(".srv-del");
    expect(dels).toHaveLength(3);
    expect(dels[0].tagName).toBe("BUTTON");
    expect((dels[0] as HTMLButtonElement).type).toBe("button");
    expect(dels[0].getAttribute("aria-label")).toBe("Delete Alpha");
  });

  it("sits after the Test button in the card's tab order", async () => {
    const { renderServers } = await import("./servers");
    renderServers();
    const card = document.querySelector(".srv")!;
    const test = card.querySelector(".srv-test")!;
    const del = card.querySelector(".srv-del")!;
    // DOM order is tab order (no positive tabindex anywhere).
    expect(test.compareDocumentPosition(del) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("deletes without triggering card selection", async () => {
    const { renderServers } = await import("./servers");
    renderServers();
    const dels = document.querySelectorAll<HTMLElement>(".srv-del");
    dels[1].click(); // delete Beta (not selected)
    expect((mainMock.config!.servers as { id: string }[]).map((s) => s.id)).toEqual(["a", "c"]);
    expect(mainMock.config!.selected_server).toBe("a");
    // selectServer calls updateDiagnostics; deletion must not.
    expect(updateDiagnostics).not.toHaveBeenCalled();
  });

  it("moves focus to the delete button at the same position after deletion", async () => {
    const { renderServers } = await import("./servers");
    renderServers();
    const dels = document.querySelectorAll<HTMLElement>(".srv-del");
    dels[0].focus();
    dels[0].click();
    const after = document.querySelectorAll<HTMLElement>(".srv-del");
    expect(after).toHaveLength(2);
    expect(document.activeElement).toBe(after[0]);
    expect(after[0].getAttribute("aria-label")).toBe("Delete Beta");
  });

  it("falls back to the import zone when the last server is deleted", async () => {
    mainMock.config!.servers = [server("a", "Alpha")];
    const { renderServers } = await import("./servers");
    renderServers();
    const del = document.querySelector<HTMLElement>(".srv-del")!;
    del.focus();
    del.click();
    expect(document.activeElement).toBe(document.getElementById("import-zone"));
  });

  it("does not steal focus when deletion happens with focus elsewhere", async () => {
    const { renderServers } = await import("./servers");
    renderServers();
    const outside = document.getElementById("import-zone")!;
    outside.focus();
    document.querySelectorAll<HTMLElement>(".srv-del")[1].click();
    expect(document.activeElement).toBe(outside);
  });
});
