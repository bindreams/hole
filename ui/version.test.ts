import { beforeEach, describe, expect, it, vi } from "vitest";

const getVersionMock = vi.fn<() => Promise<string>>();
vi.mock("@tauri-apps/api/app", () => ({ getVersion: () => getVersionMock() }));

beforeEach(() => {
  getVersionMock.mockReset();
  document.body.innerHTML = `<span id="version-footer"></span>`;
  vi.resetModules();
});

describe("initVersion", () => {
  it("paints `Hole v<version>` on success", async () => {
    getVersionMock.mockResolvedValue("1.2.3");
    const { initVersion } = await import("./version");
    await initVersion();
    expect(document.getElementById("version-footer")!.textContent).toBe("Hole v1.2.3");
  });

  it("falls back to `Hole` on getVersion rejection", async () => {
    getVersionMock.mockRejectedValue(new Error("ipc fail"));
    const { initVersion } = await import("./version");
    await initVersion();
    expect(document.getElementById("version-footer")!.textContent).toBe("Hole");
  });
});
