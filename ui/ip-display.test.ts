import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...args: unknown[]) => invokeMock(...args) }));

beforeEach(() => {
  invokeMock.mockReset();
  document.body.innerHTML = `
    <span id="ip-text"><span class="country-flag fi fis fi-xx" id="country-flag" title="Unknown"></span></span>
    <button id="copy-ip-btn"></button>
  `;
  vi.resetModules();
});

afterEach(() => {
  // jsdom adds a clipboard mock to navigator that persists across tests.
  delete (navigator as { clipboard?: unknown }).clipboard;
});

describe("updatePublicIp", () => {
  it("paints the country flag + IP text from invoke result", async () => {
    invokeMock.mockResolvedValue({ ip: "1.2.3.4", country_code: "DE" });
    const { initIpDisplay, updatePublicIp } = await import("./ip-display");
    initIpDisplay();
    await updatePublicIp();
    const flag = document.getElementById("country-flag")!;
    expect(flag.classList.contains("fi-de")).toBe(true);
    expect(flag.title).toBe("DE");
    expect(document.getElementById("ip-text")!.textContent).toContain("1.2.3.4");
  });

  it("falls back to placeholder flag + 'unknown' on empty fields", async () => {
    invokeMock.mockResolvedValue({ ip: "", country_code: "" });
    const { initIpDisplay, updatePublicIp } = await import("./ip-display");
    initIpDisplay();
    await updatePublicIp();
    const flag = document.getElementById("country-flag")!;
    expect(flag.classList.contains("fi-xx")).toBe(true);
    expect(flag.title).toBe("Unknown");
    expect(document.getElementById("ip-text")!.textContent).toContain("unknown");
  });
});

describe("copy button", () => {
  it("writes the cached IP to the clipboard on click", async () => {
    invokeMock.mockResolvedValue({ ip: "1.2.3.4", country_code: "DE" });
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    const { initIpDisplay, updatePublicIp } = await import("./ip-display");
    initIpDisplay();
    await updatePublicIp();
    document.getElementById("copy-ip-btn")!.click();
    expect(writeText).toHaveBeenCalledWith("1.2.3.4");
  });
});
