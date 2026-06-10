import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.fn();
const showToastMock = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...args: unknown[]) => invokeMock(...args) }));
vi.mock("./toast", () => ({ showToast: (...args: unknown[]) => showToastMock(...args) }));

beforeEach(() => {
  invokeMock.mockReset();
  showToastMock.mockReset();
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

  it("does NOT write the literal 'unknown' fallback to the clipboard", async () => {
    // Footgun guard: when the IP fetch returns empty, the UI displays
    // "unknown" as human-readable text — but that text must never be
    // committed to `currentIp` as a value the user would paste. The
    // copy button should be a no-op in this case.
    invokeMock.mockResolvedValue({ ip: "", country_code: "" });
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    const { initIpDisplay, updatePublicIp } = await import("./ip-display");
    initIpDisplay();
    await updatePublicIp();
    document.getElementById("copy-ip-btn")!.click();
    expect(writeText).not.toHaveBeenCalled();
  });

  it("toasts success after a clipboard write", async () => {
    invokeMock.mockResolvedValue({ ip: "203.0.113.7", country_code: "NL" });
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    const { initIpDisplay, updatePublicIp } = await import("./ip-display");
    initIpDisplay();
    await updatePublicIp();

    document.getElementById("copy-ip-btn")!.click();
    await Promise.resolve();
    await Promise.resolve();

    expect(writeText).toHaveBeenCalledWith("203.0.113.7");
    expect(showToastMock).toHaveBeenCalledWith(expect.stringContaining("copied"), "success");
  });

  it("toasts an error when the clipboard write fails", async () => {
    invokeMock.mockResolvedValue({ ip: "203.0.113.7", country_code: "NL" });
    const writeText = vi.fn().mockRejectedValue(new Error("denied"));
    Object.assign(navigator, { clipboard: { writeText } });
    const { initIpDisplay, updatePublicIp } = await import("./ip-display");
    initIpDisplay();
    await updatePublicIp();

    document.getElementById("copy-ip-btn")!.click();
    await Promise.resolve();
    await Promise.resolve();

    expect(showToastMock).toHaveBeenCalledWith(expect.stringContaining("denied"), "error");
  });
});
