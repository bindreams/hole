import { beforeEach, describe, expect, it } from "vitest";

// jsdom never fires transitionend on its own; tests dispatch it manually
// on the clip to drive the cleanup handler (target check is `e.target ===
// clip`, which a direct dispatch satisfies).
beforeEach(() => {
  document.body.innerHTML = `
    <button type="button" class="section-hdr" id="hdr" aria-expanded="true" aria-controls="clip">
      <span class="tri">▼</span>
      <span class="section-label">Servers</span>
    </button>
    <div class="section-clip" id="clip"><div class="section-body">content</div></div>
  `;
});

describe("section headers", () => {
  it("click collapses: aria-expanded false, tri rotated, clip collapsed after transition", async () => {
    const { initSections } = await import("./sections");
    initSections();
    const hdr = document.getElementById("hdr")!;
    const clip = document.getElementById("clip")!;
    hdr.click();
    expect(hdr.getAttribute("aria-expanded")).toBe("false");
    expect(hdr.querySelector(".tri")!.classList.contains("collapsed")).toBe(true);
    clip.dispatchEvent(new Event("transitionend"));
    expect(clip.classList.contains("collapsed")).toBe(true);
  });

  it("second click expands again", async () => {
    const { initSections } = await import("./sections");
    initSections();
    const hdr = document.getElementById("hdr")!;
    const clip = document.getElementById("clip")!;
    hdr.click();
    clip.dispatchEvent(new Event("transitionend"));
    hdr.click();
    expect(hdr.getAttribute("aria-expanded")).toBe("true");
    expect(hdr.querySelector(".tri")!.classList.contains("collapsed")).toBe(false);
    expect(clip.classList.contains("collapsed")).toBe(false);
  });
});
