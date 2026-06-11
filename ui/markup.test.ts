import { describe, expect, it } from "vitest";
import html from "./index.html?raw";

// Static-markup accessibility contract for issue #476: every interactive
// control in index.html must be a real <button> (focusable, native
// Enter/Space activation) carrying the ARIA state its pattern requires.
const doc = new DOMParser().parseFromString(html, "text/html");

function byId(id: string): HTMLElement {
  const el = doc.getElementById(id);
  if (!el) throw new Error(`#${id} missing from index.html`);
  return el;
}

function assertLabelledBy(el: HTMLElement) {
  const refs = el.getAttribute("aria-labelledby");
  expect(refs, `${el.id} needs aria-labelledby`).toBeTruthy();
  for (const ref of refs!.split(" ")) {
    expect(doc.getElementById(ref), `#${ref} referenced by #${el.id}`).toBeTruthy();
  }
}

describe("settings toggles", () => {
  const ids = [
    "toggle-start-on-login",
    "toggle-proxy-server",
    "toggle-socks5",
    "toggle-http",
    "toggle-dns-enabled",
    "toggle-dns-intercept",
  ];
  it.each(ids)("%s is a labelled switch button", (id) => {
    const el = byId(id);
    expect(el.tagName).toBe("BUTTON");
    expect(el.getAttribute("type")).toBe("button");
    expect(el.getAttribute("role")).toBe("switch");
    expect(el.getAttribute("aria-checked")).toBe("false");
    assertLabelledBy(el);
  });
});

describe("custom select dropdowns", () => {
  const families = [
    { btn: "select-on-startup", menu: "menu-on-startup" },
    { btn: "select-theme", menu: "menu-theme" },
    { btn: "select-dns-protocol", menu: "menu-dns-protocol" },
  ];
  it.each(families)("$btn trigger is a labelled listbox button", ({ btn, menu }) => {
    const el = byId(btn);
    expect(el.tagName).toBe("BUTTON");
    expect(el.getAttribute("type")).toBe("button");
    expect(el.getAttribute("aria-haspopup")).toBe("listbox");
    expect(el.getAttribute("aria-expanded")).toBe("false");
    expect(el.getAttribute("aria-controls")).toBe(menu);
    assertLabelledBy(el);
  });
  it.each(families)("$menu options are focusable option buttons", ({ menu }) => {
    const m = byId(menu);
    expect(m.getAttribute("role")).toBe("listbox");
    const opts = [...m.querySelectorAll(".custom-select-opt")];
    expect(opts.length).toBeGreaterThan(1);
    for (const opt of opts) {
      expect(opt.tagName).toBe("BUTTON");
      expect(opt.getAttribute("type")).toBe("button");
      expect(opt.getAttribute("role")).toBe("option");
      expect(opt.getAttribute("tabindex")).toBe("-1");
      expect(["true", "false"]).toContain(opt.getAttribute("aria-selected"));
    }
    expect(opts.filter((o) => o.getAttribute("aria-selected") === "true")).toHaveLength(1);
  });
});

describe("section headers", () => {
  const ids = ["section-servers-hdr", "section-filters-hdr", "section-settings-hdr"];
  it.each(ids)("%s is an expanded disclosure button controlling its clip", (id) => {
    const el = byId(id);
    expect(el.tagName).toBe("BUTTON");
    expect(el.getAttribute("type")).toBe("button");
    expect(el.getAttribute("aria-expanded")).toBe("true");
    const clipId = el.getAttribute("aria-controls");
    expect(clipId).toBeTruthy();
    const clip = doc.getElementById(clipId!);
    expect(clip?.classList.contains("section-clip")).toBe(true);
    // toggleSection finds the clip via nextElementSibling — pin the structure.
    expect(el.nextElementSibling).toBe(clip);
  });

  it.each(ids)("%s hides its decorative triangle from the accessibility tree", (id) => {
    // Without aria-hidden the ▼ glyph pollutes the button's accessible
    // name ("▼ Servers").
    expect(byId(id).querySelector(".tri")!.getAttribute("aria-hidden")).toBe("true");
  });
});

describe("remaining controls", () => {
  it("import zone is a button", () => {
    const el = byId("import-zone");
    expect(el.tagName).toBe("BUTTON");
    expect(el.getAttribute("type")).toBe("button");
  });
  it("filter add-rule is a button", () => {
    const el = byId("filter-add-btn");
    expect(el.tagName).toBe("BUTTON");
    expect(el.getAttribute("type")).toBe("button");
  });
  it("copy-IP is a button with an accessible name", () => {
    const el = byId("copy-ip-btn");
    expect(el.tagName).toBe("BUTTON");
    expect(el.getAttribute("type")).toBe("button");
    expect(el.getAttribute("aria-label")).toBeTruthy();
  });
  it("power button has an accessible name (icon-only, SVG is aria-hidden)", () => {
    expect(byId("power-btn").getAttribute("aria-label")).toBeTruthy();
  });
});
