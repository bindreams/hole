import { beforeEach, describe, expect, it, vi } from "vitest";

const mainMock: {
  config: Record<string, unknown> | null;
  saveConfig: ReturnType<typeof vi.fn<(...args: unknown[]) => void>>;
} = {
  config: null,
  saveConfig: vi.fn<(...args: unknown[]) => void>(),
};
vi.mock("./main", () => ({
  get config() {
    return mainMock.config;
  },
  saveConfig: (...args: unknown[]) => mainMock.saveConfig(...args),
}));

function pressOn(el: Element, key: string) {
  el.dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true, cancelable: true }));
}

beforeEach(() => {
  mainMock.saveConfig.mockClear();
  mainMock.config = {
    filters: [
      { address: "*", matching: "wildcard", action: "proxy" },
      { address: "example.com", matching: "exactly", action: "bypass" },
      { address: "10.0.0.0/8", matching: "subnet", action: "block" },
    ],
  };
  document.body.innerHTML = `
    <table class="filters-tbl"><tbody id="filter-tbody"></tbody></table>
    <button type="button" class="filter-add-row" id="filter-add-btn">+ Add rule</button>
    <input id="test-input" type="text">
    <div id="test-result"></div>
  `;
  vi.resetModules();
});

async function setup() {
  const mod = await import("./filters");
  mod.initFilters();
  mod.renderFilters();
  return mod;
}

function row(index: number): HTMLTableRowElement {
  return document.querySelector(`tr[data-index="${index}"]`)!;
}

describe("filter row controls", () => {
  it("delete is a labelled button on non-default rows; default row keeps the lock", async () => {
    await setup();
    const del = row(1).querySelector(".filter-del")!;
    expect(del.tagName).toBe("BUTTON");
    expect((del as HTMLButtonElement).type).toBe("button");
    expect(del.getAttribute("aria-label")).toBe("Delete rule");
    expect(row(0).querySelector(".filter-del")).toBeNull();
    expect(row(0).querySelector(".filter-lock")).toBeTruthy();
  });

  it("matching/action cells contain expandable buttons on non-default rows only", async () => {
    await setup();
    for (const field of ["matching", "action"]) {
      const cp = row(1).querySelector(`td[data-field="${field}"] .cp`)!;
      expect(cp.tagName).toBe("BUTTON");
      expect(cp.getAttribute("aria-haspopup")).toBe("listbox");
      expect(cp.getAttribute("aria-expanded")).toBe("false");
      expect(row(0).querySelector(`td[data-field="${field}"] .cp`)!.tagName).toBe("DIV");
    }
  });

  it("address cell is an editable button on non-default rows only", async () => {
    await setup();
    expect(row(1).querySelector(".filter-addr")!.tagName).toBe("BUTTON");
    expect(row(0).querySelector(".filter-addr")!.tagName).toBe("SPAN");
  });
});

describe("filter delete", () => {
  it("deletes the rule and restores focus to the delete button at the same position", async () => {
    await setup();
    const del1 = row(1).querySelector<HTMLElement>(".filter-del")!;
    del1.focus();
    del1.click();
    expect((mainMock.config!.filters as { address: string }[]).map((f) => f.address)).toEqual(["*", "10.0.0.0/8"]);
    const remaining = document.querySelectorAll<HTMLElement>(".filter-del");
    expect(remaining).toHaveLength(1);
    expect(document.activeElement).toBe(remaining[0]);
  });

  it("falls back to the add button when the last deletable rule goes", async () => {
    mainMock.config!.filters = [
      { address: "*", matching: "wildcard", action: "proxy" },
      { address: "example.com", matching: "exactly", action: "bypass" },
    ];
    await setup();
    const del = row(1).querySelector<HTMLElement>(".filter-del")!;
    del.focus();
    del.click();
    expect(document.activeElement).toBe(document.getElementById("filter-add-btn"));
  });
});

describe("filter dropdowns", () => {
  it("opening sets aria-expanded, renders option buttons, focuses the selected one", async () => {
    await setup();
    const cp = row(1).querySelector<HTMLElement>('td[data-field="action"] .cp')!;
    cp.click();
    expect(cp.getAttribute("aria-expanded")).toBe("true");
    const dropdown = row(1).querySelector(".inline-dropdown.open")!;
    expect(dropdown.getAttribute("role")).toBe("listbox");
    const opts = [...dropdown.querySelectorAll(".inline-dropdown-opt")];
    expect(opts).toHaveLength(3);
    for (const opt of opts) {
      expect(opt.tagName).toBe("BUTTON");
      expect(opt.getAttribute("role")).toBe("option");
      expect(opt.getAttribute("tabindex")).toBe("-1");
    }
    expect(document.activeElement).toBe(dropdown.querySelector('[data-value="bypass"]'));
  });

  it("arrows rove, Escape closes and refocuses the cell button", async () => {
    await setup();
    const cp = row(1).querySelector<HTMLElement>('td[data-field="action"] .cp')!;
    cp.click();
    pressOn(document.activeElement!, "ArrowDown");
    expect((document.activeElement as HTMLElement).dataset.value).toBe("block");
    pressOn(document.activeElement!, "Escape");
    expect(document.querySelector(".inline-dropdown")).toBeNull();
    const cpAfter = row(1).querySelector<HTMLElement>('td[data-field="action"] .cp')!;
    expect(document.activeElement).toBe(cpAfter);
    expect(cpAfter.getAttribute("aria-expanded")).toBe("false");
  });

  it("choosing an option updates config and restores focus to the rebuilt cell button", async () => {
    await setup();
    const cp = row(1).querySelector<HTMLElement>('td[data-field="action"] .cp')!;
    cp.click();
    (document.querySelector('.inline-dropdown-opt[data-value="block"]') as HTMLElement).click();
    expect((mainMock.config!.filters as { action: string }[])[1].action).toBe("block");
    expect(mainMock.saveConfig).toHaveBeenCalled();
    const rebuilt = row(1).querySelector<HTMLElement>('td[data-field="action"] .cp')!;
    expect(document.activeElement).toBe(rebuilt);
    expect(rebuilt.textContent).toContain("Block");
  });

  it("ArrowDown on the closed cell button opens its dropdown", async () => {
    await setup();
    const cp = row(1).querySelector<HTMLElement>('td[data-field="matching"] .cp')!;
    pressOn(cp, "ArrowDown");
    expect(row(1).querySelector(".inline-dropdown.open")).toBeTruthy();
  });
});

describe("address editing", () => {
  it("clicking the address button swaps in a focused input; Enter commits and refocuses", async () => {
    await setup();
    const addr = row(1).querySelector<HTMLElement>(".filter-addr")!;
    addr.focus();
    addr.click();
    const input = row(1).querySelector<HTMLInputElement>(".inline-input")!;
    expect(document.activeElement).toBe(input);
    input.value = "changed.example.com";
    pressOn(input, "Enter");
    expect((mainMock.config!.filters as { address: string }[])[1].address).toBe("changed.example.com");
    const rebuilt = row(1).querySelector<HTMLElement>(".filter-addr")!;
    expect(rebuilt.textContent).toBe("changed.example.com");
    expect(document.activeElement).toBe(rebuilt);
  });

  it("add rule appends an empty rule and focuses its inline input", async () => {
    await setup();
    document.getElementById("filter-add-btn")!.click();
    expect((mainMock.config!.filters as unknown[]).length).toBe(4);
    const input = document.querySelector<HTMLInputElement>(".inline-input")!;
    expect(document.activeElement).toBe(input);
  });

  it("blur-commit does not steal focus from a control the user clicked", async () => {
    // Mid-edit on row 1, the user clicks row 2's action cell: the click
    // opens that cell's dropdown (focusing an option), then the deferred
    // blur-commit fires and re-renders. Focus must stay with the user's
    // target, not jump back to row 1's address button.
    vi.useFakeTimers();
    try {
      await setup();
      row(1).querySelector<HTMLElement>(".filter-addr")!.click();
      const input = row(1).querySelector<HTMLInputElement>(".inline-input")!;
      input.value = "edited.example.com";
      input.dispatchEvent(new Event("blur"));
      row(2).querySelector<HTMLElement>('td[data-field="action"] .cp')!.click();
      vi.runAllTimers(); // deferred blur-commit: saves + re-renders
      expect((mainMock.config!.filters as { address: string }[])[1].address).toBe("edited.example.com");
      expect(document.activeElement).toBe(row(2).querySelector('td[data-field="action"] .cp'));
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("external re-renders", () => {
  // Config reloads re-render the table at any moment; the focused control
  // must survive the rebuild.
  it("keeps focus on the same cell button across a re-render", async () => {
    const mod = await setup();
    row(1).querySelector<HTMLElement>('td[data-field="matching"] .cp')!.focus();
    mod.renderFilters();
    expect(document.activeElement).toBe(row(1).querySelector('td[data-field="matching"] .cp'));
  });

  it("keeps focus on the same delete button across a re-render", async () => {
    const mod = await setup();
    row(2).querySelector<HTMLElement>(".filter-del")!.focus();
    mod.renderFilters();
    expect(document.activeElement).toBe(row(2).querySelector(".filter-del"));
  });

  it("maps a focused address button back to the rebuilt address button", async () => {
    const mod = await setup();
    row(1).querySelector<HTMLElement>(".filter-addr")!.focus();
    mod.renderFilters();
    expect(document.activeElement).toBe(row(1).querySelector(".filter-addr"));
  });

  it("does not touch focus when it is outside the table", async () => {
    const mod = await setup();
    const outside = document.getElementById("filter-add-btn")!;
    outside.focus();
    mod.renderFilters();
    expect(document.activeElement).toBe(outside);
  });
});
