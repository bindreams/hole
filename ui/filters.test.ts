import { beforeEach, describe, expect, it, vi } from "vitest";

const mainMock: {
  config: Record<string, unknown> | null;
  saveConfig: ReturnType<typeof vi.fn<(...args: unknown[]) => void>>;
} = {
  config: null,
  saveConfig: vi.fn<(...args: unknown[]) => void>(),
};
const invokeMock = vi.fn<(...args: unknown[]) => Promise<unknown>>();
const showToastMock = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...args: unknown[]) => invokeMock(...args) }));
vi.mock("./toast", () => ({ showToast: (...args: unknown[]) => showToastMock(...args) }));
vi.mock("./main", () => ({
  get config() {
    return mainMock.config;
  },
  saveConfig: (...args: unknown[]) => mainMock.saveConfig(...args),
}));

/** The typed view of the mock's filter rules. */
function rules(): { address: string; matching: string; action: string }[] {
  return mainMock.config!.filters as { address: string; matching: string; action: string }[];
}

/// Drain the persist chain: each persist is save (1 await) + reload
/// (1 await); a fixed number of microtask turns covers N chained pairs
/// because every mocked promise is already settled.
async function flushPersist(turns = 8) {
  for (let i = 0; i < turns; i++) await Promise.resolve();
}

function pressOn(el: Element, key: string) {
  el.dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true, cancelable: true }));
}

beforeEach(() => {
  mainMock.saveConfig.mockReset();
  invokeMock.mockReset();
  invokeMock.mockResolvedValue(undefined);
  showToastMock.mockReset();
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
    // Each delete names its rule — N identical "Delete rule" entries are
    // indistinguishable when browsing by button.
    expect(del.getAttribute("aria-label")).toBe("Delete rule for example.com");
    expect(row(0).querySelector(".filter-del")).toBeNull();
    expect(row(0).querySelector(".filter-lock")).toBeTruthy();
  });

  it("decorative glyphs are hidden from the accessibility tree", async () => {
    await setup();
    expect(row(1).querySelector(".drag-handle")!.getAttribute("aria-hidden")).toBe("true");
    expect(row(1).querySelector('td[data-field="matching"] .chev')!.getAttribute("aria-hidden")).toBe("true");
    expect(row(1).querySelector('td[data-field="action"] .chev')!.getAttribute("aria-hidden")).toBe("true");
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
    expect(dropdown.getAttribute("aria-label")).toBe("Action");
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
    await flushPersist(); // persistence is chained, not synchronous
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

  it("blur-commit after clicking a non-focusable area does not steal focus", async () => {
    // Click-away dismissal: focus drops to <body> before the deferred
    // commit runs. The edit must be saved, but focus must stay where the
    // user put it — not jump back into the table.
    vi.useFakeTimers();
    try {
      await setup();
      row(1).querySelector<HTMLElement>(".filter-addr")!.click();
      const input = row(1).querySelector<HTMLInputElement>(".inline-input")!;
      input.value = "kept.example.com";
      input.blur(); // fires the blur event and moves focus to <body>
      vi.runAllTimers();
      expect((mainMock.config!.filters as { address: string }[])[1].address).toBe("kept.example.com");
      expect(document.activeElement).toBe(document.body);
    } finally {
      vi.useRealTimers();
    }
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

// Merged from main's filters.test.ts (#482) — persist-chain, edit-switching,
// drag-cancel, and abandoned-rule coverage, adapted to this file's fixture
// (3 rules: *, example.com, 10.0.0.0/8) and mock names.

describe("reload_proxy_filters on mutation", () => {
  it("deleting a rule saves and reloads the live proxy", async () => {
    await setup();
    document.querySelectorAll<HTMLElement>(".filter-del")[0]!.click(); // deletes rule index 1
    await flushPersist();
    expect(rules()).toHaveLength(2);
    expect(mainMock.saveConfig).toHaveBeenCalled();
    expect(invokeMock).toHaveBeenCalledWith("reload_proxy_filters");
  });

  it("a reload failure is surfaced as a toast", async () => {
    invokeMock.mockRejectedValueOnce("bridge gone");
    await setup();
    document.querySelectorAll<HTMLElement>(".filter-del")[0]!.click();
    await flushPersist();
    expect(showToastMock).toHaveBeenCalledWith(expect.stringContaining("bridge gone"), "error");
  });

  it("two rapid mutations serialize: save,reload,save,reload in order", async () => {
    await setup();
    const order: string[] = [];
    mainMock.saveConfig.mockImplementation(async () => {
      order.push("save");
    });
    invokeMock.mockImplementation(async (cmd: unknown) => {
      order.push(String(cmd));
    });

    // Two synchronous back-to-back deletes (indices shift after the first).
    document.querySelectorAll<HTMLElement>(".filter-del")[0]!.click();
    document.querySelectorAll<HTMLElement>(".filter-del")[0]!.click();
    await flushPersist(16);

    expect(order).toEqual(["save", "reload_proxy_filters", "save", "reload_proxy_filters"]);
    expect(rules()).toHaveLength(1);
  });
});

describe("switching inline edits between cells", () => {
  it("editing rule B while rule A is open commits A and opens a live editor on B", async () => {
    await setup();

    // Open edit on rule index 1 (first non-default), type a new address.
    const cellA = document.querySelectorAll<HTMLElement>(".editable-addr")[0]!;
    cellA.click();
    const inputA = document.querySelector<HTMLInputElement>(".inline-input")!;
    inputA.value = "a2.example.com";

    // Click rule index 2's address cell.
    document.querySelectorAll<HTMLElement>(".editable-addr")[1]!.click();

    // A committed; B has a live (attached) editor.
    expect(rules()[1].address).toBe("a2.example.com");
    const inputB = document.querySelector<HTMLInputElement>(".inline-input");
    expect(inputB).not.toBeNull();
    expect(inputB!.isConnected).toBe(true);
    expect(inputB!.closest("tr")!.dataset.index).toBe("2");
  });
});

describe("background re-render during drag", () => {
  it("cancels the drag, restores document state, and never saves a corrupted list", async () => {
    const mod = await setup();
    const before = rules().map((r) => r.address);

    // Begin a drag on the first non-default rule's handle. bubbles: true is
    // required — the handler is delegated on the tbody. jsdom has no
    // PointerEvent constructor; the handler only reads target/clientY,
    // which MouseEvent provides.
    const handle = document.querySelectorAll<HTMLElement>(".drag-handle")[1]!;
    handle.dispatchEvent(new MouseEvent("pointerdown", { bubbles: true, clientY: 10 }));
    expect(document.body.style.userSelect).toBe("none");

    // A validation-changed style background reload re-renders mid-drag.
    mod.renderFilters();

    // Drag state must be fully cancelled: userSelect restored…
    expect(document.body.style.userSelect).toBe("");
    // …no placeholder or lifted row left behind…
    expect(document.querySelector(".drag-placeholder")).toBeNull();
    // …and a later pointerup must not throw, reorder, or persist anything.
    mainMock.saveConfig.mockClear();
    document.dispatchEvent(new MouseEvent("pointerup"));
    await flushPersist();
    expect(rules().map((r) => r.address)).toEqual(before);
    expect(mainMock.saveConfig).not.toHaveBeenCalled();
  });
});

describe("abandoning a new rule", () => {
  it("clicking another cell while a new rule's address is empty removes the rule", async () => {
    await setup();
    const count = rules().length;

    document.getElementById("filter-add-btn")!.click(); // adds empty rule + opens editor
    expect(rules().length).toBe(count + 1);

    // Abandon it by clicking an existing rule's address cell (sync commit path).
    document.querySelectorAll<HTMLElement>(".editable-addr")[0]!.click();

    expect(rules().length).toBe(count);
    expect(rules().every((r) => r.address !== "")).toBe(true);
  });

  it("the editor opens on the correct rule even when the splice shifts indices", async () => {
    await setup();

    document.getElementById("filter-add-btn")!.click(); // empty rule appended, editor open on it
    // Click rule 2's address cell ("10.0.0.0/8") — the empty rule is
    // spliced out; index 2 stays valid (the splice removed a LATER row),
    // and the editor must land on 10.0.0.0/8's live row.
    document.querySelectorAll<HTMLElement>(".editable-addr")[1]!.click();

    const input = document.querySelector<HTMLInputElement>(".inline-input")!;
    expect(input.isConnected).toBe(true);
    const row = input.closest("tr")!;
    expect(row.dataset.index).toBe("2");
    expect(rules()[2].address).toBe("10.0.0.0/8");
    expect(rules().every((r) => r.address !== "")).toBe(true);
  });
});

describe("test filtering", () => {
  function setTestInput(value: string) {
    const el = document.getElementById("test-input") as HTMLInputElement;
    el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
  }
  const result = () => document.getElementById("test-result")!.textContent;

  it("renders the action and rule label from evaluate_filter", async () => {
    invokeMock.mockImplementation(async (cmd: unknown) =>
      cmd === "evaluate_filter" ? { action: "bypass", rule_index: 1, matched_address: "example.com" } : undefined,
    );
    await setup();
    setTestInput("example.com");
    await flushPersist();
    expect(invokeMock).toHaveBeenCalledWith("evaluate_filter", {
      input: "example.com",
      filters: mainMock.config!.filters,
    });
    expect(result()).toBe("Bypass (matched rule #2: example.com)");
  });

  it("labels the default rule (index 0) specially", async () => {
    invokeMock.mockImplementation(async (cmd: unknown) =>
      cmd === "evaluate_filter" ? { action: "proxy", rule_index: 0, matched_address: "*" } : undefined,
    );
    await setup();
    setTestInput("anything.com");
    await flushPersist();
    expect(result()).toBe("Proxy (matched default rule)");
  });

  it("shows the no-matching-rule fallback with the proxy action", async () => {
    invokeMock.mockImplementation(async (cmd: unknown) =>
      cmd === "evaluate_filter" ? { action: "proxy", rule_index: null, matched_address: null } : undefined,
    );
    await setup();
    setTestInput("9.9.9.9");
    await flushPersist();
    expect(result()).toBe("Proxy (no matching rule)");
  });

  it("clears the result and does not invoke for empty input", async () => {
    invokeMock.mockImplementation(async (cmd: unknown) =>
      cmd === "evaluate_filter" ? { action: "proxy", rule_index: 0, matched_address: "*" } : undefined,
    );
    await setup();
    setTestInput("example.com");
    await flushPersist();
    invokeMock.mockClear();
    setTestInput("");
    await flushPersist();
    expect(result()).toBe("");
    expect(invokeMock).not.toHaveBeenCalledWith("evaluate_filter", expect.anything());
  });

  it("ignores a stale (out-of-order) response", async () => {
    // First (slow) call resolves AFTER the second (fast) call. Latest wins.
    let resolveSlow!: (v: unknown) => void;
    const slow = new Promise((r) => {
      resolveSlow = r;
    });
    invokeMock
      .mockImplementationOnce(async (cmd: unknown) => (cmd === "evaluate_filter" ? slow : undefined))
      .mockImplementation(async (cmd: unknown) =>
        cmd === "evaluate_filter" ? { action: "block", rule_index: 2, matched_address: "10.0.0.0/8" } : undefined,
      );
    await setup();
    setTestInput("first.com"); // in-flight (slow)
    setTestInput("second.com"); // resolves first, fast
    await flushPersist();
    resolveSlow({ action: "proxy", rule_index: 0, matched_address: "*" }); // stale
    await flushPersist();
    expect(result()).toBe("Block (matched rule #3: 10.0.0.0/8)");
  });

  it("survives an evaluate_filter error without throwing", async () => {
    invokeMock.mockImplementation(async (cmd: unknown) => {
      if (cmd === "evaluate_filter") throw "engine boom";
      return undefined;
    });
    await setup();
    setTestInput("example.com");
    await flushPersist();
    expect(result()).toContain("Could not evaluate");
  });

  it("does not repopulate a cleared box with an in-flight response", async () => {
    // Type, then clear before the (slow) response lands. The stale verdict
    // must not overwrite the now-empty box.
    let resolveSlow!: (v: unknown) => void;
    const slow = new Promise((r) => {
      resolveSlow = r;
    });
    invokeMock.mockImplementation(async (cmd: unknown) => (cmd === "evaluate_filter" ? slow : undefined));
    await setup();
    setTestInput("example.com"); // invoke in-flight (slow)
    setTestInput(""); // clear the box before it resolves
    await flushPersist();
    resolveSlow({ action: "bypass", rule_index: 1, matched_address: "example.com" }); // stale
    await flushPersist();
    expect(result()).toBe("");
  });
});
