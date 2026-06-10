import { beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.fn();
const saveConfigMock = vi.fn();
const showToastMock = vi.fn();
let mockConfig: { filters: { address: string; matching: string; action: string }[] } | null;

vi.mock("@tauri-apps/api/core", () => ({ invoke: (...args: unknown[]) => invokeMock(...args) }));
vi.mock("./toast", () => ({ showToast: (...args: unknown[]) => showToastMock(...args) }));
vi.mock("./main", () => ({
  get config() {
    return mockConfig;
  },
  saveConfig: (...args: unknown[]) => saveConfigMock(...args),
}));

function scaffold() {
  document.body.innerHTML = `
    <table><tbody id="filter-tbody"></tbody></table>
    <div id="filter-add-btn"></div>
    <input id="test-input" type="text">
    <div id="test-result"></div>`;
}

beforeEach(() => {
  invokeMock.mockReset();
  invokeMock.mockResolvedValue(undefined);
  saveConfigMock.mockReset();
  saveConfigMock.mockResolvedValue(undefined);
  showToastMock.mockReset();
  mockConfig = {
    filters: [
      { address: "*", matching: "wildcard", action: "proxy" },
      { address: "a.example.com", matching: "exactly", action: "block" },
      { address: "b.example.com", matching: "exactly", action: "bypass" },
    ],
  };
  scaffold();
  vi.resetModules();
});

/// Drain the persist chain: each persist is save (1 await) + reload
/// (1 await); a fixed number of microtask turns covers N chained pairs
/// because every mocked promise is already settled.
async function flushPersist(turns = 8) {
  for (let i = 0; i < turns; i++) await Promise.resolve();
}

describe("reload_proxy_filters on mutation", () => {
  it("deleting a rule saves and reloads the live proxy", async () => {
    const { initFilters, renderFilters } = await import("./filters");
    initFilters();
    renderFilters();

    document.querySelectorAll<HTMLElement>(".filter-del")[0]!.click(); // deletes rule index 1
    await flushPersist();

    expect(mockConfig!.filters).toHaveLength(2);
    expect(saveConfigMock).toHaveBeenCalled();
    expect(invokeMock).toHaveBeenCalledWith("reload_proxy_filters");
  });

  it("a reload failure is surfaced as a toast", async () => {
    invokeMock.mockRejectedValueOnce("bridge gone");
    const { initFilters, renderFilters } = await import("./filters");
    initFilters();
    renderFilters();

    document.querySelectorAll<HTMLElement>(".filter-del")[0]!.click();
    await flushPersist();

    expect(showToastMock).toHaveBeenCalledWith(expect.stringContaining("bridge gone"), "error");
  });

  it("two rapid mutations serialize: save,reload,save,reload in order", async () => {
    const { initFilters, renderFilters } = await import("./filters");
    initFilters();
    renderFilters();

    const order: string[] = [];
    saveConfigMock.mockImplementation(async () => {
      order.push("save");
    });
    invokeMock.mockImplementation(async (cmd: string) => {
      order.push(cmd);
    });

    // Two synchronous back-to-back deletes (indices shift after the first).
    document.querySelectorAll<HTMLElement>(".filter-del")[0]!.click();
    document.querySelectorAll<HTMLElement>(".filter-del")[0]!.click();
    await flushPersist(16);

    expect(order).toEqual(["save", "reload_proxy_filters", "save", "reload_proxy_filters"]);
    expect(mockConfig!.filters).toHaveLength(1);
  });
});

describe("switching inline edits between cells", () => {
  it("editing rule B while rule A is open commits A and opens a live editor on B", async () => {
    const { initFilters, renderFilters } = await import("./filters");
    initFilters();
    renderFilters();

    // Open edit on rule index 1 (first non-default), type a new address.
    const cellA = document.querySelectorAll<HTMLElement>(".editable-addr")[0]!;
    cellA.click();
    const inputA = document.querySelector<HTMLInputElement>(".inline-input")!;
    inputA.value = "a2.example.com";

    // Click rule index 2's address cell.
    document.querySelectorAll<HTMLElement>(".editable-addr")[1]!.click();

    // A committed; B has a live (attached) editor.
    expect(mockConfig!.filters[1].address).toBe("a2.example.com");
    const inputB = document.querySelector<HTMLInputElement>(".inline-input");
    expect(inputB).not.toBeNull();
    expect(inputB!.isConnected).toBe(true);
    expect(inputB!.closest("tr")!.dataset.index).toBe("2");
  });
});

describe("background re-render during drag", () => {
  it("cancels the drag, restores document state, and never saves a corrupted list", async () => {
    const { initFilters, renderFilters } = await import("./filters");
    initFilters();
    renderFilters();
    const before = mockConfig!.filters.map((r) => r.address);

    // Begin a drag on the first non-default rule's handle. bubbles: true is
    // required — the handler is delegated on the tbody. jsdom has no
    // PointerEvent constructor; the handler only reads target/clientY,
    // which MouseEvent provides.
    const handle = document.querySelectorAll<HTMLElement>(".drag-handle")[1]!;
    handle.dispatchEvent(new MouseEvent("pointerdown", { bubbles: true, clientY: 10 }));
    expect(document.body.style.userSelect).toBe("none");

    // A validation-changed style background reload re-renders mid-drag.
    renderFilters();

    // Drag state must be fully cancelled: userSelect restored…
    expect(document.body.style.userSelect).toBe("");
    // …no placeholder or lifted row left behind…
    expect(document.querySelector(".drag-placeholder")).toBeNull();
    // …and a later pointerup must not throw, reorder, or persist anything.
    // (This asserts the *outcome* — whether the listener was removed or
    // onDragEnd early-returns on null dragState, the corruption vector is
    // closed either way.)
    saveConfigMock.mockClear();
    document.dispatchEvent(new MouseEvent("pointerup"));
    await flushPersist();
    expect(mockConfig!.filters.map((r) => r.address)).toEqual(before);
    expect(saveConfigMock).not.toHaveBeenCalled();
  });
});

describe("abandoning a new rule", () => {
  it("clicking another cell while a new rule's address is empty removes the rule", async () => {
    const { initFilters, renderFilters } = await import("./filters");
    initFilters();
    renderFilters();
    const count = mockConfig!.filters.length;

    document.getElementById("filter-add-btn")!.click(); // adds empty rule + opens editor
    expect(mockConfig!.filters.length).toBe(count + 1);

    // Abandon it by clicking an existing rule's address cell (sync commit path).
    document.querySelectorAll<HTMLElement>(".editable-addr")[0]!.click();

    expect(mockConfig!.filters.length).toBe(count);
    expect(mockConfig!.filters.every((r) => r.address !== "")).toBe(true);
  });

  it("the editor opens on the correct rule even when the splice shifts indices", async () => {
    const { initFilters, renderFilters } = await import("./filters");
    initFilters();
    renderFilters();

    document.getElementById("filter-add-btn")!.click(); // empty rule appended, editor open on it
    // Click rule 2's address cell ("b.example.com") — the empty rule is
    // spliced out; index 2 stays valid (the splice removed a LATER row),
    // and the editor must land on b.example.com's live row.
    document.querySelectorAll<HTMLElement>(".editable-addr")[1]!.click();

    const input = document.querySelector<HTMLInputElement>(".inline-input")!;
    expect(input.isConnected).toBe(true);
    const row = input.closest("tr")!;
    expect(row.dataset.index).toBe("2");
    expect(mockConfig!.filters[2].address).toBe("b.example.com");
    expect(mockConfig!.filters.every((r) => r.address !== "")).toBe(true);
  });
});
