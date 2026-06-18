// Filters section: filter rules table with in-place editing, drag reorder,
// test filtering, add/delete rules.

import { invoke } from "@tauri-apps/api/core";
import { config, saveConfig } from "./main";
import { menuKeydown } from "./menu-keys";
import { showToast } from "./toast";
import type { FilterRule, InvalidFilter } from "./types";

// Constants ===========================================================================================================

const MATCH_TYPES = [
  { value: "exactly", label: "exactly" },
  { value: "with_subdomains", label: "with subdomains" },
  { value: "wildcard", label: "wildcard" },
  { value: "subnet", label: "subnet" },
];

const ACTION_TYPES = [
  { value: "proxy", label: "Proxy" },
  { value: "bypass", label: "Bypass" },
  { value: "block", label: "Block" },
];

/** Map internal values to display labels. */
function matchLabel(value: string): string {
  const entry = MATCH_TYPES.find((m) => m.value === value);
  return entry ? entry.label : value;
}

function actionLabel(value: string): string {
  const entry = ACTION_TYPES.find((a) => a.value === value);
  return entry ? entry.label : value;
}

// DOM references ======================================================================================================

const tbody = document.getElementById("filter-tbody")!;
const addBtn = document.getElementById("filter-add-btn")!;
const testInput = document.getElementById("test-input") as HTMLInputElement;
const testResult = document.getElementById("test-result")!;

// State ===============================================================================================================

/** Currently open dropdown element, or null. */
let openDropdown: (HTMLDivElement & { _td?: HTMLTableCellElement }) | null = null;

/** Index of the row being edited inline (address input), or -1. */
let editingIndex = -1;

// Invalid-filter badges (#470) ========================================================================================

/// The bridge's list of dropped rules from the latest status poll, keyed by
/// their index in `config.filters`. Repainted onto rows by `applyInvalidFilterBadges`.
let invalidFilters: InvalidFilter[] = [];

/// Monotonic epoch, bumped whenever a local mutation changes the ruleset shape.
/// The poll captures it before fetching and discards a result that resolved
/// after a mutation — those indices no longer match the rendered rows.
let epoch = 0;

/** Current ruleset epoch; the poll uses it to drop a stale-revision result. */
export function filtersEpoch(): number {
  return epoch;
}

/// Drop the cached invalid-filter list and bump the epoch. Called synchronously
/// from every ruleset mutation BEFORE its re-render, so a badge can never paint
/// against indices the bridge has not re-judged.
function invalidateInvalidFilters(): void {
  epoch++;
  invalidFilters = [];
  applyInvalidFilterBadges();
}

/// Latest dropped-rule list from the status poll; repaints the badges. `null`
/// means the bridge could not vouch this poll (a non-Status arm) — keep the
/// last-known badges instead of blinking them off on a transient hiccup
/// (mirrors the capability dots).
export function setInvalidFilters(list: InvalidFilter[] | null): void {
  if (list === null) return;
  invalidFilters = list;
  applyInvalidFilterBadges();
}

/// Targeted badge paint: add/remove a `.filter-invalid` marker on each row by
/// its index. NOT a full re-render — it must not cancel a drag, close a
/// dropdown, or commit a half-typed edit on the 5s poll. Derives purely from
/// the current rows + the cache, so it is correct however it is reached.
function applyInvalidFilterBadges(): void {
  const byIndex = new Map<number, string>();
  for (const f of invalidFilters) byIndex.set(f.index, f.error);
  for (const tr of tbody.querySelectorAll<HTMLTableRowElement>("tr")) {
    tr.querySelector(".filter-invalid")?.remove();
    const i = parseInt(tr.dataset.index ?? "", 10);
    const err = byIndex.get(i);
    const host = tr.querySelector(".cp-addr");
    if (err == null || !host) continue;
    const badge = document.createElement("span");
    badge.className = "filter-invalid";
    badge.textContent = "⚠"; // ⚠
    badge.title = `Rule not applied: ${err}`;
    badge.setAttribute("aria-label", `Rule not applied: ${err}`);
    host.appendChild(badge);
  }
}

// Persistence =========================================================================================================

/// Persist the rule list, then push it to the running proxy.
/// reload_proxy_filters is a no-op on the Rust side when disconnected;
/// when connected, skipping it would leave live traffic on the old rules
/// until the next reconnect with no indication in the UI.
///
/// Serialized through `persistChain`: callers fire-and-forget, and two
/// rapid mutations must not interleave their save/reload pairs — the
/// proxy must never be reloaded with an older snapshot than the last
/// save. A reload that follows a FAILED save is harmless: save_config
/// only replaces the Rust-side config on a successful disk write, so
/// the reload pushes the unchanged old rules.
let persistChain: Promise<void> = Promise.resolve();

function persistFilters(): Promise<void> {
  // The bridge has not re-judged the mutated ruleset; drop stale badges now and
  // invalidate any in-flight poll result via the epoch (#470).
  invalidateInvalidFilters();
  persistChain = persistChain.then(async () => {
    await saveConfig();
    try {
      await invoke("reload_proxy_filters");
    } catch (err) {
      console.error("reload_proxy_filters failed:", err);
      showToast(`Filters saved, but not applied to the running proxy: ${err}`, "error");
    }
  });
  return persistChain;
}

// Rendering ===========================================================================================================

/** Ensure config.filters has the default wildcard rule at index 0. */
function ensureDefaultRule() {
  if (!config) return;
  if (!config.filters) {
    config.filters = [];
  }
  if (
    config.filters.length === 0 ||
    config.filters[0].address !== "*" ||
    config.filters[0].matching !== "wildcard" ||
    config.filters[0].action !== "proxy"
  ) {
    config.filters.unshift({
      address: "*",
      matching: "wildcard",
      action: "proxy",
    });
    // The unshift shifts every later index — stale invalid-filter indices no
    // longer match the rows (#470).
    invalidateInvalidFilters();
    saveConfig();
  }
}

/**
 * Re-render all filter rows based on the current config.
 * Call this whenever `config.filters` changes.
 */
export function renderFilters() {
  if (!config) return;
  ensureDefaultRule();

  // External re-renders (e.g. config reloads) destroy the focused control
  // with the rest of the table; remember which rule + control held focus
  // so the rebuild can put it back. A focused inline edit input or
  // dropdown option maps back to the control that opened it. The rule is
  // remembered both by identity (commitPendingEdit below may splice,
  // shifting indices) and by index (a config reload replaces the rule
  // objects but keeps the structure). Captured before closeDropdown()
  // removes a focused option.
  const active = document.activeElement;
  let restoreRule: FilterRule | null = null;
  let restoreIndex = -1;
  let restoreControl: string | null = null;
  if (active instanceof HTMLElement && tbody.contains(active)) {
    restoreIndex = parseInt(active.closest("tr")?.dataset.index ?? "", 10);
    restoreRule = Number.isNaN(restoreIndex) ? null : (config.filters[restoreIndex] ?? null);
    if (active.closest(".filter-del")) {
      restoreControl = ".filter-del";
    } else if (active.closest(".editable-addr")) {
      restoreControl = ".filter-addr";
    } else {
      const field = (active.closest("td") as HTMLTableCellElement | null)?.dataset.field;
      restoreControl = field ? `td[data-field="${field}"] .cp` : null;
    }
  }

  // Flush a pending edit before wiping the tbody. This writes the open
  // editor's value into the CURRENT config by row index — sound because
  // every loadConfig caller today reloads a structurally identical
  // filters array; a reload that reshapes the rules would need an
  // identity-based commit instead.
  commitPendingEdit();
  cancelDrag();
  closeDropdown();
  tbody.innerHTML = "";

  for (let i = 0; i < config.filters.length; i++) {
    const rule = config.filters[i];
    const isDefault = i === 0;

    const tr = document.createElement("tr");
    tr.dataset.index = String(i);
    if (isDefault) tr.classList.add("no-drag");

    // Address cell ----------------------------------------------------------------------------------------------------
    const tdAddr = document.createElement("td");
    tdAddr.className = isDefault ? "" : "editable-addr";

    const divAddr = document.createElement("div");
    divAddr.className = "cp-addr";

    const handle = document.createElement("span");
    handle.className = "drag-handle";
    handle.textContent = "\u283F"; // ⠿ braille pattern dots-123456
    handle.setAttribute("aria-hidden", "true"); // decorative; drag is pointer-only
    divAddr.appendChild(handle);

    // The address is a button on editable rows (activation starts the
    // inline edit; startAddressEdit swaps exactly this node for the
    // input, so the button must be the .filter-addr node itself).
    const addrEl = document.createElement(isDefault ? "span" : "button");
    if (addrEl instanceof HTMLButtonElement) addrEl.type = "button";
    addrEl.className = "filter-addr";
    addrEl.textContent = rule.address;
    divAddr.appendChild(addrEl);

    tdAddr.appendChild(divAddr);
    tr.appendChild(tdAddr);

    // Matching cell ---------------------------------------------------------------------------------------------------
    const tdMatch = document.createElement("td");
    tdMatch.className = isDefault ? "" : "editable-cell";
    tdMatch.dataset.field = "matching";

    const divMatch = document.createElement(isDefault ? "div" : "button");
    divMatch.className = "cp";
    if (divMatch instanceof HTMLButtonElement) {
      divMatch.type = "button";
      divMatch.setAttribute("aria-haspopup", "listbox");
      divMatch.setAttribute("aria-expanded", "false");
      wireCellArrowOpen(divMatch, tdMatch, i);
    }

    const matchSpan = document.createElement("span");
    matchSpan.className = "filter-match";
    matchSpan.textContent = matchLabel(rule.matching);
    divMatch.appendChild(matchSpan);

    if (!isDefault) {
      const chev = document.createElement("span");
      chev.className = "chev";
      chev.textContent = "\u25BE";
      chev.setAttribute("aria-hidden", "true"); // decorative; keeps it out of the button's name
      divMatch.appendChild(chev);
    }

    tdMatch.appendChild(divMatch);
    tr.appendChild(tdMatch);

    // Action cell -----------------------------------------------------------------------------------------------------
    const tdAction = document.createElement("td");
    tdAction.className = `${isDefault ? "action-cell" : "action-cell editable-cell"} ${rule.action}`;
    tdAction.dataset.field = "action";

    const divAction = document.createElement(isDefault ? "div" : "button");
    divAction.className = "cp";
    divAction.textContent = actionLabel(rule.action);
    if (divAction instanceof HTMLButtonElement) {
      divAction.type = "button";
      divAction.setAttribute("aria-haspopup", "listbox");
      divAction.setAttribute("aria-expanded", "false");
      wireCellArrowOpen(divAction, tdAction, i);
    }

    if (!isDefault) {
      const chev = document.createElement("span");
      chev.className = "chev";
      chev.textContent = "\u25BE";
      chev.setAttribute("aria-hidden", "true"); // decorative; keeps it out of the button's name
      divAction.appendChild(chev);
    }

    tdAction.appendChild(divAction);
    tr.appendChild(tdAction);

    // Delete cell -----------------------------------------------------------------------------------------------------
    const tdDel = document.createElement("td");
    tdDel.className = "del-cell";

    if (!isDefault) {
      const delBtn = document.createElement("button");
      delBtn.type = "button";
      delBtn.className = "filter-del";
      delBtn.textContent = "\u2715";
      delBtn.setAttribute("aria-label", rule.address ? `Delete rule for ${rule.address}` : "Delete rule");
      tdDel.appendChild(delBtn);
    } else {
      // Default wildcard rule — show a lock icon to indicate it cannot be deleted.
      // Inline monochrome SVG to match the UI icon style. Static literal (no
      // user input) so innerHTML is XSS-safe.
      const lockSpan = document.createElement("span");
      lockSpan.className = "filter-lock";
      lockSpan.title = "Default rule (cannot be deleted)";
      lockSpan.innerHTML =
        '<svg viewBox="0 0 16 16" width="11" height="11" fill="currentColor" fill-rule="evenodd" aria-hidden="true">' +
        '<path d="M8 1a3 3 0 0 0-3 3v3H4a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V8a1 1 0 0 0-1-1h-1V4a3 3 0 0 0-3-3zM6 4a2 2 0 1 1 4 0v3H6V4z"/>' +
        "</svg>";
      tdDel.appendChild(lockSpan);
    }

    tr.appendChild(tdDel);
    tbody.appendChild(tr);
  }

  // preventScroll: restoration preserves tab position invisibly — a
  // background re-render must not yank the viewport to the element.
  if (restoreControl !== null && !Number.isNaN(restoreIndex)) {
    const byIdentity = restoreRule ? config.filters.indexOf(restoreRule) : -1;
    const index = byIdentity >= 0 ? byIdentity : restoreIndex;
    tbody.querySelector<HTMLElement>(`tr[data-index="${index}"] ${restoreControl}`)?.focus({ preventScroll: true });
  }

  // Repaint invalid-filter badges from the cache (#470): the table was rebuilt,
  // so the prior badge spans are gone.
  applyInvalidFilterBadges();

  // Re-evaluate test filtering after render.
  evaluateTestFilter();
}

// In-place address editing ============================================================================================

/**
 * Start inline editing of an address cell.
 * @param {HTMLTableCellElement} td - The `.editable-addr` cell.
 * @param {number} index - The filter rule index.
 */
function startAddressEdit(td: HTMLTableCellElement, index: number) {
  if (editingIndex === index) return; // Already editing this cell.

  // Committing the previous edit re-renders the table, detaching `td`
  // and possibly shifting `index` (an abandoned empty rule is spliced
  // out). Capture the rule's identity, commit, then re-resolve both.
  // Safe: this whole path is synchronous, so `config` cannot be
  // reassigned between capture and re-resolution.
  const rule = config?.filters[index];
  commitOrCancelEditing(); // Close any other active edit.
  if (!rule || !config) return;
  const liveIndex = config.filters.indexOf(rule);
  if (liveIndex < 0) return; // rule was removed by the commit
  const liveTd = tbody.querySelector<HTMLTableCellElement>(`tr[data-index="${liveIndex}"] .editable-addr`);
  if (!liveTd) return;
  td = liveTd;
  index = liveIndex;

  editingIndex = index;
  const addrSpan = td.querySelector(".filter-addr");
  if (!addrSpan) return;

  const original = addrSpan.textContent ?? "";

  const input = document.createElement("input");
  input.className = "inline-input";
  input.type = "text";
  input.value = original;

  addrSpan.replaceWith(input);
  input.focus();
  input.select();

  function commit() {
    if (editingIndex !== index) return; // Already committed or cancelled.
    // Refocus eligibility is decided BEFORE the re-render: only an edit
    // ending with the input still focused (Enter/Escape) may move focus
    // afterwards — a blur-commit from clicking elsewhere must not.
    const shouldRefocus = document.activeElement === input;
    editingIndex = -1;

    const newValue = input.value.trim();
    if (!newValue) {
      // Empty address — remove the rule (it was never valid).
      config?.filters.splice(index, 1);
      void persistFilters();
    } else if (newValue !== original) {
      if (config) config.filters[index].address = newValue;
      void persistFilters();
    }
    renderFilters();
    refocusAddrAfterEdit(index, shouldRefocus);
  }

  function cancel() {
    if (editingIndex !== index) return;
    const shouldRefocus = document.activeElement === input;
    editingIndex = -1;
    // If the original address was empty (new rule), remove it.
    if (!original && config?.filters[index]) {
      config.filters.splice(index, 1);
    }
    renderFilters();
    refocusAddrAfterEdit(index, shouldRefocus);
  }

  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      commit();
    } else if (e.key === "Escape") {
      e.preventDefault();
      cancel();
    }
  });

  input.addEventListener("blur", () => {
    // Use setTimeout so that if blur was triggered by a click on another
    // interactive element, the click handler runs first.
    setTimeout(() => {
      if (editingIndex === index) commit();
    }, 0);
  });
}

/// Commit a pending inline address edit WITHOUT re-rendering. Lets
/// renderFilters() flush the edit before it wipes the tbody (calling the
/// rendering variant from there would recurse).
function commitPendingEdit() {
  if (editingIndex < 0) return;
  const index = editingIndex;
  const input = tbody.querySelector<HTMLInputElement>(".inline-input");
  editingIndex = -1; // Clear first so the blur handler becomes a no-op.
  if (input && config?.filters[index]) {
    const value = input.value.trim();
    if (!value) {
      // Empty address — the rule was never valid; drop it like commit() does.
      config.filters.splice(index, 1);
      void persistFilters();
    } else if (value !== config.filters[index].address) {
      config.filters[index].address = value;
      void persistFilters();
    }
  }
}

/** If there's an active address edit, commit it synchronously. */
function commitOrCancelEditing() {
  if (editingIndex < 0) return;
  commitPendingEdit();
  renderFilters();
}

// Inline dropdowns ====================================================================================================

/** Close the currently open dropdown. */
function closeDropdown() {
  if (openDropdown) {
    openDropdown._td?.querySelector(".cp")?.setAttribute("aria-expanded", "false");
    openDropdown.remove();
    openDropdown = null;
  }
}

/** Focus the dropdown-cell button of a row after a re-render. */
function focusCellButton(index: number, field: string) {
  tbody.querySelector<HTMLElement>(`tr[data-index="${index}"] td[data-field="${field}"] .cp`)?.focus();
}

/**
 * Refocus an address button after an edit-triggered re-render.
 * @param {number} index - The edited rule's index.
 * @param {boolean} shouldRefocus - Whether the input held focus when the
 *   edit ended (captured before the re-render). False for blur-commits,
 *   which must never steal focus from wherever the user clicked.
 */
function refocusAddrAfterEdit(index: number, shouldRefocus: boolean) {
  if (!shouldRefocus) return;
  // renderFilters' own focus capture usually restores the address button
  // already; this fallback covers a removed row (cancelled new rule).
  if (document.activeElement !== document.body) return;
  const addr = tbody.querySelector<HTMLElement>(`tr[data-index="${index}"] .filter-addr`);
  (addr ?? addBtn).focus();
}

/**
 * Toggle an inline dropdown for a matching or action cell.
 * @param {HTMLTableCellElement} td - The `.editable-cell` that was clicked.
 * @param {number} index - The filter rule index.
 */
function toggleDropdown(td: HTMLTableCellElement, index: number) {
  const field = td.dataset.field; // "matching" or "action"
  if (!field) return;

  // If this dropdown is already open on this cell, close it (toggle).
  if (openDropdown && openDropdown._td === td) {
    closeDropdown();
    return;
  }

  closeDropdown();

  if (!config) return;

  const options = field === "matching" ? MATCH_TYPES : ACTION_TYPES;
  const rule = config.filters[index];
  const currentValue = field === "matching" ? rule.matching : rule.action;

  const dropdown = document.createElement("div") as HTMLDivElement & { _td?: HTMLTableCellElement };
  dropdown.className = "inline-dropdown open";
  dropdown.setAttribute("role", "listbox");
  dropdown.setAttribute("aria-label", field === "matching" ? "Matching" : "Action");
  dropdown._td = td; // Tag so we can detect toggle clicks.

  const cellBtn = td.querySelector<HTMLElement>(".cp");

  for (const opt of options) {
    const optBtn = document.createElement("button");
    optBtn.type = "button";
    optBtn.className = `inline-dropdown-opt${opt.value === currentValue ? " selected" : ""}`;
    optBtn.setAttribute("role", "option");
    optBtn.setAttribute("aria-selected", String(opt.value === currentValue));
    optBtn.tabIndex = -1;
    optBtn.textContent = opt.label;
    optBtn.dataset.value = opt.value;

    optBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      if (!config) return;
      if (field === "matching") {
        config.filters[index].matching = opt.value as FilterRule["matching"];
      } else {
        config.filters[index].action = opt.value as FilterRule["action"];
      }
      void persistFilters();
      closeDropdown();
      renderFilters();
      // The re-render rebuilt the row; keep keyboard users on the cell.
      focusCellButton(index, field);
    });

    dropdown.appendChild(optBtn);
  }

  dropdown.addEventListener("keydown", (e) => {
    const opts = [...dropdown.querySelectorAll<HTMLElement>(".inline-dropdown-opt")];
    menuKeydown(e, opts, () => {
      closeDropdown();
      cellBtn?.focus();
    });
  });

  td.appendChild(dropdown);
  openDropdown = dropdown;
  cellBtn?.setAttribute("aria-expanded", "true");
  (
    dropdown.querySelector<HTMLElement>(".inline-dropdown-opt.selected") ??
    dropdown.querySelector<HTMLElement>(".inline-dropdown-opt")
  )?.focus();
}

/**
 * Let ArrowDown/ArrowUp on a closed cell button open its dropdown,
 * mirroring the settings dropdowns.
 */
function wireCellArrowOpen(btn: HTMLButtonElement, td: HTMLTableCellElement, index: number) {
  btn.addEventListener("keydown", (e) => {
    if ((e.key === "ArrowDown" || e.key === "ArrowUp") && openDropdown?._td !== td) {
      e.preventDefault();
      toggleDropdown(td, index);
    }
  });
}

// Drag reorder ========================================================================================================

interface DragState {
  row: HTMLTableRowElement;
  index: number;
  currentIndex: number;
  placeholder: HTMLTableRowElement;
  offsetY: number;
  tbodyTop: number;
}

/** Active drag state, or null. */
let dragState: DragState | null = null;

/// Abandon an in-progress drag without applying a reorder. Called by
/// renderFilters() when a background reload wipes the tbody mid-drag:
/// finishing the drag against detached rows would throw before listener
/// cleanup and then save a corrupted rule list on the next click. The
/// lifted row's inline styles are not restored here — every caller wipes
/// the tbody immediately after, discarding the row.
function cancelDrag() {
  if (!dragState) return;
  dragState.placeholder.remove();
  document.removeEventListener("pointermove", onDragMove);
  document.removeEventListener("pointerup", onDragEnd);
  document.body.style.userSelect = "";
  dragState = null;
}

/**
 * Start dragging a row.
 * @param {PointerEvent} e - The pointerdown event on the drag handle.
 * @param {HTMLTableRowElement} row - The row being dragged.
 * @param {number} index - The filter rule index.
 */
function startDrag(e: PointerEvent, row: HTMLTableRowElement, index: number) {
  e.preventDefault();
  closeDropdown();
  // Any open edit was already committed by onTbodyPointerDown, which
  // re-resolved `row`/`index` against the post-commit DOM.

  const rect = row.getBoundingClientRect();
  const tbodyRect = tbody.getBoundingClientRect();

  // Snapshot cell widths so the lifted row keeps its layout.
  const cells = row.querySelectorAll("td");
  const cellWidths = [];
  for (const cell of cells) {
    cellWidths.push(cell.getBoundingClientRect().width);
  }

  // Create placeholder.
  const placeholder = document.createElement("tr");
  placeholder.className = "drag-placeholder";
  placeholder.innerHTML = `<td colspan="4" style="height:${rect.height}px; border-bottom: 2px solid var(--accent); padding:0;"></td>`;

  // Insert placeholder where the row was.
  row.parentNode!.insertBefore(placeholder, row);

  // Lift the row.
  for (let i = 0; i < cells.length; i++) {
    cells[i].style.width = `${cellWidths[i]}px`;
  }
  row.style.position = "fixed";
  row.style.top = `${rect.top}px`;
  row.style.left = `${rect.left}px`;
  row.style.width = `${rect.width}px`;
  row.style.zIndex = "100";
  row.style.background = "var(--bg-elevated)";
  row.style.boxShadow = "0 4px 16px rgba(0,0,0,0.3)";
  row.style.pointerEvents = "none";
  row.style.transition = "none";

  // Move row to end of tbody so it renders on top.
  tbody.appendChild(row);

  dragState = {
    row,
    index,
    currentIndex: index,
    placeholder,
    offsetY: e.clientY - rect.top,
    tbodyTop: tbodyRect.top,
  };

  document.addEventListener("pointermove", onDragMove);
  document.addEventListener("pointerup", onDragEnd);
  // Prevent text selection during drag.
  document.body.style.userSelect = "none";
}

/** Handle pointer move during drag. */
function onDragMove(e: PointerEvent) {
  if (!dragState) return;

  const { row, placeholder, offsetY } = dragState;
  row.style.top = `${e.clientY - offsetY}px`;

  // Determine where the placeholder should go.
  const rows = Array.from(tbody.querySelectorAll("tr")).filter((r) => r !== row && r !== placeholder);

  // Snapshot positions BEFORE any DOM move.
  const beforePositions = new Map();
  for (const r of rows) {
    beforePositions.set(r, r.getBoundingClientRect().top);
  }

  // Find insertion point based on cursor Y vs. midpoints.
  let insertBefore = null;
  for (const r of rows) {
    const rect = r.getBoundingClientRect();
    const midY = rect.top + rect.height / 2;
    if (e.clientY < midY) {
      insertBefore = r;
      break;
    }
  }

  // The default rule (index 0) is always first. Don't insert placeholder
  // before it.
  const firstRow = rows[0];
  if (firstRow && firstRow.dataset.index === "0" && insertBefore === firstRow) {
    // Insert after the default rule instead.
    insertBefore = firstRow.nextElementSibling;
    if (insertBefore === placeholder) {
      insertBefore = placeholder.nextElementSibling;
    }
  }

  // Only move if the target position is different.
  const currentNext = placeholder.nextElementSibling;
  if (insertBefore !== currentNext) {
    // Move placeholder in the DOM.
    tbody.insertBefore(placeholder, insertBefore);
    // Re-append dragged row to keep it on top.
    tbody.appendChild(row);

    // Snapshot positions AFTER DOM move.
    const afterPositions = new Map();
    for (const r of rows) {
      afterPositions.set(r, r.getBoundingClientRect().top);
    }

    // FLIP animation: apply inverse transform then animate to 0.
    for (const r of rows) {
      const before = beforePositions.get(r);
      const after = afterPositions.get(r);
      if (before === undefined || after === undefined) continue;
      const delta = before - after;
      if (Math.abs(delta) < 1) continue;

      // Cancel any in-progress animation.
      r.style.transition = "none";
      r.style.transform = `translateY(${delta}px)`;

      // Force reflow then animate.
      r.offsetHeight; // eslint-disable-line no-unused-expressions
      r.style.transition = "transform 250ms ease";
      r.style.transform = "translateY(0)";
    }
  }
}

/** Handle pointer up to finish drag. */
function onDragEnd() {
  if (!dragState) return;

  const { row, placeholder } = dragState;

  // Insert the row where the placeholder is.
  tbody.insertBefore(row, placeholder);
  placeholder.remove();

  // Clean up all inline styles on the row.
  row.style.position = "";
  row.style.top = "";
  row.style.left = "";
  row.style.width = "";
  row.style.zIndex = "";
  row.style.background = "";
  row.style.boxShadow = "";
  row.style.pointerEvents = "";
  row.style.transition = "";
  for (const cell of row.querySelectorAll("td")) {
    cell.style.width = "";
  }

  // Clean up transforms on all rows.
  for (const r of tbody.querySelectorAll("tr")) {
    r.style.transition = "";
    r.style.transform = "";
  }

  // Update config.filters to match new DOM order.
  if (config) {
    const newFilters: FilterRule[] = [];
    for (const tr of tbody.querySelectorAll("tr")) {
      const idx = parseInt(tr.dataset.index ?? "", 10);
      if (!Number.isNaN(idx) && config.filters[idx]) {
        newFilters.push(config.filters[idx]);
      }
    }
    config.filters = newFilters;
    void persistFilters();
  }

  document.removeEventListener("pointermove", onDragMove);
  document.removeEventListener("pointerup", onDragEnd);
  document.body.style.userSelect = "";

  dragState = null;

  // Re-render to normalize data-index attributes.
  renderFilters();
}

// Add rule ============================================================================================================

/** Add a new empty filter rule and focus it for editing. */
function addRule() {
  if (!config) return;
  ensureDefaultRule();

  config.filters.push({
    address: "",
    matching: "wildcard",
    action: "proxy",
  });
  // Do not saveConfig() yet — wait until the user commits a non-empty address.
  renderFilters();

  // Focus the new row's address cell for immediate editing.
  const lastRow = tbody.querySelector("tr:last-child");
  if (lastRow) {
    const addrTd = lastRow.querySelector(".editable-addr") as HTMLTableCellElement | null;
    if (addrTd) {
      const newIndex = config.filters.length - 1;
      startAddressEdit(addrTd, newIndex);
    }
  }
}

// Delete rule =========================================================================================================

/**
 * Delete a filter rule by index.
 * @param {number} index - The filter rule index (cannot be 0).
 */
function deleteRule(index: number) {
  if (index <= 0 || !config?.filters) return; // Cannot delete default rule.
  // The re-render destroys the focused delete button; remember whether
  // focus was inside the table so keyboard users stay in place.
  const hadFocusInTable = tbody.contains(document.activeElement);
  config.filters.splice(index, 1);
  void persistFilters();
  renderFilters();
  if (hadFocusInTable) {
    const dels = tbody.querySelectorAll<HTMLElement>(".filter-del");
    (dels[Math.min(index - 1, dels.length - 1)] ?? addBtn).focus();
  }
}

// Test filtering ======================================================================================================

/**
 * Evaluate a test input against all filter rules and display the result.
 */
function evaluateTestFilter() {
  if (!testInput || !testResult) return;
  const input = testInput.value.trim();

  if (!input) {
    testResult.innerHTML = "";
    return;
  }

  if (!config?.filters || config.filters.length === 0) {
    testResult.innerHTML = "";
    return;
  }

  // Evaluate rules top-to-bottom; later rules override.
  let matchedAction: string | null = null;
  let matchedRule: FilterRule | null = null;
  let matchedIndex = -1;

  for (let i = 0; i < config.filters.length; i++) {
    const rule = config.filters[i];
    if (ruleMatches(rule, input)) {
      matchedAction = rule.action;
      matchedRule = rule;
      matchedIndex = i;
    }
  }

  if (matchedAction === null) {
    testResult.innerHTML = '<span class="match-rule">No matching rule</span>';
    return;
  }

  const actionClass = `match-${matchedAction}`;
  const actionText = actionLabel(matchedAction);
  const ruleDesc = matchedIndex === 0 ? "default rule" : `rule #${matchedIndex + 1}: ${matchedRule!.address}`;

  testResult.textContent = "";
  const actionSpan = document.createElement("span");
  actionSpan.className = actionClass;
  actionSpan.textContent = actionText;
  const ruleSpan = document.createElement("span");
  ruleSpan.className = "match-rule";
  ruleSpan.textContent = ` (matched ${ruleDesc})`;
  testResult.append(actionSpan, ruleSpan);
}

/**
 * Check if a filter rule matches the given input string.
 * @param {object} rule - A FilterRule object.
 * @param {string} input - The domain or IP to test.
 * @returns {boolean}
 */
function ruleMatches(rule: FilterRule, input: string): boolean {
  const addr = rule.address;

  switch (rule.matching) {
    case "exactly":
      return input === addr;

    case "with_subdomains":
      return input === addr || input.endsWith(`.${addr}`);

    case "wildcard":
      if (addr === "*") return true;
      // Convert glob pattern to regex: escape special regex chars, then
      // replace literal * with .* for glob semantics.
      try {
        const escaped = addr.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
        const pattern = `^${escaped.replace(/\*/g, ".*")}$`;
        return new RegExp(pattern, "i").test(input);
      } catch {
        return false;
      }

    case "subnet":
      return cidrMatch(input, addr);

    default:
      return false;
  }
}

/**
 * Check if an IP address matches a CIDR range.
 * Supports IPv4 only (e.g. "192.168.0.0/16").
 * @param {string} ip - The IP address to test.
 * @param {string} cidr - The CIDR notation string.
 * @returns {boolean}
 */
function cidrMatch(ip: string, cidr: string): boolean {
  const parts = cidr.split("/");
  if (parts.length !== 2) return false;

  const cidrIp = parseIpv4(parts[0]);
  const prefixLen = parseInt(parts[1], 10);
  const testIp = parseIpv4(ip);

  if (cidrIp === null || testIp === null) return false;
  if (Number.isNaN(prefixLen) || prefixLen < 0 || prefixLen > 32) return false;

  if (prefixLen === 0) return true;

  // Create mask: prefixLen leading 1-bits.
  // Use unsigned right shift to handle 32-bit properly.
  const mask = prefixLen === 32 ? 0xffffffff : ~((1 << (32 - prefixLen)) - 1);

  return (cidrIp & mask) === (testIp & mask);
}

/**
 * Parse an IPv4 address string into a 32-bit integer.
 * @param {string} ip - e.g. "192.168.1.1"
 * @returns {number|null} The 32-bit integer, or null if invalid.
 */
function parseIpv4(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;

  let result = 0;
  for (let i = 0; i < 4; i++) {
    const n = parseInt(parts[i], 10);
    if (Number.isNaN(n) || n < 0 || n > 255) return null;
    // Use unsigned arithmetic via >>> to avoid sign issues.
    result = ((result << 8) | n) >>> 0;
  }
  return result;
}

// Event handling ======================================================================================================

/** Handle clicks on the tbody (delegated). */
function onTbodyClick(e: MouseEvent) {
  const target = e.target as HTMLElement | null;
  if (!target) return;

  // Delete button. closest() instead of an identity check so the button
  // can gain child nodes without breaking delegation.
  const delBtn = target.closest(".filter-del");
  if (delBtn) {
    const tr = delBtn.closest("tr");
    if (tr) deleteRule(parseInt(tr.dataset.index ?? "", 10));
    return;
  }

  // Editable address cell.
  const addrTd = target.closest(".editable-addr") as HTMLTableCellElement | null;
  if (addrTd) {
    const tr = addrTd.closest("tr");
    if (tr) {
      startAddressEdit(addrTd, parseInt(tr.dataset.index ?? "", 10));
    }
    return;
  }

  // Editable cell (matching or action) — but not if it's a dropdown option
  // (those handle their own clicks).
  if (target.closest(".inline-dropdown")) return;

  const editableTd = target.closest(".editable-cell") as HTMLTableCellElement | null;
  if (editableTd) {
    const tr = editableTd.closest("tr");
    if (tr) {
      toggleDropdown(editableTd, parseInt(tr.dataset.index ?? "", 10));
    }
    return;
  }
}

/** Handle pointerdown on the tbody (delegated) for drag. */
function onTbodyPointerDown(e: PointerEvent) {
  const handle = (e.target as HTMLElement | null)?.closest(".drag-handle");
  if (!handle) return;

  const tr = handle.closest("tr");
  if (!tr || tr.classList.contains("no-drag")) return;

  const index = parseInt(tr.dataset.index ?? "", 10);
  if (Number.isNaN(index) || index <= 0) return; // Cannot drag default rule.

  // Commit any open edit FIRST (it re-renders), then re-resolve the row —
  // same detached-node hazard as startAddressEdit.
  const rule = config?.filters[index];
  commitOrCancelEditing();
  if (!rule || !config) return;
  const liveIndex = config.filters.indexOf(rule);
  if (liveIndex <= 0) return;
  const liveRow = tbody.querySelector<HTMLTableRowElement>(`tr[data-index="${liveIndex}"]`);
  if (!liveRow) return;

  startDrag(e, liveRow, liveIndex);
}

/** Close dropdown when clicking outside. */
function onDocumentClick(e: MouseEvent) {
  if (!openDropdown) return;
  const target = e.target as HTMLElement | null;
  // If the click was inside the dropdown or on its parent cell, let the
  // cell/option click handlers deal with it.
  if (target?.closest(".inline-dropdown")) return;
  if (target?.closest(".editable-cell") === openDropdown._td) return;
  closeDropdown();
}

// Initialization ======================================================================================================

/**
 * Set up event listeners for the filters section. Called once from main.ts.
 */
export function initFilters() {
  tbody.addEventListener("click", onTbodyClick);
  tbody.addEventListener("pointerdown", onTbodyPointerDown);
  addBtn.addEventListener("click", addRule);
  testInput.addEventListener("input", evaluateTestFilter);
  document.addEventListener("click", onDocumentClick);
}
