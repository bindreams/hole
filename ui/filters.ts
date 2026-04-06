// Filters section: filter rules table with in-place editing, drag reorder,
// test filtering, add/delete rules.

import { config, saveConfig } from "./main";
import type { FilterRule } from "./types";

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

  closeDropdown();
  editingIndex = -1;
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
    divAddr.appendChild(handle);

    const addrSpan = document.createElement("span");
    addrSpan.className = "filter-addr";
    addrSpan.textContent = rule.address;
    divAddr.appendChild(addrSpan);

    tdAddr.appendChild(divAddr);
    tr.appendChild(tdAddr);

    // Matching cell ---------------------------------------------------------------------------------------------------
    const tdMatch = document.createElement("td");
    tdMatch.className = isDefault ? "" : "editable-cell";
    tdMatch.dataset.field = "matching";

    const divMatch = document.createElement("div");
    divMatch.className = "cp";

    const matchSpan = document.createElement("span");
    matchSpan.className = "filter-match";
    matchSpan.textContent = matchLabel(rule.matching);
    divMatch.appendChild(matchSpan);

    if (!isDefault) {
      const chev = document.createElement("span");
      chev.className = "chev";
      chev.textContent = "\u25BE";
      divMatch.appendChild(chev);
    }

    tdMatch.appendChild(divMatch);
    tr.appendChild(tdMatch);

    // Action cell -----------------------------------------------------------------------------------------------------
    const tdAction = document.createElement("td");
    tdAction.className = `${isDefault ? "action-cell" : "action-cell editable-cell"} ${rule.action}`;
    tdAction.dataset.field = "action";

    const divAction = document.createElement("div");
    divAction.className = "cp";
    divAction.textContent = actionLabel(rule.action);

    if (!isDefault) {
      const chev = document.createElement("span");
      chev.className = "chev";
      chev.textContent = "\u25BE";
      divAction.appendChild(chev);
    }

    tdAction.appendChild(divAction);
    tr.appendChild(tdAction);

    // Delete cell -----------------------------------------------------------------------------------------------------
    const tdDel = document.createElement("td");
    tdDel.className = "del-cell";

    if (!isDefault) {
      const delSpan = document.createElement("span");
      delSpan.className = "filter-del";
      delSpan.textContent = "\u2715";
      tdDel.appendChild(delSpan);
    } else {
      // Default wildcard rule — show a lock icon to indicate it cannot be deleted.
      // Inline SVG (monochrome, currentColor, evenodd) so it matches the rest of
      // the UI's icon style instead of rendering as a colorful 🔒 emoji.
      // innerHTML with a static SVG literal is XSS-safe (no user input) and the
      // HTML parser correctly creates SVG-namespaced elements when parsing <svg>
      // inside a non-SVG parent.
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
  commitOrCancelEditing(); // Close any other active edit.

  editingIndex = index;
  const addrSpan = td.querySelector(".filter-addr");
  if (!addrSpan) return;

  const original = addrSpan.textContent;

  const input = document.createElement("input");
  input.className = "inline-input";
  input.type = "text";
  input.value = original;

  addrSpan.replaceWith(input);
  input.focus();
  input.select();

  function commit() {
    if (editingIndex !== index) return; // Already committed or cancelled.
    editingIndex = -1;

    const newValue = input.value.trim();
    if (!newValue) {
      // Empty address — remove the rule (it was never valid).
      config?.filters.splice(index, 1);
      saveConfig();
    } else if (newValue !== original) {
      if (config) config.filters[index].address = newValue;
      saveConfig();
    }
    renderFilters();
  }

  function cancel() {
    if (editingIndex !== index) return;
    editingIndex = -1;
    // If the original address was empty (new rule), remove it.
    if (!original && config?.filters[index]) {
      config.filters.splice(index, 1);
    }
    renderFilters();
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

/** If there's an active address edit, commit it synchronously. */
function commitOrCancelEditing() {
  if (editingIndex < 0) return;
  const index = editingIndex;
  const input = tbody.querySelector<HTMLInputElement>(".inline-input");
  editingIndex = -1; // Clear first so the blur handler becomes a no-op.
  if (input && config?.filters[index]) {
    const value = input.value.trim();
    if (value && value !== config.filters[index].address) {
      config.filters[index].address = value;
      saveConfig();
    }
  }
  renderFilters();
}

// Inline dropdowns ====================================================================================================

/** Close the currently open dropdown. */
function closeDropdown() {
  if (openDropdown) {
    openDropdown.remove();
    openDropdown = null;
  }
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
  dropdown._td = td; // Tag so we can detect toggle clicks.

  for (const opt of options) {
    const div = document.createElement("div");
    div.className = `inline-dropdown-opt${opt.value === currentValue ? " selected" : ""}`;
    div.textContent = opt.label;
    div.dataset.value = opt.value;

    div.addEventListener("click", (e) => {
      e.stopPropagation();
      if (!config) return;
      if (field === "matching") {
        config.filters[index].matching = opt.value as FilterRule["matching"];
      } else {
        config.filters[index].action = opt.value as FilterRule["action"];
      }
      saveConfig();
      closeDropdown();
      renderFilters();
    });

    dropdown.appendChild(div);
  }

  td.appendChild(dropdown);
  openDropdown = dropdown;
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

/**
 * Start dragging a row.
 * @param {PointerEvent} e - The pointerdown event on the drag handle.
 * @param {HTMLTableRowElement} row - The row being dragged.
 * @param {number} index - The filter rule index.
 */
function startDrag(e: PointerEvent, row: HTMLTableRowElement, index: number) {
  e.preventDefault();
  closeDropdown();
  commitOrCancelEditing();

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
    saveConfig();
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
  config.filters.splice(index, 1);
  saveConfig();
  renderFilters();
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

  // Delete button.
  if (target.classList.contains("filter-del")) {
    const tr = target.closest("tr");
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

  startDrag(e, tr, index);
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
