// Shared roving-focus keyboard handling for custom dropdown menus
// (settings custom-selects and the filters table's inline dropdowns).
// Options carry tabindex="-1" and receive focus programmatically.

/**
 * Handle a keydown inside an open menu.
 * @param {KeyboardEvent} e - The keydown event.
 * @param {HTMLElement[]} options - Menu options in display order.
 * @param {Function} close - Closes the menu and returns focus to its
 *   trigger. For Tab, the default action then moves focus onward from
 *   the trigger, which is why Tab does not preventDefault.
 */
export function menuKeydown(e: KeyboardEvent, options: HTMLElement[], close: () => void): void {
  const i = options.indexOf(document.activeElement as HTMLElement);
  switch (e.key) {
    case "ArrowDown":
      e.preventDefault();
      options[Math.min(i + 1, options.length - 1)]?.focus();
      break;
    case "ArrowUp":
      e.preventDefault();
      options[Math.max(i - 1, 0)]?.focus();
      break;
    case "Home":
      e.preventDefault();
      options[0]?.focus();
      break;
    case "End":
      e.preventDefault();
      options[options.length - 1]?.focus();
      break;
    case "Escape":
      e.preventDefault();
      close();
      break;
    case "Tab":
      close();
      break;
  }
}
