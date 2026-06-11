import { beforeEach, describe, expect, it, vi } from "vitest";
import { menuKeydown } from "./menu-keys";

let options: HTMLElement[];
let close: ReturnType<typeof vi.fn<() => void>>;

function press(key: string): KeyboardEvent {
  const e = new KeyboardEvent("keydown", { key, bubbles: true, cancelable: true });
  (document.activeElement ?? document.body).dispatchEvent(e);
  menuKeydown(e, options, close);
  return e;
}

beforeEach(() => {
  document.body.innerHTML = `
    <div id="menu">
      <button type="button" tabindex="-1">One</button>
      <button type="button" tabindex="-1">Two</button>
      <button type="button" tabindex="-1">Three</button>
    </div>
  `;
  options = [...document.querySelectorAll<HTMLElement>("#menu button")];
  close = vi.fn<() => void>();
});

describe("menuKeydown", () => {
  it("ArrowDown moves focus to the next option and stops at the last", () => {
    options[0].focus();
    press("ArrowDown");
    expect(document.activeElement).toBe(options[1]);
    press("ArrowDown");
    press("ArrowDown");
    expect(document.activeElement).toBe(options[2]);
  });

  it("ArrowUp moves focus to the previous option and stops at the first", () => {
    options[2].focus();
    press("ArrowUp");
    expect(document.activeElement).toBe(options[1]);
    press("ArrowUp");
    press("ArrowUp");
    expect(document.activeElement).toBe(options[0]);
  });

  it("Home and End jump to the first and last options", () => {
    options[1].focus();
    press("End");
    expect(document.activeElement).toBe(options[2]);
    press("Home");
    expect(document.activeElement).toBe(options[0]);
  });

  it("arrow keys prevent default scrolling", () => {
    options[0].focus();
    expect(press("ArrowDown").defaultPrevented).toBe(true);
    expect(press("ArrowUp").defaultPrevented).toBe(true);
    expect(press("Home").defaultPrevented).toBe(true);
    expect(press("End").defaultPrevented).toBe(true);
  });

  it("Escape closes (preventing default), Tab closes without preventing default", () => {
    options[0].focus();
    expect(press("Escape").defaultPrevented).toBe(true);
    expect(close).toHaveBeenCalledTimes(1);
    expect(press("Tab").defaultPrevented).toBe(false);
    expect(close).toHaveBeenCalledTimes(2);
  });

  it("ignores unrelated keys", () => {
    options[0].focus();
    press("a");
    expect(document.activeElement).toBe(options[0]);
    expect(close).not.toHaveBeenCalled();
  });
});
