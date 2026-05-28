// Country-flag DOM helper. Writes a `flag-icons` CSS class
// (`.fi.fi-<cc>`) and a title attribute onto a passed-in element. The
// loaded flag-icons stylesheet (imported from ui/main.ts) does the
// actual SVG rendering.
//
// Class names are required lowercase by flag-icons' convention
// (.fi-us, not .fi-US). Titles are uppercase by ISO 3166-1 convention.
//
// Treats `"??"`, empty, null/undefined, and shape-invalid inputs as
// "unknown": applies the package's built-in `fi-xx` placeholder
// (xx.svg ships as a "?" glyph) so the badge always shows something
// visible, even when the backend returns garbage.

const ISO_ALPHA2 = /^[A-Za-z]{2}$/;

export function setCountryFlag(el: HTMLElement, cc: string | null | undefined): void {
  // Strip any prior fi-* class. flag-icons owns the .fi- prefix on this
  // element; nothing else in the project applies fi-* classes.
  for (const cls of [...el.classList]) {
    if (cls.startsWith("fi-")) el.classList.remove(cls);
  }
  if (!cc || cc === "??" || !ISO_ALPHA2.test(cc)) {
    el.classList.add("fi-xx");
    el.title = "Unknown";
    return;
  }
  el.classList.add(`fi-${cc.toLowerCase()}`);
  el.title = cc.toUpperCase();
}
