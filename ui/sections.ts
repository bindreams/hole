// Collapsible section slide animation.
//
// Each `.section-hdr` toggles its next sibling `.section-clip`. The content
// slides up behind the header divider line (translateY + opacity), and
// max-height animates to/from 0 for smooth height collapse.

/**
 * Toggle a single section between expanded and collapsed states.
 * @param {HTMLElement} hdr - The `.section-hdr` element that was clicked.
 */
function toggleSection(hdr: HTMLElement) {
  const tri = hdr.querySelector(".tri");
  const clip = hdr.nextElementSibling as HTMLElement | null;
  if (!clip?.classList.contains("section-clip")) return;
  const body = clip.querySelector(".section-body") as HTMLElement | null;
  if (!body) return;

  const isCollapsed = clip.classList.contains("collapsed");

  if (isCollapsed) {
    // Expand ----------------------------------------------------------------------------------------------------------
    clip.classList.remove("collapsed");
    clip.style.overflow = "hidden";

    const h = body.scrollHeight;
    clip.style.maxHeight = "0px";
    body.style.transform = "translateY(-100%)";
    body.style.opacity = "0";

    // Force layout so the starting values are applied before we transition.
    clip.offsetHeight; // eslint-disable-line no-unused-expressions

    clip.style.transition = "max-height 0.3s ease";
    body.style.transition = "transform 0.3s ease, opacity 0.2s ease";
    clip.style.maxHeight = `${h}px`;
    body.style.transform = "translateY(0)";
    body.style.opacity = "1";
    tri?.classList.remove("collapsed");

    const cleanup = (e: Event) => {
      // Only react to the max-height transition (not child transitions).
      if (e.target !== clip) return;
      clip.style.maxHeight = "";
      clip.style.overflow = "";
      clip.style.transition = "";
      body.style.transition = "";
      body.style.transform = "";
      body.style.opacity = "";
      clip.removeEventListener("transitionend", cleanup);
    };
    clip.addEventListener("transitionend", cleanup);
  } else {
    // Collapse --------------------------------------------------------------------------------------------------------
    const h = body.scrollHeight;
    clip.style.overflow = "hidden";
    clip.style.maxHeight = `${h}px`;

    clip.offsetHeight; // eslint-disable-line no-unused-expressions

    clip.style.transition = "max-height 0.3s ease";
    body.style.transition = "transform 0.3s ease, opacity 0.2s ease";
    clip.style.maxHeight = "0px";
    body.style.transform = "translateY(-100%)";
    body.style.opacity = "0";
    tri?.classList.add("collapsed");

    const cleanup = (e: Event) => {
      if (e.target !== clip) return;
      clip.classList.add("collapsed");
      clip.style.maxHeight = "";
      clip.style.overflow = "";
      clip.style.transition = "";
      body.style.transition = "";
      body.style.transform = "";
      body.style.opacity = "";
      clip.removeEventListener("transitionend", cleanup);
    };
    clip.addEventListener("transitionend", cleanup);
  }
}

/** Attach click handlers to all section headers. */
export function initSections() {
  for (const hdr of document.querySelectorAll<HTMLElement>(".section-hdr")) {
    hdr.addEventListener("click", () => toggleSection(hdr));
  }
}
