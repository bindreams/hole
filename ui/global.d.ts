// Side-effect CSS imports (e.g. `import "overlayscrollbars/overlayscrollbars.css"`)
// have no runtime type to declare, but TypeScript 6+ rejects them without an
// explicit module declaration. Vite handles the actual CSS bundling.
declare module "*.css";

// Vite `?raw` asset imports (used by markup tests to assert on the
// static index.html) have no ambient type without vite/client.
declare module "*.html?raw" {
  const content: string;
  export default content;
}
