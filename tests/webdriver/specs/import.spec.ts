describe("Import", () => {
  it("import button is clickable", async () => {
    const btn = await $("#btn-import");
    expect(await btn.isClickable()).toBe(true);
  });

  // Note: Full import tests require file dialog interaction,
  // which is not easily automatable in WebDriverIO.
  // These are covered by the Rust-side unit tests in hole-common.
});
