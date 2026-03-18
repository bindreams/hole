describe("Settings Window", () => {
  it("has correct title", async () => {
    const title = await browser.getTitle();
    expect(title).toBe("Hole Settings");
  });

  it("shows empty server list on first launch", async () => {
    const emptyMsg = await $("#empty-message");
    await emptyMsg.waitForDisplayed();
    expect(await emptyMsg.isDisplayed()).toBe(true);
  });

  it("shows default local port 4073", async () => {
    const portInput = await $("#local-port");
    expect(await portInput.getValue()).toBe("4073");
  });

  it("has import button", async () => {
    const btn = await $("#btn-import");
    expect(await btn.isDisplayed()).toBe(true);
    expect(await btn.getText()).toBe("Import...");
  });

  it("has save button", async () => {
    const btn = await $("#btn-save");
    expect(await btn.isDisplayed()).toBe(true);
    expect(await btn.getText()).toBe("Save");
  });

  it("shows daemon status badge", async () => {
    const badge = await $("#status");
    expect(await badge.isDisplayed()).toBe(true);
  });
});
