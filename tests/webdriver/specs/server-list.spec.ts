describe("Server List", () => {
  it("shows empty message when no servers", async () => {
    const emptyMsg = await $("#empty-message");
    await emptyMsg.waitForDisplayed();
    expect(await emptyMsg.isDisplayed()).toBe(true);
  });

  it("server table exists", async () => {
    const table = await $("#server-table");
    expect(await table.isExisting()).toBe(true);
  });

  it("table has correct column headers", async () => {
    const headers = await $$("#server-table thead th");
    const texts = await Promise.all(headers.map((h) => h.getText()));
    expect(texts).toContain("Name");
    expect(texts).toContain("Address");
    expect(texts).toContain("Method");
    expect(texts).toContain("Plugin");
  });
});
