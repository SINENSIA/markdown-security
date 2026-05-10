const request = require("supertest");
const app = require("../server");

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

describe("Request ID", () => {
  it("echoes a valid x-request-id back to the client", async () => {
    const id = "trace-abc123_456.7";
    const res = await request(app)
      .post("/validate")
      .set("x-request-id", id)
      .send({ markdown: "# hi" });

    expect(res.headers["x-request-id"]).toBe(id);
  });

  it("generates a UUID when no x-request-id is provided", async () => {
    const res = await request(app)
      .post("/validate")
      .send({ markdown: "# hi" });

    expect(res.headers["x-request-id"]).toMatch(UUID_RE);
  });

  it("rejects malformed x-request-id and generates a fresh one", async () => {
    const res = await request(app)
      .post("/validate")
      .set("x-request-id", "has space and @ and #")
      .send({ markdown: "# hi" });

    expect(res.headers["x-request-id"]).not.toContain("has space");
    expect(res.headers["x-request-id"]).toMatch(UUID_RE);
  });

  it("exposes x-request-id on /health", async () => {
    const res = await request(app).get("/health");

    expect(res.headers["x-request-id"]).toMatch(UUID_RE);
  });
});
