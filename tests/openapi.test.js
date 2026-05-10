const request = require("supertest");
const app = require("../server");
const pkg = require("../package.json");

describe("OpenAPI specification", () => {
  it("serves the spec at GET /openapi.json", async () => {
    const res = await request(app).get("/openapi.json");

    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/application\/json/);
    expect(res.body.openapi).toBe("3.1.0");
    expect(res.body.info.title).toBe("markdown-security");
  });

  it("describes /validate, /health and /openapi.json", async () => {
    const res = await request(app).get("/openapi.json");

    expect(Object.keys(res.body.paths).sort()).toEqual([
      "/health",
      "/openapi.json",
      "/validate",
    ]);
    expect(res.body.paths["/validate"]).toHaveProperty("post");
    expect(res.body.paths["/health"]).toHaveProperty("get");
  });

  it("matches the documented response shape of /validate", async () => {
    const res = await request(app).get("/openapi.json");
    const props =
      res.body.components.schemas.ValidateResponse.properties;

    expect(Object.keys(props).sort()).toEqual([
      "frontMatter",
      "message",
      "safe",
      "sanitized",
    ]);
  });

  it("declares /validate 200, 400 and 413 responses", async () => {
    const res = await request(app).get("/openapi.json");
    const responses = res.body.paths["/validate"].post.responses;

    expect(Object.keys(responses).sort()).toEqual(["200", "400", "413"]);
  });

  it("keeps info.version in sync with package.json", async () => {
    const res = await request(app).get("/openapi.json");

    expect(res.body.info.version).toBe(pkg.version);
  });
});
