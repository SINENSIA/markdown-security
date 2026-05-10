const request = require("supertest");

describe("Rate limiting (RATE_LIMIT_RPM)", () => {
  let originalEnv;

  beforeEach(() => {
    originalEnv = process.env.RATE_LIMIT_RPM;
  });

  afterEach(() => {
    if (originalEnv === undefined) delete process.env.RATE_LIMIT_RPM;
    else process.env.RATE_LIMIT_RPM = originalEnv;
    jest.resetModules();
  });

  const loadApp = () => {
    let app;
    jest.isolateModules(() => {
      app = require("../server");
    });
    return app;
  };

  it("does not rate-limit when RATE_LIMIT_RPM is unset", async () => {
    delete process.env.RATE_LIMIT_RPM;
    const app = loadApp();

    for (let i = 0; i < 5; i++) {
      const res = await request(app)
        .post("/validate")
        .send({ markdown: "# hi" })
        .set("Content-Type", "application/json");
      expect(res.status).toBe(200);
    }
  });

  it("returns 429 once the per-minute limit is exceeded on /validate", async () => {
    process.env.RATE_LIMIT_RPM = "2";
    const app = loadApp();

    const results = [];
    for (let i = 0; i < 3; i++) {
      results.push(
        await request(app)
          .post("/validate")
          .send({ markdown: "# hi" })
          .set("Content-Type", "application/json")
      );
    }

    expect(results[0].status).toBe(200);
    expect(results[1].status).toBe(200);
    expect(results[2].status).toBe(429);
    expect(results[2].body).toEqual({
      safe: false,
      error: "Rate limit exceeded",
    });
    expect(results[2].headers).toHaveProperty("retry-after");
  });

  it("does not rate-limit /health", async () => {
    process.env.RATE_LIMIT_RPM = "1";
    const app = loadApp();

    for (let i = 0; i < 5; i++) {
      const res = await request(app).get("/health");
      expect(res.status).toBe(200);
    }
  });

  it("does not rate-limit /openapi.json", async () => {
    process.env.RATE_LIMIT_RPM = "1";
    const app = loadApp();

    for (let i = 0; i < 5; i++) {
      const res = await request(app).get("/openapi.json");
      expect(res.status).toBe(200);
    }
  });

  it.each(["0", "-1", "1.5", "abc", ""])(
    "rejects RATE_LIMIT_RPM=%p at startup",
    (value) => {
      if (value === "") {
        // Empty string is treated as unset; loading succeeds with no limiter.
        process.env.RATE_LIMIT_RPM = value;
        expect(() => loadApp()).not.toThrow();
        return;
      }
      process.env.RATE_LIMIT_RPM = value;
      expect(() => loadApp()).toThrow(/RATE_LIMIT_RPM/);
    }
  );
});
