const request = require("supertest");
const app = require("../server");

describe("Markdown Validator API", () => {
  it("validates a safe Markdown payload", async () => {
    const response = await request(app)
      .post("/validate")
      .send({ markdown: "# Title\n\nThis is an _example_ of Markdown." })
      .set("Content-Type", "application/json");

    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty("safe", true);
    expect(response.body).toHaveProperty("sanitized");
    expect(response.body).toHaveProperty("frontMatter", null);
  });

  it("rejects an empty Markdown payload", async () => {
    const response = await request(app)
      .post("/validate")
      .send({ markdown: "" })
      .set("Content-Type", "application/json");

    expect(response.status).toBe(400);
    expect(response.body).toHaveProperty("error");
  });

  it("rejects requests missing the 'markdown' field", async () => {
    const response = await request(app)
      .post("/validate")
      .send({})
      .set("Content-Type", "application/json");

    expect(response.status).toBe(400);
    expect(response.body).toHaveProperty("error");
  });

  it("flags unsafe Markdown", async () => {
    const response = await request(app)
      .post("/validate")
      .send({ markdown: "<script>alert('XSS')</script>" })
      .set("Content-Type", "application/json");

    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty("safe", false);
    expect(response.body).toHaveProperty("sanitized");
  });

  describe("Schema validation", () => {
    it("rejects unexpected fields in the request body", async () => {
      const response = await request(app)
        .post("/validate")
        .send({ markdown: "# ok", extra: "nope" })
        .set("Content-Type", "application/json");

      expect(response.status).toBe(400);
      expect(response.body.safe).toBe(false);
      expect(response.body.error).toBe("Invalid request");
      expect(Array.isArray(response.body.details)).toBe(true);
      expect(response.body.details[0]).toHaveProperty("message");
    });

    it("rejects a non-string markdown field", async () => {
      const response = await request(app)
        .post("/validate")
        .send({ markdown: 123 })
        .set("Content-Type", "application/json");

      expect(response.status).toBe(400);
      expect(response.body.error).toBe("Invalid request");
      expect(response.body.details).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ message: expect.stringMatching(/string/i) }),
        ])
      );
    });

    it("rejects markdown:null", async () => {
      const response = await request(app)
        .post("/validate")
        .send({ markdown: null })
        .set("Content-Type", "application/json");

      expect(response.status).toBe(400);
      expect(response.body.error).toBe("Invalid request");
    });

    it("rejects markdown as an array", async () => {
      const response = await request(app)
        .post("/validate")
        .send({ markdown: ["# hi"] })
        .set("Content-Type", "application/json");

      expect(response.status).toBe(400);
      expect(response.body.error).toBe("Invalid request");
    });

    it("reports the missing field in details when markdown is absent", async () => {
      const response = await request(app)
        .post("/validate")
        .send({})
        .set("Content-Type", "application/json");

      expect(response.status).toBe(400);
      expect(response.body.details).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ field: "/markdown" }),
        ])
      );
    });
  });

  it("rejects payloads larger than the 256kb body limit", async () => {
    const oversized = "a".repeat(300 * 1024);
    const response = await request(app)
      .post("/validate")
      .send({ markdown: oversized })
      .set("Content-Type", "application/json");

    expect(response.status).toBe(413);
  });

  describe("Health endpoint", () => {
    it("returns 200 with status ok", async () => {
      const response = await request(app).get("/health");

      expect(response.status).toBe(200);
      expect(response.body).toEqual({ status: "ok" });
    });
  });

  describe("URL schemes", () => {
    it("strips javascript: hrefs", async () => {
      const response = await request(app)
        .post("/validate")
        .send({ markdown: '<a href="javascript:alert(1)">x</a>' })
        .set("Content-Type", "application/json");

      expect(response.status).toBe(200);
      expect(response.body.safe).toBe(false);
      expect(response.body.sanitized.toLowerCase()).not.toContain("javascript:");
    });

    it("strips data: hrefs", async () => {
      const response = await request(app)
        .post("/validate")
        .send({ markdown: '<a href="data:text/html,hi">x</a>' })
        .set("Content-Type", "application/json");

      expect(response.status).toBe(200);
      expect(response.body.safe).toBe(false);
      expect(response.body.sanitized.toLowerCase()).not.toContain("data:");
    });

    it("strips vbscript: hrefs", async () => {
      const response = await request(app)
        .post("/validate")
        .send({ markdown: '<a href="vbscript:msgbox(1)">x</a>' })
        .set("Content-Type", "application/json");

      expect(response.status).toBe(200);
      expect(response.body.safe).toBe(false);
      expect(response.body.sanitized.toLowerCase()).not.toContain("vbscript:");
    });
  });

  describe("Front matter", () => {
    it("flags a front matter containing HTML as unsafe", async () => {
      const markdown = "---\ntitle: <script>alert(1)</script>\n---\n# hello\n";
      const response = await request(app)
        .post("/validate")
        .send({ markdown })
        .set("Content-Type", "application/json");

      expect(response.status).toBe(200);
      expect(response.body.safe).toBe(false);
      expect(response.body.frontMatter).toBe("title: <script>alert(1)</script>");
      expect(response.body.sanitized).not.toMatch(/<script/i);
      expect(response.body.sanitized).not.toMatch(/^---/);
    });

    it("accepts a front matter with legitimate YAML", async () => {
      const markdown = "---\ntitle: My post\ntags: [a, b]\n---\n# hello\n";
      const response = await request(app)
        .post("/validate")
        .send({ markdown })
        .set("Content-Type", "application/json");

      expect(response.status).toBe(200);
      expect(response.body.safe).toBe(true);
      expect(response.body.frontMatter).toBe("title: My post\ntags: [a, b]");
      expect(response.body.sanitized).not.toMatch(/^---/);
    });

    it("returns frontMatter:null when no front matter is present", async () => {
      const response = await request(app)
        .post("/validate")
        .send({ markdown: "# Just a body\n" })
        .set("Content-Type", "application/json");

      expect(response.status).toBe(200);
      expect(response.body.frontMatter).toBeNull();
    });

    it("flags as unsafe when the body is unsafe even with a clean front matter", async () => {
      const markdown = "---\ntitle: ok\n---\n<script>alert(1)</script>\n";
      const response = await request(app)
        .post("/validate")
        .send({ markdown })
        .set("Content-Type", "application/json");

      expect(response.status).toBe(200);
      expect(response.body.safe).toBe(false);
      expect(response.body.frontMatter).toBe("title: ok");
      expect(response.body.sanitized).not.toMatch(/<script/i);
    });

    it("does not re-inject the front matter into sanitized", async () => {
      const markdown = "---\ntitle: <iframe src=evil></iframe>\n---\n# hello\n";
      const response = await request(app)
        .post("/validate")
        .send({ markdown })
        .set("Content-Type", "application/json");

      expect(response.body.sanitized).not.toMatch(/<iframe/i);
      expect(response.body.sanitized).not.toMatch(/^---/);
    });
  });
});
