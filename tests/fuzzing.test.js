const fc = require("fast-check");
const request = require("supertest");
const app = require("../server");

const post = (markdown) =>
  request(app)
    .post("/validate")
    .send({ markdown })
    .set("Content-Type", "application/json");

const DANGEROUS_TAGS = [
  "<script",
  "<iframe",
  "<object",
  "<embed",
  "<form",
  "<meta",
  "<link",
];

// Inputs prefixed with "# " so they cannot accidentally form a YAML
// front-matter block — that lets each property isolate one concern.
const bodyOnly = fc
  .string({ minLength: 1, maxLength: 2048 })
  .map((s) => "# " + s);

describe("Property-based fuzzing", () => {
  it("sanitized never contains dangerous tags", async () => {
    await fc.assert(
      fc.asyncProperty(bodyOnly, async (markdown) => {
        const res = await post(markdown);
        if (res.status !== 200) return;
        const lower = (res.body.sanitized || "").toLowerCase();
        for (const tag of DANGEROUS_TAGS) {
          expect(lower).not.toContain(tag);
        }
      }),
      { numRuns: 200 }
    );
  });

  it("body sanitization is idempotent: sanitized output validates as safe", async () => {
    await fc.assert(
      fc.asyncProperty(bodyOnly, async (markdown) => {
        const first = await post(markdown);
        if (first.status !== 200) return;
        const sanitized = first.body.sanitized || "";
        // Skip empty results (the endpoint rejects empty markdown with 400).
        if (!sanitized.trim()) return;
        const second = await post(sanitized);
        if (second.status !== 200) return;
        expect(second.body.safe).toBe(true);
      }),
      { numRuns: 200 }
    );
  });

  it("front matter never bleeds into sanitized", async () => {
    const fmInput = fc
      .tuple(
        fc
          .string({ minLength: 1, maxLength: 200 })
          .filter((s) => !s.includes("---")),
        fc.string({ minLength: 1, maxLength: 200 })
      )
      .map(([fm, body]) => `---\n${fm}\n---\n# ${body}`);

    await fc.assert(
      fc.asyncProperty(fmInput, async (markdown) => {
        const res = await post(markdown);
        if (res.status !== 200) return;
        const sanitized = res.body.sanitized || "";
        expect(sanitized).not.toMatch(/^---/);
      }),
      { numRuns: 200 }
    );
  });

  it("front matter with HTML-like content flips safe to false", async () => {
    const htmlSnippet = fc.constantFrom(
      "<script>",
      "<iframe>",
      "<img>",
      "<a>",
      "<!--",
      "</p>"
    );
    const fmInput = fc
      .tuple(htmlSnippet, fc.string({ minLength: 0, maxLength: 100 }))
      .map(
        ([html, rest]) =>
          `---\nfield: ${html}${rest.replace(/[\r\n]/g, " ")}\n---\n# body\n`
      );

    await fc.assert(
      fc.asyncProperty(fmInput, async (markdown) => {
        const res = await post(markdown);
        if (res.status !== 200) return;
        expect(res.body.safe).toBe(false);
      }),
      { numRuns: 200 }
    );
  });
});
