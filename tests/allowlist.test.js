const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const request = require("supertest");
const { loadAllowlist, DEFAULT_ALLOWLIST } = require("../lib/allowlist");

const writeFixture = (name, content) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "allowlist-test-"));
  const file = path.join(dir, `${name}.json`);
  fs.writeFileSync(file, typeof content === "string" ? content : JSON.stringify(content));
  return file;
};

const removeFixture = (file) => {
  fs.rmSync(path.dirname(file), { recursive: true, force: true });
};

describe("loadAllowlist", () => {
  it("returns the default allowlist when no path is provided", () => {
    expect(loadAllowlist({ path: undefined })).toBe(DEFAULT_ALLOWLIST);
    expect(DEFAULT_ALLOWLIST.allowedTags).toContain("p");
    expect(DEFAULT_ALLOWLIST.allowedTags).not.toContain("script");
    expect(DEFAULT_ALLOWLIST.nonTextTags).toContain("xmp");
  });

  it("reads a JSON file when a path is provided", () => {
    const file = writeFixture("allowlist", {
      allowedTags: ["p", "em"],
      allowedAttributes: {},
      allowedSchemes: ["http"],
      disallowedTagsMode: "escape",
    });

    try {
      const loaded = loadAllowlist({ path: file });
      expect(loaded.allowedTags).toEqual(["p", "em"]);
      expect(loaded.disallowedTagsMode).toBe("escape");
      expect(loaded.nonTextTags).toContain("xmp");
    } finally {
      removeFixture(file);
    }
  });

  it("does not force xmp into nonTextTags when xmp is explicitly allowed", () => {
    const file = writeFixture("xmp-allowed", {
      allowedTags: ["xmp"],
      allowedAttributes: {},
      disallowedTagsMode: "discard",
    });

    try {
      const loaded = loadAllowlist({ path: file });
      expect(loaded.nonTextTags).toBeUndefined();
    } finally {
      removeFixture(file);
    }
  });

  it("throws when the file cannot be read", () => {
    expect(() =>
      loadAllowlist({ path: "/definitely/does/not/exist.json" })
    ).toThrow(/cannot read/);
  });

  it("throws on malformed JSON", () => {
    const file = writeFixture("bad", "not json");
    try {
      expect(() => loadAllowlist({ path: file })).toThrow(/invalid JSON/);
    } finally {
      removeFixture(file);
    }
  });

  it("throws when allowedTags is not an array", () => {
    const file = writeFixture("wrong-tags", { allowedTags: "not an array" });
    try {
      expect(() => loadAllowlist({ path: file })).toThrow(
        /allowedTags.*array/
      );
    } finally {
      removeFixture(file);
    }
  });

  it("throws when the top-level is not an object", () => {
    const file = writeFixture("array-top", ["p", "em"]);
    try {
      expect(() => loadAllowlist({ path: file })).toThrow(
        /top-level must be a JSON object/
      );
    } finally {
      removeFixture(file);
    }
  });
});

describe("ALLOWLIST_FILE integration", () => {
  let originalEnv;

  beforeEach(() => {
    originalEnv = process.env.ALLOWLIST_FILE;
  });

  afterEach(() => {
    if (originalEnv === undefined) delete process.env.ALLOWLIST_FILE;
    else process.env.ALLOWLIST_FILE = originalEnv;
    jest.resetModules();
  });

  it("a custom allowlist relaxes sanitization when set via env", async () => {
    const file = writeFixture("relaxed", {
      allowedTags: ["iframe"],
      allowedAttributes: { iframe: ["src"] },
      allowedSchemes: ["https"],
      disallowedTagsMode: "discard",
    });
    process.env.ALLOWLIST_FILE = file;

    let app;
    jest.isolateModules(() => {
      app = require("../server");
    });

    try {
      const res = await request(app)
        .post("/validate")
        .send({ markdown: '<iframe src="https://example.com"></iframe>' })
        .set("Content-Type", "application/json");

      expect(res.body.safe).toBe(true);
      expect(res.body.sanitized).toContain("<iframe");
    } finally {
      removeFixture(file);
    }
  });
});
