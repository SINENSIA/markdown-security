const request = require("supertest");
const app = require("../server"); // Importa la app sin levantar el servidor

describe("Markdown Validator API", () => {
  it("Debe validar correctamente un Markdown seguro", async () => {
    const response = await request(app)
      .post("/validate")
      .send({ markdown: "# Título\n\nEste es un _ejemplo_ de Markdown." })
      .set("Content-Type", "application/json");

    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty("safe", true);
    expect(response.body).toHaveProperty("sanitized");
    expect(response.body).toHaveProperty("frontMatter", null);
  });

  it("Debe manejar correctamente un Markdown vacío", async () => {
    const response = await request(app)
      .post("/validate")
      .send({ markdown: "" })
      .set("Content-Type", "application/json");

    expect(response.status).toBe(400);
    expect(response.body).toHaveProperty("error");
  });

  it("Debe devolver un error si el campo 'markdown' falta en el body", async () => {
    const response = await request(app)
      .post("/validate")
      .send({})
      .set("Content-Type", "application/json");

    expect(response.status).toBe(400);
    expect(response.body).toHaveProperty("error");
  });

  it("Debe detectar Markdown inseguro", async () => {
    const response = await request(app)
      .post("/validate")
      .send({ markdown: "<script>alert('XSS')</script>" })
      .set("Content-Type", "application/json");

    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty("safe", false);
    expect(response.body).toHaveProperty("sanitized");
  });

  describe("Front matter", () => {
    it("Marca como inseguro un front-matter que contiene HTML", async () => {
      const markdown = "---\ntitle: <script>alert(1)</script>\n---\n# hello\n";
      const response = await request(app)
        .post("/validate")
        .send({ markdown })
        .set("Content-Type", "application/json");

      expect(response.status).toBe(200);
      expect(response.body.safe).toBe(false);
      expect(response.body.frontMatter).toBe("title: <script>alert(1)</script>");
      // El campo sanitized NO debe contener el front-matter ni el script.
      expect(response.body.sanitized).not.toMatch(/<script/i);
      expect(response.body.sanitized).not.toMatch(/^---/);
    });

    it("Acepta un front-matter con YAML legítimo", async () => {
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

    it("Devuelve frontMatter:null cuando no hay front-matter", async () => {
      const response = await request(app)
        .post("/validate")
        .send({ markdown: "# Just a body\n" })
        .set("Content-Type", "application/json");

      expect(response.status).toBe(200);
      expect(response.body.frontMatter).toBeNull();
    });

    it("Marca como inseguro si el body es inseguro aunque el front-matter sea limpio", async () => {
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

    it("No reinyecta el front-matter dentro de sanitized", async () => {
      // Regresión del bug previo: el front-matter se concatenaba al sanitized.
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
