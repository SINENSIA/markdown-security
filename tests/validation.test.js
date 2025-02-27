const request = require("supertest");
const app = require("../server"); // Importa la app sin levantar el servidor

describe("Markdown Validator API", () => {
  it("Debe validar correctamente un Markdown seguro", async () => {
    const response = await request(app)
      .post("/validate")
      .send({ markdown: "# Título\n\nEste es un _ejemplo_ de Markdown." })
      .set("Content-Type", "application/json");

    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty("safe", true); // Verificar que el Markdown es seguro
    expect(response.body).toHaveProperty("sanitized"); // Verificar que devuelve la versión sanitizada
  });

  it("Debe manejar correctamente un Markdown vacío", async () => {
    const response = await request(app)
      .post("/validate")
      .send({ markdown: "" })
      .set("Content-Type", "application/json");

    expect(response.status).toBe(400); // Esperamos un error 400
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
      .send({ markdown: "<script>alert('XSS')</script>" }) // Markdown con potencial XSS
      .set("Content-Type", "application/json");

    expect(response.status).toBe(200); // Ahora debe responder con 200
    expect(response.body).toHaveProperty("safe", false); // No debe ser seguro
    expect(response.body).toHaveProperty("sanitized"); // Debe devolver la versión limpia
  });

});
