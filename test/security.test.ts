import request from "supertest";
import jwt from "jsonwebtoken";
import app from "../src/server";
import { createClient } from "redis";

const SECRET = process.env.JWT_SECRET || "fallback_secret";
const ISSUER = "lab-api";
const AUDIENCE = "lab-app";

// Token gerado para OUTRO propósito (ex: token de redefinição de senha ou de outra API)
const maliciousToken = jwt.sign({ username: "hacker" }, SECRET, {
  issuer: "outra-api", // Emitido por outro sistema
  audience: "admin-panel",
});

describe("Laboratório de Segurança JWT", () => {
  let validToken: string;

  beforeAll(async () => {
    // Fazer login para pegar um token válido real
    const response = await request(app)
      .post("/login")
      .send({ username: "admin", password: "1234" });

    validToken = response.body.token;
  });

  describe("Cenário 1: Injeção de Token de Outro Escopo (Claims)", () => {
    it("VULNERABILIDADE: O middleware inseguro DEVE aceitar o token de outro sistema", async () => {
      const res = await request(app)
        .get("/dados-inseguros")
        .set("Authorization", `Bearer ${maliciousToken}`);

      // O atacante consegue entrar porque a assinatura bate, mesmo o token sendo de outro lugar!
      expect(res.status).toBe(200);
      expect(res.body.user.username).toBe("hacker");
    });

    it("DEFESA: O middleware seguro DEVE rejeitar o token por issuer inválido", async () => {
      const res = await request(app)
        .get("/dados-sensiveis")
        .set("Authorization", `Bearer ${maliciousToken}`);

      // Bloqueado na porta. O log interno vai registrar "jwt issuer invalid".
      expect(res.status).toBe(401);
      expect(res.body.error).toBe("Token inválido ou expirado");
    });
  });

  describe("Cenário 2: Reuso de Token Revogado", () => {
    it("Ação prévia: Realizar o logout para revogar o token válido", async () => {
      const res = await request(app)
        .post("/logout")
        .set("Authorization", `Bearer ${validToken}`);

      expect(res.status).toBe(200);
      expect(res.body.message).toBe("Logout realizado. Token revogado.");
    });

    it("VULNERABILIDADE: O middleware inseguro DEVE permitir o acesso com o token revogado", async () => {
      const res = await request(app)
        .get("/dados-inseguros")
        .set("Authorization", `Bearer ${validToken}`);

      // O atacante ou usuário mal intencionado continua acessando o sistema pós-logout!
      expect(res.status).toBe(200);
    });

    it("DEFESA: O middleware seguro DEVE rejeitar o acesso com o token revogado", async () => {
      const res = await request(app)
        .get("/dados-sensiveis")
        .set("Authorization", `Bearer ${validToken}`);

      // Bloqueado pelo Redis.
      expect(res.status).toBe(401);
      expect(res.body.error).toBe("Token inválido ou expirado");
    });
  });
});
