import { describe, expect, it } from "vitest";
import { env } from "cloudflare:workers";
import { exportJWK, generateKeyPair } from "jose";
import { cleanupExpiredVerification } from "../src/cleanup";
import { oidcMetadata } from "../src/metadata";
import {
  ACCESS_TOKEN_TTL_SECONDS,
  AUTHORIZATION_CODE_TTL_SECONDS,
  ID_TOKEN_TTL_SECONDS,
  KEY_GRACE_TTL_SECONDS,
  KEY_ROTATION_TTL_SECONDS,
  SESSION_TTL_SECONDS,
  parseIssuer,
  parseVersionedSecrets,
} from "../src/config";
import { dispatch, dispatchWithEnvironment } from "./support/app";

describe("OIDC surface", () => {
  it("publishes the constrained authorization-server metadata", async () => {
    const response = await dispatch(new Request("https://auth.example.invalid/.well-known/openid-configuration"));
    expect(response.status).toBe(200);
    const metadata = (await response.json()) as Record<string, unknown>;
    expect(metadata).toEqual(oidcMetadata("https://auth.example.invalid"));
    expect(metadata.grant_types_supported).toEqual(["authorization_code"]);
    expect(metadata.token_endpoint_auth_methods_supported).toEqual(["client_secret_basic"]);
    expect(metadata.code_challenge_methods_supported).toEqual(["S256"]);
  });

  it("keeps endpoint request gates closed for unsupported protocol paths", async () => {
    const unknownClient = await dispatch(
      new Request(
        "https://auth.example.invalid/oauth2/authorize?client_id=unknown&response_type=code&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&scope=openid&state=s&nonce=n&code_challenge=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG&code_challenge_method=S256",
      ),
    );
    expect(unknownClient.status).toBe(400);

    const dynamicRegistration = await dispatch(
      new Request("https://auth.example.invalid/oauth2/register", { method: "POST" }),
    );
    expect(dynamicRegistration.status).toBe(404);

    const missingBasic = await dispatch(new Request("https://auth.example.invalid/oauth2/token", { method: "POST" }));
    expect(missingBasic.status).toBe(401);
  });

  it("rejects unsupported authorization requests before Better Auth", async () => {
    const missingNonce = await dispatch(
      new Request(
        "https://auth.example.invalid/oauth2/authorize?client_id=unknown&response_type=code&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&scope=openid&state=s",
      ),
    );
    expect(missingNonce.status).toBe(400);

    const forbiddenScope = await dispatch(
      new Request(
        "https://auth.example.invalid/oauth2/authorize?client_id=unknown&response_type=code&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&scope=openid%20offline_access&state=s&nonce=n",
      ),
    );
    expect(forbiddenScope.status).toBe(400);
  });

  it("fails closed before token processing when the durable rate-limit binding is absent or denies", async () => {
    const request = new Request("https://auth.example.invalid/oauth2/token", {
      method: "POST",
      headers: { "cf-connecting-ip": "198.51.100.9" },
    });
    const missing = await dispatchWithEnvironment(request, {
      ...env,
      OAUTH_TOKEN_RATE_LIMITER: undefined,
    } as unknown as Env);
    expect(missing.status).toBe(503);
    const denied = await dispatchWithEnvironment(request, {
      ...env,
      OAUTH_TOKEN_RATE_LIMITER: { limit: async () => ({ success: false }) },
    } as Env);
    expect(denied.status).toBe(503);
  });

  it("fails closed before end-session URL, D1, or JWT processing when its limiter is absent or denies", async () => {
    const request = new Request("https://auth.example.invalid/oauth2/end-session?id_token_hint=not-verified", {
      headers: { "cf-connecting-ip": "198.51.100.10" },
    });
    const missing = await dispatchWithEnvironment(request, {
      ...env,
      OAUTH_END_SESSION_RATE_LIMITER: undefined,
    } as unknown as Env);
    expect(missing.status).toBe(503);
    const denied = await dispatchWithEnvironment(request, {
      ...env,
      OAUTH_END_SESSION_RATE_LIMITER: { limit: async () => ({ success: false }) },
    } as Env);
    expect(denied.status).toBe(503);
  });
});

describe("configuration", () => {
  it("accepts only canonical HTTPS origins for the issuer", () => {
    expect(parseIssuer("https://auth.example.invalid")).toBe("https://auth.example.invalid");
    expect(parseIssuer("https://auth.example.invalid/")).toBe("https://auth.example.invalid");
    for (const value of [
      "http://auth.example.invalid",
      "https://user:password@auth.example.invalid",
      "https://auth.example.invalid/path",
      "https://auth.example.invalid?query=1",
      "https://auth.example.invalid#fragment",
      "not-an-url",
    ]) {
      expect(() => parseIssuer(value), value).toThrow("AUTH_ISSUER must be an HTTPS origin");
    }
  });

  it("parses versioned secrets with newest-first rotation semantics", () => {
    expect(
      parseVersionedSecrets(
        "2:new-secret-1234567890abcdef1234567890abcdef,1:old-secret-1234567890abcdef1234567890abcdef",
      ),
    ).toEqual([
      { version: 2, value: "new-secret-1234567890abcdef1234567890abcdef" },
      { version: 1, value: "old-secret-1234567890abcdef1234567890abcdef" },
    ]);
    expect(() => parseVersionedSecrets("1:short")).toThrow();
    expect(() =>
      parseVersionedSecrets(
        "1:duplicate-1234567890abcdef1234567890abcdef,1:duplicate-1234567890abcdef1234567890abcdef",
      ),
    ).toThrow();
    expect(() =>
      parseVersionedSecrets(
        "1:old-secret-1234567890abcdef1234567890abcdef,2:new-secret-1234567890abcdef1234567890abcdef",
      ),
    ).toThrow();
    expect(
      parseVersionedSecrets(
        "3:new-secret-1234567890abcdef1234567890abcdef,1:old-secret-1234567890abcdef1234567890abcdef",
      ),
    ).toEqual([
      { version: 3, value: "new-secret-1234567890abcdef1234567890abcdef" },
      { version: 1, value: "old-secret-1234567890abcdef1234567890abcdef" },
    ]);
  });

  it("keeps token, session, and ES256 key rotation policy exact", async () => {
    expect(AUTHORIZATION_CODE_TTL_SECONDS).toBe(60);
    expect(ID_TOKEN_TTL_SECONDS).toBe(300);
    expect(ACCESS_TOKEN_TTL_SECONDS).toBe(600);
    expect(SESSION_TTL_SECONDS).toBe(8 * 60 * 60);
    expect(KEY_ROTATION_TTL_SECONDS).toBe(90 * 24 * 60 * 60);
    expect(KEY_GRACE_TTL_SECONDS).toBe(30 * 24 * 60 * 60);
    const response = await dispatch(new Request("https://auth.example.invalid/jwks"));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { keys: Array<Record<string, unknown>> };
    expect(body.keys.length).toBeGreaterThan(0);
    expect(body.keys.every((key) => key.kty === "EC" && key.crv === "P-256" && key.alg === "ES256")).toBe(true);
  });

  it("does not republish a revoked key when cleanup interleaves JWKS reads", async () => {
    const oldId = `jwks-race-old-${crypto.randomUUID()}`;
    const activeId = `jwks-race-active-${crypto.randomUUID()}`;
    const oldKey = await generateKeyPair("ES256", { extractable: true });
    const activeKey = await generateKeyPair("ES256", { extractable: true });
    const now = new Date();
    const oldCreatedAt = new Date(now.getTime() - 60_000).toISOString();
    const oldExpiresAt = new Date(now.getTime() - 1_000).toISOString();
    const activeExpiresAt = new Date(now.getTime() + KEY_ROTATION_TTL_SECONDS * 1000).toISOString();
    await env.DB.prepare(
      "INSERT INTO jwks (id, publicKey, privateKey, createdAt, expiresAt, revokedAt) VALUES (?, ?, ?, ?, ?, ?)",
    )
      .bind(
        oldId,
        JSON.stringify(await exportJWK(oldKey.publicKey)),
        JSON.stringify(await exportJWK(oldKey.privateKey)),
        oldCreatedAt,
        oldExpiresAt,
        now.toISOString(),
      )
      .run();
    await env.DB.prepare("INSERT INTO jwks (id, publicKey, privateKey, createdAt, expiresAt) VALUES (?, ?, ?, ?, ?)")
      .bind(
        activeId,
        JSON.stringify(await exportJWK(activeKey.publicKey)),
        JSON.stringify(await exportJWK(activeKey.privateKey)),
        now.toISOString(),
        activeExpiresAt,
      )
      .run();

    let interleaved = false;
    const database = new Proxy(env.DB, {
      get(target, property, receiver) {
        if (property !== "prepare") return Reflect.get(target, property, receiver);
        return (query: string) => {
          const statement = target.prepare(query);
          const isJWKSRead =
            query.includes("SELECT id FROM jwks WHERE revokedAt IS NOT NULL") ||
            query.includes("SELECT id, publicKey, expiresAt FROM jwks WHERE revokedAt IS NULL");
          if (!isJWKSRead || interleaved) return statement;
          const wrapStatement = (statementTarget: D1PreparedStatement): D1PreparedStatement =>
            new Proxy(statementTarget, {
              get(statementTarget, method, statementReceiver) {
                if (method === "bind") {
                  const bind = statementTarget.bind as (...values: unknown[]) => D1PreparedStatement;
                  return (...args: unknown[]) => wrapStatement(bind.call(statementTarget, ...args));
                }
                if (method !== "all") return Reflect.get(statementTarget, method, statementReceiver);
                return async (...args: unknown[]) => {
                  interleaved = true;
                  await cleanupExpiredVerification(env.DB, now, 500, 1);
                  const all = statementTarget.all as (...values: unknown[]) => Promise<D1Result<unknown>>;
                  return all.call(statementTarget, ...args);
                };
              },
            });
          return wrapStatement(statement);
        };
      },
    });
    const response = await dispatchWithEnvironment(new Request("https://auth.example.invalid/jwks"), {
      ...env,
      DB: database as unknown as D1Database,
    } as Env);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/json");
    const body = (await response.json()) as { keys: Array<{ kid?: string }> };
    expect(interleaved).toBe(true);
    expect(body.keys.map((key) => key.kid)).not.toContain(oldId);
    expect(body.keys.map((key) => key.kid)).toContain(activeId);
  });

  it("publishes only supported public ES256 key material", async () => {
    const unsupportedId = `jwks-unsupported-${crypto.randomUUID()}`;
    const privateId = `jwks-private-${crypto.randomUUID()}`;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + KEY_ROTATION_TTL_SECONDS * 1000).toISOString();
    await env.DB.prepare("INSERT INTO jwks (id, publicKey, privateKey, createdAt, expiresAt) VALUES (?, ?, ?, ?, ?)")
      .bind(
        unsupportedId,
        JSON.stringify({ kty: "RSA", n: "modulus", e: "AQAB" }),
        "not-used",
        now.toISOString(),
        expiresAt,
      )
      .run();
    await env.DB.prepare("INSERT INTO jwks (id, publicKey, privateKey, createdAt, expiresAt) VALUES (?, ?, ?, ?, ?)")
      .bind(
        privateId,
        JSON.stringify({ kty: "EC", crv: "P-256", x: "x", y: "y", d: "private" }),
        "not-used",
        now.toISOString(),
        expiresAt,
      )
      .run();
    const response = await dispatch(new Request("https://auth.example.invalid/jwks"));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { keys: Array<Record<string, unknown>> };
    expect(body.keys.every((key) => !("d" in key) && key.kty === "EC" && key.alg === "ES256")).toBe(true);
    expect(body.keys.map((key) => key.kid)).not.toEqual(expect.arrayContaining([unsupportedId, privateId]));
  });

  it("fails closed when Better Auth contains malformed public key material", async () => {
    const malformedId = `jwks-malformed-${crypto.randomUUID()}`;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + KEY_ROTATION_TTL_SECONDS * 1000).toISOString();
    await env.DB.prepare("INSERT INTO jwks (id, publicKey, privateKey, createdAt, expiresAt) VALUES (?, ?, ?, ?, ?)")
      .bind(malformedId, "not-json", "not-used", now.toISOString(), expiresAt)
      .run();
    try {
      const response = await dispatch(new Request("https://auth.example.invalid/jwks"));
      expect(response.ok).toBe(false);
      expect(response.status).toBeGreaterThanOrEqual(500);
    } finally {
      await env.DB.prepare("DELETE FROM jwks WHERE id = ?").bind(malformedId).run();
    }
  });
});
