import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { env } from "cloudflare:workers";
import { decodeProtectedHeader, exportJWK, generateKeyPair, importJWK } from "jose";
import { describe, expect, it } from "vitest";
import { createAuth } from "../src/auth";
import { revokeSigningKey, rotateSigningKey } from "../src/jwk";
import { codeChallenge, createTestOAuthClient, dispatch, sessionCookie } from "./support";

const v1 = { version: 1, value: "jwk-rotation-v1-secret-1234567890abcdef" } as const;
const v2 = { version: 2, value: "jwk-rotation-v2-secret-1234567890abcdef" } as const;

async function insertOldKey(id: string, createdAt: Date): Promise<{ id: string; privateKey: CryptoKey }> {
  const pair = await generateKeyPair("ES256", { extractable: true });
  const privateKeyJSON = JSON.stringify(await exportJWK(pair.privateKey));
  const encrypted = await symmetricEncrypt({
    key: { keys: new Map([[v1.version, v1.value]]), currentVersion: v1.version },
    data: privateKeyJSON,
  });
  await env.DB.prepare("INSERT INTO jwks (id, publicKey, privateKey, createdAt, expiresAt) VALUES (?, ?, ?, ?, ?)")
    .bind(
      id,
      JSON.stringify(await exportJWK(pair.publicKey)),
      JSON.stringify(encrypted),
      createdAt.toISOString(),
      new Date(createdAt.getTime() + 60 * 60 * 1000).toISOString(),
    )
    .run();
  return { id, privateKey: pair.privateKey };
}

describe("operator JWK rotation", () => {
  it("creates a v2 key while v1 remains decryptable and published during grace", async () => {
    const now = new Date();
    const oldId = `jwk-old-${crypto.randomUUID()}`;
    await insertOldKey(oldId, new Date(now.getTime() - 1000));
    const rotated = await rotateSigningKey(env.DB, [v2, v1], now);
    const old = await env.DB.prepare("SELECT expiresAt FROM jwks WHERE id = ?")
      .bind(oldId)
      .first<{ expiresAt: string }>();
    expect(new Date(old?.expiresAt ?? 0).getTime()).toBe(now.getTime());

    const decrypted = await symmetricDecrypt({
      key: { keys: new Map([[v2.version, v2.value]]), currentVersion: v2.version },
      data: JSON.parse(rotated.privateKey),
    });
    await importJWK(JSON.parse(decrypted), "ES256");
    const jwks = (
      await env.DB.prepare("SELECT id FROM jwks WHERE id IN (?, ?) ORDER BY id")
        .bind(oldId, rotated.id)
        .all<{ id: string }>()
    ).results;
    expect(jwks.map((row) => row.id)).toEqual(expect.arrayContaining([oldId, rotated.id]));
  });

  it("uses the newly encrypted key for signing after the transition", async () => {
    const now = new Date();
    const oldId = `jwk-sign-${crypto.randomUUID()}`;
    await insertOldKey(oldId, new Date(now.getTime() - 1000));
    const rotated = await rotateSigningKey(env.DB, [v2, v1], now);
    const rotationEnv = { ...env, BETTER_AUTH_SECRETS: `${v2.version}:${v2.value}` };
    const client = await createTestOAuthClient({
      name: `JWK rotation ${crypto.randomUUID()}`,
      redirectURI: "https://jwk-rotation.example/callback",
      postLogoutRedirectURI: "https://jwk-rotation.example/signed-out",
    });
    const cookie = await sessionCookie({
      userId: `jwk-sign-user-${crypto.randomUUID()}`,
      email: `jwk-sign-${crypto.randomUUID()}@example.com`,
      token: `jwk-sign-token-${crypto.randomUUID()}`,
      sessionId: `jwk-sign-session-${crypto.randomUUID()}`,
      name: "JWK signing user",
    });
    const verifier = `jwk-sign-verifier-${crypto.randomUUID()}-abcdefghijklmnopqrstuvwxyz`;
    const authorizationURL = new URL("https://auth.example.invalid/oauth2/authorize");
    authorizationURL.search = new URLSearchParams({
      client_id: client.client_id,
      response_type: "code",
      redirect_uri: "https://jwk-rotation.example/callback",
      scope: "openid profile email",
      state: "jwk-sign-state",
      nonce: "jwk-sign-nonce",
      code_challenge: await codeChallenge(verifier),
      code_challenge_method: "S256",
    }).toString();
    const authorization = await dispatch(new Request(authorizationURL, { headers: { cookie }, redirect: "manual" }));
    const code = new URL(authorization.headers.get("location") ?? "https://invalid.example/").searchParams.get("code");
    if (!code) throw new Error("JWK signing authorization did not return a code");
    if (!client.client_secret) throw new Error("JWK signing client secret was not returned");
    const response = await createAuth(rotationEnv).handler(
      new Request("https://auth.example.invalid/oauth2/token", {
        method: "POST",
        headers: {
          authorization: `Basic ${btoa(`${client.client_id}:${client.client_secret}`)}`,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: "https://jwk-rotation.example/callback",
          code_verifier: verifier,
        }),
      }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { id_token?: string };
    expect(body.id_token).toBeTypeOf("string");
    expect(decodeProtectedHeader(body.id_token ?? "").kid).toBe(rotated.id);
    expect(oldId).not.toBe(rotated.id);
  });

  it("does not revive a key whose grace expiry is already in the past", async () => {
    const now = new Date();
    const oldId = `jwk-expired-${crypto.randomUUID()}`;
    await insertOldKey(oldId, new Date(now.getTime() - 3 * 24 * 60 * 60 * 1000));
    const oldExpiry = new Date(now.getTime() - 2 * 24 * 60 * 60 * 1000).toISOString();
    await env.DB.prepare("UPDATE jwks SET expiresAt = ? WHERE id = ?").bind(oldExpiry, oldId).run();
    await rotateSigningKey(env.DB, [v2, v1], now);
    const old = await env.DB.prepare("SELECT expiresAt FROM jwks WHERE id = ?")
      .bind(oldId)
      .first<{ expiresAt: string }>();
    expect(old?.expiresAt).toBe(oldExpiry);
  });

  it("rolls back insert and retirement together when the D1 batch fails", async () => {
    const now = new Date();
    const oldId = `jwk-atomic-${crypto.randomUUID()}`;
    await insertOldKey(oldId, new Date(now.getTime() - 1000));
    const failingBatch = async (statements: D1PreparedStatement[]) =>
      env.DB.batch([...statements, env.DB.prepare("UPDATE jwks SET missing_column = 1 WHERE id = ?").bind(oldId)]);
    await expect(rotateSigningKey(env.DB, [v2, v1], now, failingBatch)).rejects.toThrow();
    const old = await env.DB.prepare("SELECT expiresAt FROM jwks WHERE id = ?")
      .bind(oldId)
      .first<{ expiresAt: string }>();
    expect(new Date(old?.expiresAt ?? 0).getTime()).toBeGreaterThan(now.getTime());
    const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM jwks WHERE id LIKE 'jwk-atomic-%'").first<{
      count: number;
    }>();
    expect(count?.count).toBe(1);
  });

  it("fails closed when multiple keys share Better Auth's newest createdAt", async () => {
    const now = new Date();
    const tied = await insertOldKey(`jwk-tied-a-${crypto.randomUUID()}`, now);
    const tiedId = `jwk-tied-b-${crypto.randomUUID()}`;
    const pair = await generateKeyPair("ES256", { extractable: true });
    await env.DB.prepare("INSERT INTO jwks (id, publicKey, privateKey, createdAt, expiresAt) VALUES (?, ?, ?, ?, ?)")
      .bind(
        tiedId,
        JSON.stringify(await exportJWK(pair.publicKey)),
        JSON.stringify(await exportJWK(pair.privateKey)),
        now.toISOString(),
        new Date(now.getTime() + 60 * 60 * 1000).toISOString(),
      )
      .run();
    expect(await revokeSigningKey(env.DB, tiedId, now)).toBe(false);
    expect(await revokeSigningKey(env.DB, tied.id, now)).toBe(false);
    const rows = await env.DB.prepare("SELECT id, revokedAt FROM jwks WHERE id IN (?, ?) ORDER BY id")
      .bind(tied.id, tiedId)
      .all<{ id: string; revokedAt: string | null }>();
    expect(rows.results.every((row) => row.revokedAt === null)).toBe(true);
  });

  it("serializes concurrent rotations so only the last same-timestamp key remains active", async () => {
    const now = new Date();
    const [first, second] = await Promise.all([
      rotateSigningKey(env.DB, [v2, v1], now),
      rotateSigningKey(env.DB, [v2, v1], now),
    ]);
    const rows = await env.DB.prepare("SELECT id, expiresAt FROM jwks WHERE id IN (?, ?) ORDER BY id")
      .bind(first.id, second.id)
      .all<{ id: string; expiresAt: string }>();
    expect(rows.results).toHaveLength(2);
    expect(rows.results.filter((row) => new Date(row.expiresAt).getTime() > now.getTime())).toHaveLength(1);
  });
});
