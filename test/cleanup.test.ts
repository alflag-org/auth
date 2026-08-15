import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { cleanupExpiredVerification } from "../src/cleanup";

describe("bounded verification cleanup", () => {
  it("deletes exact expired rows in batches and leaves future rows", async () => {
    const now = new Date("2030-01-01T00:00:00.000Z");
    const expired = ["cleanup-expired-a", "cleanup-expired-b", "cleanup-expired-c"];
    for (const [index, id] of expired.entries()) {
      await env.DB.prepare(
        "INSERT INTO verification (id, identifier, value, expiresAt, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)",
      )
        .bind(
          id,
          id,
          `value-${id}`,
          new Date(now.getTime() - (index + 1) * 1000).toISOString(),
          now.toISOString(),
          now.toISOString(),
        )
        .run();
    }
    await env.DB.prepare(
      "INSERT INTO verification (id, identifier, value, expiresAt, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)",
    )
      .bind(
        "cleanup-future",
        "cleanup-future",
        "future-value",
        new Date(now.getTime() + 60_000).toISOString(),
        now.toISOString(),
        now.toISOString(),
      )
      .run();

    expect(await cleanupExpiredVerification(env.DB, now, 2)).toBe(2);
    expect(await cleanupExpiredVerification(env.DB, now, 2)).toBe(1);
    const remaining = await env.DB.prepare("SELECT id FROM verification WHERE id LIKE 'cleanup-%' ORDER BY id").all<{
      id: string;
    }>();
    expect(remaining.results).toEqual([{ id: "cleanup-future" }]);
  });

  it("drains expired access tokens, sessions, and retired JWKs while preserving active rows", async () => {
    const now = new Date("2030-01-01T00:00:00.000Z");
    const expired = new Date(now.getTime() - 1_000).toISOString();
    const future = new Date(now.getTime() + 60_000).toISOString();
    const retired = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000 - 1_000).toISOString();
    await env.DB.prepare(
      "INSERT OR IGNORE INTO user (id, name, email, emailVerified, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)",
    )
      .bind("cleanup-user", "Cleanup User", "cleanup-user@example.com", 1, now.toISOString(), now.toISOString())
      .run();
    await env.DB.prepare("INSERT OR IGNORE INTO oauthClient (id, clientId, redirectUris) VALUES (?, ?, ?)")
      .bind("cleanup-client-row", "cleanup-client", '["https://cleanup.example/callback"]')
      .run();
    await env.DB.prepare(
      "INSERT OR REPLACE INTO session (id, expiresAt, token, createdAt, updatedAt, userId) VALUES (?, ?, ?, ?, ?, ?)",
    )
      .bind(
        "cleanup-expired-session",
        expired,
        "cleanup-expired-session-token",
        now.toISOString(),
        now.toISOString(),
        "cleanup-user",
      )
      .run();
    await env.DB.prepare(
      "INSERT OR REPLACE INTO session (id, expiresAt, token, createdAt, updatedAt, userId) VALUES (?, ?, ?, ?, ?, ?)",
    )
      .bind(
        "cleanup-active-session",
        future,
        "cleanup-active-session-token",
        now.toISOString(),
        now.toISOString(),
        "cleanup-user",
      )
      .run();
    await env.DB.prepare(
      "INSERT OR REPLACE INTO oauthAccessToken (id, token, clientId, expiresAt, createdAt, scopes) VALUES (?, ?, ?, ?, ?, ?)",
    )
      .bind(
        "cleanup-expired-access",
        "cleanup-expired-access-token",
        "cleanup-client",
        expired,
        now.toISOString(),
        "[]",
      )
      .run();
    await env.DB.prepare(
      "INSERT OR REPLACE INTO oauthAccessToken (id, token, clientId, expiresAt, createdAt, scopes) VALUES (?, ?, ?, ?, ?, ?)",
    )
      .bind("cleanup-active-access", "cleanup-active-access-token", "cleanup-client", future, now.toISOString(), "[]")
      .run();
    await env.DB.prepare(
      "INSERT OR REPLACE INTO jwks (id, publicKey, privateKey, createdAt, expiresAt) VALUES (?, ?, ?, ?, ?)",
    )
      .bind("cleanup-retired-jwk", '{"kty":"EC"}', '{"kty":"EC"}', now.toISOString(), retired)
      .run();
    await env.DB.prepare(
      "INSERT OR REPLACE INTO jwks (id, publicKey, privateKey, createdAt, expiresAt) VALUES (?, ?, ?, ?, ?)",
    )
      .bind("cleanup-active-jwk", '{"kty":"EC"}', '{"kty":"EC"}', new Date(now.getTime() + 1_000).toISOString(), future)
      .run();

    await cleanupExpiredVerification(env.DB, now, 10);

    for (const [table, id] of [
      ["session", "cleanup-expired-session"],
      ["oauthAccessToken", "cleanup-expired-access"],
      ["jwks", "cleanup-retired-jwk"],
    ] as const) {
      const row = await env.DB.prepare(`SELECT id FROM ${table} WHERE id = ?`).bind(id).first();
      expect(row, `${table}:${id}`).toBeNull();
    }
    for (const [table, id] of [
      ["session", "cleanup-active-session"],
      ["oauthAccessToken", "cleanup-active-access"],
      ["jwks", "cleanup-active-jwk"],
    ] as const) {
      const row = await env.DB.prepare(`SELECT id FROM ${table} WHERE id = ?`).bind(id).first();
      expect(row, `${table}:${id}`).not.toBeNull();
    }
  });
});
