import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import {
  admitAuthorizationRequest,
  bindAuthorizationAdmission,
  claimAuthorizationAdmission,
  consumeAuthorizationAdmission,
  oauthQueryDigest,
  releaseAuthorizationAdmission,
} from "../src/admission";

describe("authorization admission capacity", () => {
  it("keeps a global cap atomic across different source addresses", async () => {
    await env.DB.prepare("DELETE FROM oauthAuthorizationAdmission").run();
    const now = new Date("2030-01-01T00:00:00.000Z");
    const [first, second] = await Promise.all([
      admitAuthorizationRequest(
        env.DB,
        new Request("https://auth.example.invalid/oauth2/authorize", { headers: { "cf-connecting-ip": "192.0.2.1" } }),
        "client-a",
        now,
        { globalCap: 1, perSourceClientCap: 1 },
      ),
      admitAuthorizationRequest(
        env.DB,
        new Request("https://auth.example.invalid/oauth2/authorize", { headers: { "cf-connecting-ip": "192.0.2.2" } }),
        "client-b",
        now,
        { globalCap: 1, perSourceClientCap: 1 },
      ),
    ]);
    expect([first, second].filter(Boolean)).toHaveLength(1);
    const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM oauthAuthorizationAdmission").first<{
      count: number;
    }>();
    expect(count?.count).toBe(1);
  });

  it("bounds expired admission purge and fails closed while backlog remains", async () => {
    await env.DB.prepare("DELETE FROM oauthAuthorizationAdmission").run();
    const expired = "2029-12-31T23:59:00.000Z";
    const statements = Array.from({ length: 60 }, (_, index) =>
      env.DB.prepare(
        "INSERT INTO oauthAuthorizationAdmission (id, sourceKey, clientId, expiresAt, createdAt) VALUES (?, ?, ?, ?, ?)",
      ).bind(`test-admission:${index}`, `192.0.2.${index}`, `client-${index}`, expired, expired),
    );
    await env.DB.batch(statements);
    const admitted = await admitAuthorizationRequest(
      env.DB,
      new Request("https://auth.example.invalid/oauth2/authorize", { headers: { "cf-connecting-ip": "192.0.2.99" } }),
      "client-new",
      new Date("2030-01-01T00:00:00.000Z"),
      { globalCap: 1, perSourceClientCap: 1 },
    );
    expect(admitted).toBeNull();
    const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM oauthAuthorizationAdmission").first<{
      count: number;
    }>();
    expect(count?.count).toBe(10);
  });

  it("binds and consumes one exact continuation per admission without cross-admission replay", async () => {
    await env.DB.prepare("DELETE FROM oauthAuthorizationAdmission").run();
    const now = new Date("2030-01-01T00:00:00.000Z");
    const request = new Request("https://auth.example.invalid/oauth2/authorize", {
      headers: { "cf-connecting-ip": "192.0.2.50" },
    });
    const first = await admitAuthorizationRequest(env.DB, request, "client-replay", now, {
      globalCap: 10,
      perSourceClientCap: 10,
    });
    const second = await admitAuthorizationRequest(env.DB, request, "client-replay", now, {
      globalCap: 10,
      perSourceClientCap: 10,
    });
    if (!first || !second) throw new Error("admission fixtures were not created");
    const query = "client_id=client-replay&sig=signature&exp=1893456300&ba_iat=1893456000000";
    const digest = await oauthQueryDigest(query);
    if (!digest) throw new Error("continuation digest was not created");
    expect(await bindAuthorizationAdmission(env.DB, first.id, digest, now)).toBe(true);
    expect(await bindAuthorizationAdmission(env.DB, second.id, digest, now)).toBe(true);
    expect(await claimAuthorizationAdmission(env.DB, `${digest}-invalid`, "client-replay", "invalid", now)).toBeNull();
    const [claimedA, claimedB] = await Promise.all([
      claimAuthorizationAdmission(env.DB, digest, "client-replay", "state-a", now),
      claimAuthorizationAdmission(env.DB, digest, "client-replay", "state-b", now),
    ]);
    expect([claimedA, claimedB].filter(Boolean)).toHaveLength(1);
    const claimed = claimedA ?? claimedB;
    if (!claimed) throw new Error("continuation was not claimed");
    expect(await consumeAuthorizationAdmission(env.DB, claimed.id, digest, claimedA ? "state-a" : "state-b", now)).toBe(
      true,
    );
    expect(await consumeAuthorizationAdmission(env.DB, claimed.id, digest, claimedA ? "state-a" : "state-b", now)).toBe(
      false,
    );
    const remaining = claimed.id === first.id ? second.id : first.id;
    await releaseAuthorizationAdmission(env.DB, remaining);
    const replacement = await admitAuthorizationRequest(env.DB, request, "client-replay", now, {
      globalCap: 1,
      perSourceClientCap: 1,
    });
    expect(replacement).not.toBeNull();
    if (replacement) await releaseAuthorizationAdmission(env.DB, replacement.id);
    await releaseAuthorizationAdmission(env.DB, claimed.id);
  });
});
