import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { createAuth } from "../src/auth";
import operator from "../src/operator";
import { dispatch } from "./support";

const issuer = "https://auth.example.invalid";

async function seedOperatorCookie(): Promise<Headers> {
  const now = new Date();
  const token = "operator-api-session-token";
  await env.DB.prepare(
    "INSERT OR REPLACE INTO user (id, name, email, emailVerified, image, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?, ?)",
  )
    .bind("operator-api-user", "Operator", "operator@example.invalid", 1, null, now.toISOString(), now.toISOString())
    .run();
  await env.DB.prepare(
    "INSERT OR REPLACE INTO session (id, expiresAt, token, createdAt, updatedAt, ipAddress, userAgent, userId) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(
      "operator-api-session",
      new Date(now.getTime() + 60 * 60 * 1000).toISOString(),
      token,
      now.toISOString(),
      now.toISOString(),
      null,
      "operator-test",
      "operator-api-user",
    )
    .run();
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.BETTER_AUTH_SECRETS.split(":", 2)[1]),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(token));
  return new Headers({
    cookie: `__Host-better-auth.session_token=${token}.${btoa(String.fromCharCode(...new Uint8Array(signature)))}`,
  });
}

async function production(request: Request): Promise<Response> {
  return dispatch(request);
}

describe("operator boundary", () => {
  it("does not expose operator or production admin routes", async () => {
    for (const path of [
      "/__operator/health",
      "/__operator/client-create",
      "/__operator/jwk-rotate",
      "/__operator/jwk-revoke",
      "/admin/oauth2/create-client",
    ]) {
      const response = await production(
        new Request(`${issuer}${path}`, { method: path.includes("create") ? "POST" : "GET" }),
      );
      expect(response.status, path).toBe(404);
    }
    const operatorCookie = await seedOperatorCookie();
    await expect(
      createAuth(env).api.adminCreateOAuthClient({
        headers: operatorCookie,
        body: {
          client_name: "Denied Client",
          redirect_uris: ["https://operator.example/callback"],
          post_logout_redirect_uris: ["https://operator.example/signed-out"],
        },
      }),
    ).rejects.toMatchObject({ statusCode: 401 });
    await env.DB.prepare("DELETE FROM session WHERE id = ?").bind("operator-api-session").run();
  });

  it("creates only fixed confidential web authorization-code clients through the operator Worker", async () => {
    const operatorNonce = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg";
    const operatorEnv: OperatorEnv = {
      DB: env.DB,
      AUTH_ISSUER: "https://auth.example.invalid",
      OPERATOR_NONCE: operatorNonce,
      OPERATOR_ACTION: "client-create",
      BETTER_AUTH_SECRETS: env.BETTER_AUTH_SECRETS,
      GOOGLE_CLIENT_ID: env.GOOGLE_CLIENT_ID,
      GOOGLE_CLIENT_SECRET: env.GOOGLE_CLIENT_SECRET,
      ALLOWED_GOOGLE_DOMAIN: env.ALLOWED_GOOGLE_DOMAIN,
    };
    const placeholderContext = createExecutionContext();
    const placeholderResponse = await operator.fetch(
      new Request("https://operator.example/__operator/client-create", {
        method: "POST",
        headers: { "content-type": "application/json", "x-operator-nonce": "set-by-client-create" },
        body: JSON.stringify({
          client_name: "Placeholder Client",
          redirect_uris: ["https://operator.example/callback"],
          post_logout_redirect_uris: ["https://operator.example/signed-out"],
        }),
      }),
      { ...operatorEnv, OPERATOR_NONCE: "set-by-client-create" },
      placeholderContext,
    );
    await waitOnExecutionContext(placeholderContext);
    expect(placeholderResponse.status).toBe(404);
    const wrongNonceContext = createExecutionContext();
    const wrongNonceResponse = await operator.fetch(
      new Request("https://operator.example/__operator/client-create", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-operator-nonce": "1111111111111111111111111111111111111111111",
        },
        body: JSON.stringify({
          client_name: "Wrong Nonce Client",
          redirect_uris: ["https://operator.example/callback"],
          post_logout_redirect_uris: ["https://operator.example/signed-out"],
        }),
      }),
      operatorEnv,
      wrongNonceContext,
    );
    await waitOnExecutionContext(wrongNonceContext);
    expect(wrongNonceResponse.status).toBe(404);
    const context = createExecutionContext();
    const response = await operator.fetch(
      new Request("https://operator.example/__operator/client-create", {
        method: "POST",
        headers: { "content-type": "application/json", "x-operator-nonce": operatorEnv.OPERATOR_NONCE },
        body: JSON.stringify({
          client_name: "Operator Test Client",
          redirect_uris: ["https://operator.example/callback"],
          post_logout_redirect_uris: ["https://operator.example/signed-out"],
        }),
      }),
      operatorEnv,
      context,
    );
    await waitOnExecutionContext(context);
    expect(response.status).toBe(200);
    const result = (await response.json()) as {
      client_id: string;
      client_secret: string;
      client_secret_expires_at: number;
    };
    expect(result.client_id).toBeTypeOf("string");
    expect(result.client_secret).toBeTypeOf("string");
    expect(result.client_secret_expires_at).toBe(0);
    const stored = await env.DB.prepare(
      "SELECT tokenEndpointAuthMethod, grantTypes, responseTypes, type, requirePKCE, enableEndSession, scopes FROM oauthClient WHERE clientId = ?",
    )
      .bind(result.client_id)
      .first<{
        tokenEndpointAuthMethod: string;
        grantTypes: string;
        responseTypes: string;
        type: string;
        requirePKCE: number;
        enableEndSession: number;
        scopes: string;
      }>();
    expect(stored).toEqual({
      tokenEndpointAuthMethod: "client_secret_basic",
      grantTypes: '["authorization_code"]',
      responseTypes: '["code"]',
      type: "web",
      requirePKCE: 1,
      enableEndSession: 1,
      scopes: '["openid","profile","email"]',
    });
    const operatorSessions = await env.DB.prepare("SELECT id FROM session WHERE userId = ?")
      .bind("local-operator")
      .all();
    expect(operatorSessions.results).toEqual([]);
  });

  it("rejects authorization-response parameters while allowing unrelated redirect queries", async () => {
    const operatorNonce = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg";
    const operatorEnv: OperatorEnv = {
      DB: env.DB,
      AUTH_ISSUER: issuer,
      OPERATOR_NONCE: operatorNonce,
      OPERATOR_ACTION: "client-create",
      BETTER_AUTH_SECRETS: env.BETTER_AUTH_SECRETS,
      GOOGLE_CLIENT_ID: env.GOOGLE_CLIENT_ID,
      GOOGLE_CLIENT_SECRET: env.GOOGLE_CLIENT_SECRET,
      ALLOWED_GOOGLE_DOMAIN: env.ALLOWED_GOOGLE_DOMAIN,
    };
    const request = (redirectURI: string, postLogoutRedirectURI: string) =>
      new Request("https://operator.example/__operator/client-create", {
        method: "POST",
        headers: { "content-type": "application/json", "x-operator-nonce": operatorNonce },
        body: JSON.stringify({
          client_name: "Redirect validation",
          redirect_uris: [redirectURI],
          post_logout_redirect_uris: [postLogoutRedirectURI],
        }),
      });
    for (const parameter of [
      "code",
      "state",
      "iss",
      "error",
      "error_description",
      "error_uri",
      "session_state",
      "response",
    ]) {
      const context = createExecutionContext();
      const response = await operator.fetch(
        request(`https://operator.example/callback?${parameter}=attacker`, "https://operator.example/signed-out"),
        operatorEnv,
        context,
      );
      await waitOnExecutionContext(context);
      expect(response.status, parameter).toBe(400);
    }
    const validContext = createExecutionContext();
    const valid = await operator.fetch(
      request("https://operator.example/callback?tenant=alpha", "https://operator.example/signed-out?return=1"),
      operatorEnv,
      validContext,
    );
    await waitOnExecutionContext(validContext);
    expect(valid.status).toBe(200);
    const invalidLogoutContext = createExecutionContext();
    const invalidLogout = await operator.fetch(
      request("https://operator.example/callback", "https://operator.example/signed-out?state=attacker"),
      operatorEnv,
      invalidLogoutContext,
    );
    await waitOnExecutionContext(invalidLogoutContext);
    expect(invalidLogout.status).toBe(400);
  });

  it("keeps JWK rotation behind the operator nonce and an empty request body", async () => {
    const operatorNonce = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg";
    const operatorEnv: OperatorEnv = {
      DB: env.DB,
      AUTH_ISSUER: issuer,
      OPERATOR_NONCE: operatorNonce,
      OPERATOR_ACTION: "jwk-rotate",
      BETTER_AUTH_SECRETS: `2:operator-rotation-v2-secret-1234567890abcdef,1:${env.BETTER_AUTH_SECRETS.split(":", 2)[1] ?? "operator-rotation-v1-secret-1234567890abcdef"}`,
      GOOGLE_CLIENT_ID: env.GOOGLE_CLIENT_ID,
      GOOGLE_CLIENT_SECRET: env.GOOGLE_CLIENT_SECRET,
      ALLOWED_GOOGLE_DOMAIN: env.ALLOWED_GOOGLE_DOMAIN,
    };
    const wrongContext = createExecutionContext();
    const wrong = await operator.fetch(
      new Request("https://operator.example/__operator/jwk-rotate", {
        method: "POST",
        headers: { "content-length": "0", "x-operator-nonce": "wrong" },
      }),
      operatorEnv,
      wrongContext,
    );
    await waitOnExecutionContext(wrongContext);
    expect(wrong.status).toBe(404);

    const bodyContext = createExecutionContext();
    const body = await operator.fetch(
      new Request("https://operator.example/__operator/jwk-rotate", {
        method: "POST",
        headers: { "content-type": "text/plain", "x-operator-nonce": operatorNonce },
        body: "unexpected",
      }),
      operatorEnv,
      bodyContext,
    );
    await waitOnExecutionContext(bodyContext);
    expect(body.status).toBe(404);
  });

  it("removes an operator-revoked retired JWK from publication and RP logout", async () => {
    const oldId = `revoke-old-${crypto.randomUUID()}`;
    const clientId = `revoke-client-${crypto.randomUUID()}`;
    const oldKeys = await generateKeyPair("ES256", { extractable: true });
    const currentKeys = await generateKeyPair("ES256", { extractable: true });
    const now = new Date();
    await env.DB.prepare("INSERT INTO jwks (id, publicKey, privateKey, createdAt, expiresAt) VALUES (?, ?, ?, ?, ?)")
      .bind(
        oldId,
        JSON.stringify(await exportJWK(oldKeys.publicKey)),
        JSON.stringify(await exportJWK(oldKeys.privateKey)),
        new Date(now.getTime() - 60_000).toISOString(),
        new Date(now.getTime() - 1_000).toISOString(),
      )
      .run();
    await env.DB.prepare("INSERT INTO jwks (id, publicKey, privateKey, createdAt, expiresAt) VALUES (?, ?, ?, ?, ?)")
      .bind(
        `revoke-current-${crypto.randomUUID()}`,
        JSON.stringify(await exportJWK(currentKeys.publicKey)),
        JSON.stringify(await exportJWK(currentKeys.privateKey)),
        new Date(now.getTime() + 1_000).toISOString(),
        new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000).toISOString(),
      )
      .run();
    await env.DB.prepare(
      "INSERT OR REPLACE INTO oauthClient (id, clientId, redirectUris, postLogoutRedirectUris, enableEndSession) VALUES (?, ?, ?, ?, ?)",
    )
      .bind(`revoke-client-row-${crypto.randomUUID()}`, clientId, "[]", "[]", 1)
      .run();
    const operatorEnv: OperatorEnv = {
      DB: env.DB,
      AUTH_ISSUER: issuer,
      OPERATOR_NONCE: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg",
      OPERATOR_ACTION: "jwk-revoke",
      BETTER_AUTH_SECRETS: env.BETTER_AUTH_SECRETS,
      GOOGLE_CLIENT_ID: env.GOOGLE_CLIENT_ID,
      GOOGLE_CLIENT_SECRET: env.GOOGLE_CLIENT_SECRET,
      ALLOWED_GOOGLE_DOMAIN: env.ALLOWED_GOOGLE_DOMAIN,
    };
    const context = createExecutionContext();
    const revoked = await operator.fetch(
      new Request("https://operator.example/__operator/jwk-revoke", {
        method: "POST",
        headers: { "content-type": "application/json", "x-operator-nonce": operatorEnv.OPERATOR_NONCE },
        body: JSON.stringify({ key_id: oldId }),
      }),
      operatorEnv,
      context,
    );
    await waitOnExecutionContext(context);
    expect(revoked.status).toBe(200);
    expect(
      (await env.DB.prepare("SELECT revokedAt FROM jwks WHERE id = ?").bind(oldId).first<{ revokedAt: string }>())
        ?.revokedAt,
    ).toBeTruthy();
    const jwks = (await (await production(new Request(`${issuer}/jwks`))).json()) as { keys: Array<{ kid?: string }> };
    expect(jwks.keys.some((key) => key.kid === oldId)).toBe(false);
    const hint = await new SignJWT({ aud: clientId, sid: "revoked-logout-session" })
      .setProtectedHeader({ alg: "ES256", kid: oldId })
      .setIssuer(issuer)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(oldKeys.privateKey);
    const logout = await production(
      new Request(`${issuer}/oauth2/end-session?id_token_hint=${encodeURIComponent(hint)}&client_id=${clientId}`),
    );
    expect(logout.status).toBe(400);
  });
});
