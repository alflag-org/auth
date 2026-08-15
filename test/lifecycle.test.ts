import { env } from "cloudflare:workers";
import { sha256Base64Url } from "../src/crypto";
import { describe, expect, it } from "vitest";
import { codeChallenge, createTestOAuthClient, dispatch, sessionCookie } from "./support";

const issuer = "https://auth.example.invalid";
const redirectURI = "https://lifecycle.example/callback";

async function signedCookie(label: string, expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000)): Promise<string> {
  return sessionCookie({
    userId: `lifecycle-user-${label}`,
    email: `${label}@example.com`,
    token: `lifecycle-token-${label}`,
    sessionId: `lifecycle-session-${label}`,
    name: "Lifecycle User",
    expiresAt,
  });
}

async function createClient(label: string, scope = "openid profile email") {
  return createTestOAuthClient({
    name: `Lifecycle ${label}`,
    redirectURI,
    postLogoutRedirectURI: "https://lifecycle.example/signed-out",
    scope,
  });
}

async function issueCode(
  label: string,
  scope = "openid profile email",
  verifier = `lifecycle-verifier-${label}-abcdefghijklmnopqrstuvwxyz-0123456789`,
) {
  const cookie = await signedCookie(label);
  const client = await createClient(label, scope);
  const url = new URL(`${issuer}/oauth2/authorize`);
  url.search = new URLSearchParams({
    client_id: client.client_id,
    response_type: "code",
    redirect_uri: redirectURI,
    scope,
    state: `state-${label}`,
    nonce: `nonce-${label}`,
    code_challenge: await codeChallenge(verifier),
    code_challenge_method: "S256",
  }).toString();
  const authorization = await dispatch(new Request(url, { headers: { cookie }, redirect: "manual" }));
  expect(authorization.status, await authorization.clone().text()).toBe(302);
  const callback = new URL(authorization.headers.get("location") ?? "https://invalid.example/");
  const code = callback.searchParams.get("code");
  if (!code) throw new Error("authorization response did not include a code");
  const verification = await env.DB.prepare(
    "SELECT createdAt, expiresAt FROM verification WHERE identifier = ? LIMIT 1",
  )
    .bind(await sha256Base64Url(code))
    .first<{
      createdAt: string;
      expiresAt: string;
    }>();
  if (!verification) throw new Error("authorization code verification row was not created");
  expect(
    Math.round((new Date(verification.expiresAt).getTime() - new Date(verification.createdAt).getTime()) / 1000),
  ).toBe(60);
  return { client, cookie, verifier, code, sessionId: `lifecycle-session-${label}` };
}

async function tokenRequest(
  client: { client_id: string; client_secret?: string },
  code: string,
  verifier: string,
  overrides: { clientSecret?: string; redirectURI?: string } = {},
): Promise<Response> {
  if (!client.client_secret) throw new Error("client secret was not returned");
  return dispatch(
    new Request(`${issuer}/oauth2/token`, {
      method: "POST",
      headers: {
        authorization: `Basic ${btoa(`${client.client_id}:${overrides.clientSecret ?? client.client_secret}`)}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: overrides.redirectURI ?? redirectURI,
        code_verifier: verifier,
      }),
    }),
  );
}

describe("authorization code and session lifecycle", () => {
  it("validates client secret, redirect URI, and PKCE before consuming a fresh code", async () => {
    const fresh = await issueCode("fresh-pkce");
    const mismatch = await tokenRequest(fresh.client, fresh.code, "wrong-verifier-fresh-pkce");
    expect(mismatch.status).toBe(400);
    expect(await mismatch.json()).toEqual({ error: "invalid_grant", error_description: "invalid code" });
    const validAfterPKCEMismatch = await tokenRequest(fresh.client, fresh.code, fresh.verifier);
    expect(validAfterPKCEMismatch.status).toBe(200);

    const wrongSecretFlow = await issueCode("wrong-secret");
    const wrongSecret = await tokenRequest(wrongSecretFlow.client, wrongSecretFlow.code, wrongSecretFlow.verifier, {
      clientSecret: "wrong-client-secret",
    });
    expect(wrongSecret.status).toBe(401);
    expect(await wrongSecret.json()).toEqual({ error: "invalid_client", error_description: "invalid client" });
    expect(wrongSecret.headers.get("www-authenticate")).toBe('Basic realm="oauth2/token"');
    expect((await tokenRequest(wrongSecretFlow.client, wrongSecretFlow.code, wrongSecretFlow.verifier)).status).toBe(
      200,
    );

    const wrongRedirectFlow = await issueCode("wrong-redirect");
    const wrongRedirect = await tokenRequest(
      wrongRedirectFlow.client,
      wrongRedirectFlow.code,
      wrongRedirectFlow.verifier,
      {
        redirectURI: "https://other.example/callback",
      },
    );
    expect(wrongRedirect.status).toBe(400);
    expect(await wrongRedirect.json()).toEqual({ error: "invalid_grant", error_description: "invalid code" });
    expect(
      (await tokenRequest(wrongRedirectFlow.client, wrongRedirectFlow.code, wrongRedirectFlow.verifier)).status,
    ).toBe(200);

    const bindingA = await issueCode("client-binding-a");
    const bindingB = await createClient("client-binding-b");
    const bindingMismatch = await tokenRequest(bindingB, bindingA.code, bindingA.verifier);
    expect(bindingMismatch.status).toBe(400);
    expect(await bindingMismatch.json()).toEqual({ error: "invalid_grant", error_description: "invalid code" });
    expect((await tokenRequest(bindingA.client, bindingA.code, bindingA.verifier)).status).toBe(200);
  });

  it("rejects a successfully consumed authorization code on replay", async () => {
    const fresh = await issueCode("replay");
    const [first, replay] = await Promise.all([
      tokenRequest(fresh.client, fresh.code, fresh.verifier),
      tokenRequest(fresh.client, fresh.code, fresh.verifier),
    ]);
    expect([first.status, replay.status].sort((left, right) => left - right)).toEqual([200, 400]);
    const replayResponse = first.status === 400 ? first : replay;
    expect(await replayResponse.json()).toEqual({ error: "invalid_grant", error_description: "invalid code" });
  });

  it("enforces the RFC 7636 code_verifier shape before consuming the code", async () => {
    const cases = [
      ["too-short", "A".repeat(42), "A".repeat(43), false],
      ["minimum", "A".repeat(43), "A".repeat(43), true],
      ["maximum", "A".repeat(128), "A".repeat(128), true],
      ["too-long", "A".repeat(129), "A".repeat(43), false],
      ["invalid-character", `${"A".repeat(42)}!`, "A".repeat(43), false],
    ] as const;
    for (const [label, candidate, issuedVerifier, valid] of cases) {
      const flow = await issueCode(`verifier-${label}`, "openid profile email", issuedVerifier);
      const response = await tokenRequest(flow.client, flow.code, candidate);
      expect(response.status, label).toBe(valid ? 200 : 400);
      if (!valid) {
        expect(await response.json()).toEqual({ error: "invalid_grant", error_description: "invalid code" });
        const retry = await tokenRequest(flow.client, flow.code, flow.verifier);
        expect(retry.status, label).toBe(200);
      }
    }
  });

  it("rejects an expired authorization code deterministically", async () => {
    const flow = await issueCode("expired-code");
    const identifier = await sha256Base64Url(flow.code);
    await env.DB.prepare("UPDATE verification SET expiresAt = ? WHERE identifier = ?")
      .bind(new Date(Date.now() - 1000).toISOString(), identifier)
      .run();
    const response = await tokenRequest(flow.client, flow.code, flow.verifier);
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_grant", error_description: "invalid code" });
  });

  it("rejects malformed and future authorization timestamps without consuming the code", async () => {
    const futureCreatedAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    const cases = [
      ["malformed-expires", { expiresAt: "not-a-date" }],
      ["malformed-created", { createdAt: "not-a-date" }],
      ["future-created", { createdAt: futureCreatedAt }],
    ] as const;
    for (const [label, update] of cases) {
      const flow = await issueCode(label);
      const identifier = await sha256Base64Url(flow.code);
      const original = await env.DB.prepare("SELECT createdAt, expiresAt FROM verification WHERE identifier = ?")
        .bind(identifier)
        .first<{ createdAt: string; expiresAt: string }>();
      if (!original) throw new Error("authorization code verification row was not created");
      const changed = await env.DB.prepare(`UPDATE verification SET createdAt = ?, expiresAt = ? WHERE identifier = ?`)
        .bind(
          "createdAt" in update ? update.createdAt : original.createdAt,
          "expiresAt" in update ? update.expiresAt : original.expiresAt,
          identifier,
        )
        .run();
      expect(changed.meta.changes).toBe(1);
      if (label === "future-created") expect(new Date(futureCreatedAt).getTime()).toBeGreaterThan(Date.now());
      const rejected = await tokenRequest(flow.client, flow.code, flow.verifier);
      expect(rejected.status, label).toBe(400);
      expect(await rejected.json()).toEqual({ error: "invalid_grant", error_description: "invalid code" });
      await env.DB.prepare("UPDATE verification SET createdAt = ?, expiresAt = ? WHERE identifier = ?")
        .bind(original.createdAt, original.expiresAt, identifier)
        .run();
      const accepted = await tokenRequest(flow.client, flow.code, flow.verifier);
      expect(accepted.status, label).toBe(200);
    }
  });

  it("rejects expired and explicitly revoked sessions before authorization", async () => {
    const expiredCookie = await signedCookie("expired-session", new Date(Date.now() - 1000));
    const expiredClient = await createClient("expired-session");
    const expiredURL = new URL(`${issuer}/oauth2/authorize`);
    expiredURL.search = new URLSearchParams({
      client_id: expiredClient.client_id,
      response_type: "code",
      redirect_uri: redirectURI,
      scope: "openid",
      state: "expired-state",
      nonce: "expired-nonce",
      code_challenge: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
      code_challenge_method: "S256",
    }).toString();
    const expired = await dispatch(new Request(expiredURL, { headers: { cookie: expiredCookie }, redirect: "manual" }));
    expect(expired.status).toBe(302);
    expect(new URL(expired.headers.get("location") ?? "/invalid", issuer).pathname).toBe("/sign-in");

    const revokedCookie = await signedCookie("revoked-session");
    await env.DB.prepare("DELETE FROM session WHERE id = ?").bind("lifecycle-session-revoked-session").run();
    const revokedClient = await createClient("revoked-session");
    const revokedURL = new URL(`${issuer}/oauth2/authorize`);
    revokedURL.search = new URLSearchParams({
      client_id: revokedClient.client_id,
      response_type: "code",
      redirect_uri: redirectURI,
      scope: "openid",
      state: "revoked-state",
      nonce: "revoked-nonce",
      code_challenge: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
      code_challenge_method: "S256",
    }).toString();
    const revoked = await dispatch(new Request(revokedURL, { headers: { cookie: revokedCookie }, redirect: "manual" }));
    expect(revoked.status).toBe(302);
    expect(new URL(revoked.headers.get("location") ?? "/invalid", issuer).pathname).toBe("/sign-in");
  });

  it("minimizes claims to the requested scope and keeps Google identity material out of OAuth claims", async () => {
    const flow = await issueCode("openid-only", "openid");
    const response = await tokenRequest(flow.client, flow.code, flow.verifier);
    expect(response.status).toBe(200);
    const tokens = (await response.json()) as { access_token: string; id_token: string };
    const encodedPayload = tokens.id_token.split(".")[1];
    if (!encodedPayload) throw new Error("id token payload was missing");
    const idPayload = JSON.parse(atob(encodedPayload.replaceAll("-", "+").replaceAll("_", "/"))) as Record<
      string,
      unknown
    >;
    expect(idPayload.sub).toBe("lifecycle-user-openid-only");
    expect(idPayload.email).toBeUndefined();
    expect(idPayload.name).toBeUndefined();
    expect(idPayload.sub).not.toBe("google-sub");
    const userInfo = await dispatch(
      new Request(`${issuer}/oauth2/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } }),
    );
    expect(userInfo.status).toBe(200);
    expect(await userInfo.json()).toEqual({ sub: "lifecycle-user-openid-only" });
    await env.DB.prepare("UPDATE oauthAccessToken SET expiresAt = ? WHERE clientId = ? ORDER BY createdAt DESC LIMIT 1")
      .bind(new Date(Date.now() - 1000).toISOString(), flow.client.client_id)
      .run();
    const expiredAccess = await dispatch(
      new Request(`${issuer}/oauth2/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } }),
    );
    expect(expiredAccess.status).toBe(401);
    expect(expiredAccess.headers.get("www-authenticate")).toBe('Bearer error="invalid_token"');
    expect(await expiredAccess.json()).toEqual({ error: "invalid_token" });
  });

  it("keeps the central session when RP-local logout occurs outside the auth service", async () => {
    const cookie = await signedCookie("application-logout");
    expect(cookie).toContain("__Host-better-auth.session_token=");
    const appA = await createClient("application-logout-a");
    const appBRedirect = "https://lifecycle.example/second-callback";
    const appB = await createTestOAuthClient({
      name: "Lifecycle application-logout-b",
      redirectURI: appBRedirect,
      postLogoutRedirectURI: "https://lifecycle.example/signed-out-b",
    });
    const authorize = async (clientId: string, redirectURI: string, state: string) => {
      const verifier = `application-logout-verifier-${state}-abcdefghijklmnopqrstuvwxyz-0123456789`;
      const url = new URL(`${issuer}/oauth2/authorize`);
      url.search = new URLSearchParams({
        client_id: clientId,
        response_type: "code",
        redirect_uri: redirectURI,
        scope: "openid profile email",
        state,
        nonce: `nonce-${state}`,
        code_challenge: await codeChallenge(verifier),
        code_challenge_method: "S256",
      }).toString();
      return dispatch(new Request(url, { headers: { cookie }, redirect: "manual" }));
    };
    const appAResponse = await authorize(appA.client_id, redirectURI, "application-a");
    expect(appAResponse.status, await appAResponse.clone().text()).toBe(302);
    expect(new URL(appAResponse.headers.get("location") ?? "https://invalid.example/").pathname).toBe("/callback");
    const appBResponse = await authorize(appB.client_id, appBRedirect, "application-b");
    expect(appBResponse.status, await appBResponse.clone().text()).toBe(302);
    expect(new URL(appBResponse.headers.get("location") ?? "https://invalid.example/").pathname).toBe(
      "/second-callback",
    );
    const central = await env.DB.prepare("SELECT id FROM session WHERE id = ?")
      .bind("lifecycle-session-application-logout")
      .first<{ id: string }>();
    expect(central?.id).toBe("lifecycle-session-application-logout");
  });

  it("requires same-origin POST for central sign-out and keeps GET side-effect free", async () => {
    const cookie = await signedCookie("csrf-logout");
    const signIn = await dispatch(new Request(`${issuer}/sign-in?oauth_query=state-marker`));
    expect(signIn.status).toBe(200);
    expect(signIn.headers.get("cache-control")).toBe("no-store");
    expect(signIn.headers.get("content-security-policy")).toBe(
      "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    );
    expect(signIn.headers.get("x-content-type-options")).toBe("nosniff");
    expect(signIn.headers.get("referrer-policy")).toBe("no-referrer");
    const getResponse = await dispatch(new Request(`${issuer}/sign-out`, { headers: { cookie } }));
    expect(getResponse.status).toBe(200);
    expect(getResponse.headers.get("cache-control")).toBe("no-store");
    expect(getResponse.headers.get("referrer-policy")).toBe("no-referrer");
    expect(getResponse.headers.get("content-security-policy")).toBe(
      "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    );
    const getSession = await env.DB.prepare("SELECT id FROM session WHERE id = ?")
      .bind("lifecycle-session-csrf-logout")
      .first<{ id: string }>();
    expect(getSession?.id).toBe("lifecycle-session-csrf-logout");
    for (const origin of [undefined, "https://attacker.example"]) {
      const headers = new Headers({ cookie });
      if (origin) headers.set("origin", origin);
      const response = await dispatch(new Request(`${issuer}/sign-out`, { method: "POST", headers }));
      expect(response.status).toBe(403);
      expect(await response.json()).toEqual({ error: "forbidden" });
      const session = await env.DB.prepare("SELECT id FROM session WHERE id = ?")
        .bind("lifecycle-session-csrf-logout")
        .first<{ id: string }>();
      expect(session?.id).toBe("lifecycle-session-csrf-logout");
    }
    const valid = await dispatch(
      new Request(`${issuer}/sign-out`, { method: "POST", headers: { cookie, origin: issuer } }),
    );
    expect(valid.status).toBe(302);
    const revoked = await env.DB.prepare("SELECT id FROM session WHERE id = ?")
      .bind("lifecycle-session-csrf-logout")
      .first();
    expect(revoked).toBeNull();
  });
});
