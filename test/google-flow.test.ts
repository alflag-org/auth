import { env } from "cloudflare:workers";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";
import { codeChallenge, createTestOAuthClient, dispatch } from "./support";
import { describe, expect, it, vi } from "vitest";
import { createAuth } from "../src/auth";
import { GOOGLE_CERTS_URL, getRuntimeConfig } from "../src/config";
import { signVersionedValue, verifyVersionedValue } from "../src/crypto";
import { completeGoogleLogin, startGoogleLogin } from "../src/google";
import { admitAuthorizationRequest, bindAuthorizationAdmission, oauthQueryDigest } from "../src/admission";
import { cookieValue } from "./support";

type GoogleTokenOverrides = Partial<{
  iss: string;
  aud: string | string[];
  exp: number;
  iat: number;
  nonce: string;
  hd: string | null;
  email: string;
}>;

async function signedToken(
  keyPair: CryptoKeyPair,
  config: ReturnType<typeof getRuntimeConfig>,
  nonce: string,
  label: string,
  overrides: GoogleTokenOverrides = {},
): Promise<string> {
  const { hd, ...claimOverrides } = overrides;
  const payload = {
    sub: `google-${label}`,
    email: `${label}@example.com`,
    email_verified: true,
    name: "Workspace User",
    ...(hd === null ? {} : { hd: hd ?? config.allowedGoogleDomain }),
    nonce,
    ...claimOverrides,
  };
  const token = new SignJWT(payload).setProtectedHeader({ alg: "RS256" });
  if (overrides.iss === undefined) token.setIssuer("https://accounts.google.com");
  if (overrides.aud === undefined) token.setAudience(config.googleClientId);
  if (overrides.iat === undefined) token.setIssuedAt();
  else token.setIssuedAt(overrides.iat);
  if (overrides.exp === undefined) token.setExpirationTime("5m");
  return token.sign(keyPair.privateKey);
}

async function callbackFixture(
  label: string,
  tokenBody: string | ((state: { state: string; nonce: string }) => Promise<string>),
  status = 200,
  keySet?: ReturnType<typeof createLocalJWKSet>,
  stateOverride?: string,
  omitCookie = false,
  fetchOverride?: typeof fetch,
): Promise<Response> {
  const config = getRuntimeConfig(env);
  const keyPair = await generateKeyPair("RS256");
  const tokenKeySet = keySet ?? createLocalJWKSet({ keys: [await exportJWK(keyPair.publicKey)] });
  const start = await startGoogleLogin(new Request(`${config.issuer}/sign-in/google`), config, env.DB);
  const stateCookie = start.headers.get("set-cookie");
  if (!stateCookie) throw new Error("Google state cookie was not set");
  const stateValue = cookieValue(stateCookie, "__Host-auth_google_state");
  if (!stateValue) throw new Error("Google state cookie was empty");
  const statePayload = await verifyVersionedValue(stateValue, config.secrets);
  if (!statePayload) throw new Error("Google state could not be decoded");
  const state = JSON.parse(statePayload) as { state: string; nonce: string };
  const resolvedTokenBody =
    typeof tokenBody === "function" ? JSON.stringify({ id_token: await tokenBody(state) }) : tokenBody;
  const fakeFetch: typeof fetch =
    fetchOverride ??
    (async () => new Response(resolvedTokenBody, { status, headers: { "content-type": "application/json" } }));
  const request = new Request(
    `${config.issuer}/callback/google?code=fake-${label}&state=${encodeURIComponent(stateOverride ?? state.state)}`,
    omitCookie ? undefined : { headers: { cookie: stateCookie.split(";", 1)[0] ?? "" } },
  );
  return completeGoogleLogin(request, createAuth(env, tokenKeySet), config, {
    fetch: fakeFetch,
    keySet: tokenKeySet,
    stateStore: env.DB,
  });
}

async function expectNoGoogleIdentity(label: string, email = `${label}@example.com`): Promise<void> {
  const user = await env.DB.prepare("SELECT id FROM user WHERE email = ?").bind(email).first();
  expect(user).toBeNull();
  const account = await env.DB.prepare("SELECT id FROM account WHERE accountId = ?").bind(`google-${label}`).first();
  expect(account).toBeNull();
}

async function createAuthorizationContinuation(
  config: ReturnType<typeof getRuntimeConfig>,
  clientId: string,
  label: string,
  sourceKey: string,
): Promise<string> {
  const query = `client_id=${clientId}&state=${label}&sig=signature-${label}&exp=1893456300&ba_iat=1893456000000`;
  const digest = await oauthQueryDigest(query);
  if (!digest) throw new Error("continuation digest was not created");
  const admission = await admitAuthorizationRequest(
    env.DB,
    new Request(`${config.issuer}/oauth2/authorize`, { headers: { "cf-connecting-ip": sourceKey } }),
    clientId,
    new Date(),
    { globalCap: 100, perSourceClientCap: 100 },
  );
  if (!admission || !(await bindAuthorizationAdmission(env.DB, admission.id, digest)))
    throw new Error("continuation admission was not bound");
  return query;
}

type GoogleStartDependencies = NonNullable<Parameters<typeof startGoogleLogin>[3]>;

function startStandaloneLogin(
  config: ReturnType<typeof getRuntimeConfig>,
  sourceKey: string,
  limits: GoogleStartDependencies,
): Promise<Response> {
  return startGoogleLogin(
    new Request(`${config.issuer}/sign-in/google`, { headers: { "cf-connecting-ip": sourceKey } }),
    config,
    env.DB,
    limits,
  );
}

async function startRelyingPartyLogin(
  config: ReturnType<typeof getRuntimeConfig>,
  clientId: string,
  label: string,
  sourceKey: string,
  limits: GoogleStartDependencies,
): Promise<Response> {
  const query = await createAuthorizationContinuation(config, clientId, label, sourceKey);
  return startGoogleLogin(
    new Request(`${config.issuer}/sign-in/google?oauth_query=${encodeURIComponent(query)}`, {
      headers: { "cf-connecting-ip": sourceKey },
    }),
    config,
    env.DB,
    limits,
  );
}

describe("Google login flow", () => {
  it("uses a fake upstream end to end and creates the local identity", async () => {
    const config = getRuntimeConfig(env);
    const keyPair = await generateKeyPair("RS256");
    const keySet = createLocalJWKSet({ keys: [await exportJWK(keyPair.publicKey)] });
    const start = await startGoogleLogin(new Request(`${config.issuer}/sign-in/google`), config, env.DB);
    expect(start.status).toBe(302);
    const location = new URL(start.headers.get("location") ?? "https://invalid.example/");
    expect(location.origin).toBe("https://accounts.google.com");
    expect(location.searchParams.get("redirect_uri")).toBe(`${config.issuer}/callback/google`);
    expect(location.searchParams.get("code_challenge_method")).toBe("S256");
    const stateCookie = start.headers.get("set-cookie");
    if (!stateCookie) throw new Error("Google login did not set a state cookie");
    expect(stateCookie).toContain("Path=/");
    expect(stateCookie).toContain("Secure");
    expect(stateCookie).toContain("HttpOnly");
    expect(stateCookie).toContain("SameSite=Lax");
    expect(stateCookie).not.toContain("Domain=");
    const stateValue = stateCookie.split(";", 1)[0]?.split("=", 2)[1];
    if (!stateValue) throw new Error("Google login state cookie was empty");
    const statePayload = await verifyVersionedValue(stateValue, config.secrets);
    if (!statePayload) throw new Error("Google login state cookie could not be verified");
    const state = JSON.parse(statePayload) as { state: string; nonce: string };
    const upstreamIdToken = await new SignJWT({
      sub: "google-sub-fake",
      email: "workspace-user@example.com",
      email_verified: true,
      name: "Workspace User",
      hd: "example.com",
      nonce: state.nonce,
    })
      .setProtectedHeader({ alg: "RS256" })
      .setIssuer("https://accounts.google.com")
      .setAudience(config.googleClientId)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(keyPair.privateKey);

    const fakeFetch: typeof fetch = async (input) => {
      const inputURL = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      expect(inputURL).toBe("https://oauth2.googleapis.com/token");
      return Response.json({ id_token: upstreamIdToken, access_token: "not-persisted" });
    };
    const response = await completeGoogleLogin(
      new Request(`${config.issuer}/callback/google?code=fake-code&state=${encodeURIComponent(state.state)}`, {
        headers: { cookie: `${stateCookie.split(";", 1)[0]}` },
      }),
      createAuth(env, keySet),
      config,
      { fetch: fakeFetch, keySet, stateStore: env.DB },
    );
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(`${config.issuer}/`);
    expect(response.headers.get("set-cookie")).toContain("__Host-auth_google_state=");
    const sessionCookie = response.headers
      .getSetCookie()
      .find((value) => value.startsWith("__Host-better-auth.session_token="));
    if (!sessionCookie) throw new Error("Google login did not set the central session cookie");
    expect(sessionCookie).toContain("Path=/");
    expect(sessionCookie).toContain("Secure");
    expect(sessionCookie).toContain("HttpOnly");
    expect(sessionCookie).toContain("SameSite=Lax");
    expect(sessionCookie).not.toContain("Domain=");

    const user = await env.DB.prepare("SELECT id, email FROM user WHERE email = ?")
      .bind("workspace-user@example.com")
      .first<{ id: string; email: string }>();
    expect(user?.email).toBe("workspace-user@example.com");
    expect(user?.id).not.toBe("google-sub-fake");
    const account = await env.DB.prepare(
      "SELECT accountId, accessToken, refreshToken, idToken FROM account WHERE userId = ?",
    )
      .bind(user?.id)
      .first<{ accountId: string; accessToken: string | null; refreshToken: string | null; idToken: string | null }>();
    expect(account?.accountId).toBe("google-sub-fake");
    expect(account?.accessToken).toBeNull();
    expect(account?.refreshToken).toBeNull();
    expect(account?.idToken).toBeNull();
    const session = await env.DB.prepare("SELECT userId, expiresAt FROM session WHERE userId = ?")
      .bind(user?.id)
      .first<{ userId: string; expiresAt: string }>();
    expect(session?.userId).toBe(user?.id);
    expect(new Date(session?.expiresAt ?? 0).getTime()).toBeGreaterThan(Date.now());
  });

  it("does not implicitly link a verified email to a different Google subject", async () => {
    const config = getRuntimeConfig(env);
    const firstKeyPair = await generateKeyPair("RS256");
    const firstKeySet = createLocalJWKSet({ keys: [await exportJWK(firstKeyPair.publicKey)] });
    const first = await callbackFixture(
      "same-email-first",
      (state) => signedToken(firstKeyPair, config, state.nonce, "subject-a"),
      200,
      firstKeySet,
    );
    expect(first.status).toBe(302);
    const firstUser = await env.DB.prepare("SELECT id FROM user WHERE email = ?")
      .bind("subject-a@example.com")
      .first<{ id: string }>();
    if (!firstUser) throw new Error("first Google user was not persisted");
    const sessionsBefore = await env.DB.prepare("SELECT COUNT(*) AS count FROM session WHERE userId = ?")
      .bind(firstUser.id)
      .first<{ count: number }>();

    const secondKeyPair = await generateKeyPair("RS256");
    const secondKeySet = createLocalJWKSet({ keys: [await exportJWK(secondKeyPair.publicKey)] });
    const second = await callbackFixture(
      "same-email-second",
      (state) => signedToken(secondKeyPair, config, state.nonce, "subject-b", { email: "subject-a@example.com" }),
      200,
      secondKeySet,
    );
    expect(second.status).toBe(400);
    expect(await second.text()).toBe("Authentication failed");
    const users = await env.DB.prepare("SELECT id FROM user WHERE email = ?").bind("subject-a@example.com").all<{
      id: string;
    }>();
    expect(users.results).toHaveLength(1);
    expect(users.results[0]?.id).toBe(firstUser.id);
    const accounts = await env.DB.prepare("SELECT accountId, userId FROM account WHERE userId = ?")
      .bind(firstUser.id)
      .all<{ accountId: string; userId: string }>();
    expect(accounts.results).toEqual([{ accountId: "google-subject-a", userId: firstUser.id }]);
    const secondAccount = await env.DB.prepare("SELECT id FROM account WHERE accountId = ?").bind("subject-b").first();
    expect(secondAccount).toBeNull();
    const sessionsAfter = await env.DB.prepare("SELECT COUNT(*) AS count FROM session WHERE userId = ?")
      .bind(firstUser.id)
      .first<{ count: number }>();
    expect(sessionsAfter?.count).toBe(sessionsBefore?.count);
  });

  it("fails closed before D1 writes when the Google rate-limit binding is absent or denies", async () => {
    const config = getRuntimeConfig(env);
    const before = await env.DB.prepare("SELECT COUNT(*) AS count FROM verification WHERE identifier = ?")
      .bind("google-oauth-state")
      .first<{ count: number }>();
    const missingBinding = await startGoogleLogin(new Request(`${config.issuer}/sign-in/google`), config, env.DB, {
      requireRateLimiter: true,
    });
    expect(missingBinding.status).toBe(429);
    const deniedLimiter: RateLimit = {
      limit: async () => ({ success: false }),
    };
    const denied = await startGoogleLogin(
      new Request(`${config.issuer}/sign-in/google`, { headers: { "cf-connecting-ip": "192.0.2.10" } }),
      config,
      env.DB,
      { rateLimiter: deniedLimiter, requireRateLimiter: true },
    );
    expect(denied.status).toBe(429);
    const after = await env.DB.prepare("SELECT COUNT(*) AS count FROM verification WHERE identifier = ?")
      .bind("google-oauth-state")
      .first<{ count: number }>();
    expect(after?.count).toBe(before?.count);
  });

  it("bounds expired state admission work and leaves backlog draining to scheduled cleanup", async () => {
    const config = getRuntimeConfig(env);
    await env.DB.prepare("DELETE FROM verification WHERE identifier = ?").bind("google-oauth-state").run();
    const expired = new Date(Date.now() - 60_000).toISOString();
    for (let index = 0; index < 100; index += 1) {
      await env.DB.prepare(
        "INSERT INTO verification (id, identifier, value, expiresAt, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)",
      )
        .bind(`google-backlog-${index}`, "google-oauth-state", `backlog-${index}`, expired, expired, expired)
        .run();
    }
    const response = await startGoogleLogin(
      new Request(`${config.issuer}/sign-in/google`, { headers: { "cf-connecting-ip": "192.0.2.88" } }),
      config,
      env.DB,
      { rateLimiter: { limit: async () => ({ success: true }) }, requireRateLimiter: true, maxPendingStates: 2 },
    );
    expect(response.status).toBe(429);
    const rows = await env.DB.prepare("SELECT COUNT(*) AS count FROM verification WHERE identifier = ?")
      .bind("google-oauth-state")
      .first<{ count: number }>();
    expect(rows?.count).toBe(50);
  });

  it("accepts a real unauthenticated OAuth continuation after 61 seconds and expires its code at 60 seconds", async () => {
    const config = getRuntimeConfig(env);
    const client = await createTestOAuthClient({
      name: `Google continuation ${crypto.randomUUID()}`,
      redirectURI: "https://google-continuation.example/callback",
      postLogoutRedirectURI: "https://google-continuation.example/signed-out",
    });
    const keyPair = await generateKeyPair("RS256");
    const baseTime = Date.now();
    vi.useFakeTimers({ now: baseTime });
    try {
      const verifier = `google-continuation-verifier-${crypto.randomUUID()}-abcdefghijklmnopqrstuvwxyz`;
      const authorizeURL = new URL(`${config.issuer}/oauth2/authorize`);
      authorizeURL.search = new URLSearchParams({
        client_id: client.client_id,
        response_type: "code",
        redirect_uri: "https://google-continuation.example/callback",
        scope: "openid profile email",
        state: "google-continuation-state",
        nonce: "google-continuation-nonce",
        code_challenge: await codeChallenge(verifier),
        code_challenge_method: "S256",
      }).toString();
      const authorizeResponse = await dispatch(new Request(authorizeURL, { redirect: "manual" }));
      expect(authorizeResponse.status).toBe(302);
      const signInLocation = new URL(authorizeResponse.headers.get("location") ?? "", config.issuer);
      expect(signInLocation.pathname).toBe("/sign-in");
      expect(signInLocation.searchParams.get("sig")).toBeTruthy();
      const signIn = await dispatch(new Request(signInLocation));
      const html = await signIn.text();
      const googleHref = /href="([^"]*\/sign-in\/google[^"]*)"/u.exec(html)?.[1];
      if (!googleHref) throw new Error("sign-in page did not contain the Google continuation link");
      const [startA, startB] = await Promise.all([
        dispatch(new Request(new URL(googleHref, config.issuer), { headers: { "cf-connecting-ip": "192.0.2.61" } })),
        dispatch(new Request(new URL(googleHref, config.issuer), { headers: { "cf-connecting-ip": "192.0.2.61" } })),
      ]);
      expect([startA.status, startB.status].sort((left, right) => left - right)).toEqual([302, 400]);
      const googleStart = startA.status === 302 ? startA : startB;
      const googleCookieHeader = googleStart.headers.get("set-cookie");
      if (!googleCookieHeader) throw new Error("Google state cookie was not set");
      const cookie = googleCookieHeader.split(";", 1)[0];
      if (!cookie) throw new Error("Google state cookie was empty");
      const statePayload = await verifyVersionedValue(cookie.split("=", 2)[1] ?? "", config.secrets);
      if (!statePayload) throw new Error("Google state could not be decoded");
      const state = JSON.parse(statePayload) as { state: string; nonce: string };
      const token = await signedToken(keyPair, config, state.nonce, "sixty-one-seconds");
      const publicJWK = await exportJWK(keyPair.publicKey);
      const originalFetch = globalThis.fetch;
      let fakeCalls = 0;
      vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
        const inputURL = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (inputURL === GOOGLE_CERTS_URL) return Response.json({ keys: [publicJWK] });
        if (inputURL !== "https://oauth2.googleapis.com/token") return originalFetch(input, init);
        fakeCalls += 1;
        return Response.json({ id_token: token });
      });
      try {
        vi.setSystemTime(baseTime + 61_000);
        const callback = await dispatch(
          new Request(
            `${config.issuer}/callback/google?code=sixty-one-seconds&state=${encodeURIComponent(state.state)}`,
            { headers: { cookie, "cf-connecting-ip": "192.0.2.61" }, redirect: "manual" },
          ),
        );
        expect(fakeCalls).toBe(1);
        expect(callback.status, await callback.clone().text()).toBe(302);
        const callbackLocation = new URL(callback.headers.get("location") ?? "https://invalid.example/");
        expect(callbackLocation.origin + callbackLocation.pathname).toBe(
          "https://google-continuation.example/callback",
        );
        const code = callbackLocation.searchParams.get("code");
        if (!code) throw new Error("Google continuation did not issue an authorization code");
        if (!client.client_secret) throw new Error("Google continuation client secret was not returned");
        vi.setSystemTime(baseTime + 122_000);
        const tokenResponse = await dispatch(
          new Request(`${config.issuer}/oauth2/token`, {
            method: "POST",
            headers: {
              authorization: `Basic ${btoa(`${client.client_id}:${client.client_secret}`)}`,
              "content-type": "application/x-www-form-urlencoded",
            },
            body: new URLSearchParams({
              grant_type: "authorization_code",
              code,
              redirect_uri: "https://google-continuation.example/callback",
              code_verifier: verifier,
            }),
          }),
        );
        expect(tokenResponse.status).toBe(400);
        expect(await tokenResponse.json()).toEqual({ error: "invalid_grant", error_description: "invalid code" });
      } finally {
        vi.stubGlobal("fetch", originalFetch);
      }
    } finally {
      vi.useRealTimers();
    }
  });

  it("releases continuation admissions on expired and failed callbacks", async () => {
    const config = getRuntimeConfig(env);
    const base = Math.floor(Date.now() / 1000);
    await env.DB.prepare("DELETE FROM verification WHERE identifier = ?").bind("google-oauth-state").run();
    await env.DB.prepare("DELETE FROM oauthAuthorizationAdmission").run();

    const startContinuation = async (suffix: string) => {
      const clientId = `continuation-release-${suffix}`;
      const query = `client_id=${clientId}&sig=signature-${suffix}&exp=1893456300&ba_iat=1893456000000`;
      const digest = await oauthQueryDigest(query);
      if (!digest) throw new Error("continuation digest was not created");
      const admission = await admitAuthorizationRequest(
        env.DB,
        new Request(`${config.issuer}/oauth2/authorize`, { headers: { "cf-connecting-ip": `192.0.2.${suffix}` } }),
        clientId,
        new Date(base * 1000),
        { globalCap: 10, perSourceClientCap: 10 },
      );
      if (!admission || !(await bindAuthorizationAdmission(env.DB, admission.id, digest, new Date(base * 1000))))
        throw new Error("continuation admission was not bound");
      const response = await startGoogleLogin(
        new Request(`${config.issuer}/sign-in/google?oauth_query=${encodeURIComponent(query)}`),
        config,
        env.DB,
        { now: () => base },
      );
      expect(response.status).toBe(302);
      const setCookie = response.headers.get("set-cookie");
      if (!setCookie) throw new Error("Google state cookie was not set");
      const statePayload = await verifyVersionedValue(
        cookieValue(setCookie, "__Host-auth_google_state") ?? "",
        config.secrets,
      );
      if (!statePayload) throw new Error("Google state could not be decoded");
      const state = JSON.parse(statePayload) as { state: string; issuedAt: number };
      return { admission, state, setCookie };
    };

    const expired = await startContinuation("expired");
    const expiredResponse = await completeGoogleLogin(
      new Request(`${config.issuer}/callback/google?code=unused&state=${expired.state.state}`, {
        headers: { cookie: expired.setCookie.split(";", 1)[0] ?? "" },
      }),
      createAuth(env),
      config,
      { stateStore: env.DB, now: () => base + 301 },
    );
    expect(expiredResponse.status).toBe(400);
    const expiredRow = await env.DB.prepare(
      "SELECT id, continuationDigest, continuationStateId, consumedAt, expiresAt FROM oauthAuthorizationAdmission WHERE id = ?",
    )
      .bind(expired.admission.id)
      .first();
    expect(expiredRow).toBeNull();

    const failed = await startContinuation("failed");
    const failedResponse = await completeGoogleLogin(
      new Request(`${config.issuer}/callback/google?code=failed&state=${failed.state.state}`, {
        headers: { cookie: failed.setCookie.split(";", 1)[0] ?? "" },
      }),
      createAuth(env),
      config,
      { stateStore: env.DB, now: () => base, fetch: async () => new Response("upstream failure", { status: 500 }) },
    );
    expect(failedResponse.status).toBe(400);
    expect(
      await env.DB.prepare("SELECT id FROM oauthAuthorizationAdmission WHERE id = ?").bind(failed.admission.id).first(),
    ).toBeNull();
  });

  it("rejects personal, missing-domain, and mismatched-domain callbacks without persistence", async () => {
    const config = getRuntimeConfig(env);
    for (const [label, hd, email] of [
      ["personal-account", null, "person@gmail.com"],
      ["missing-domain", null, "missing-domain@example.com"],
      ["wrong-domain", "other.example.com"],
    ] as const) {
      const keyPair = await generateKeyPair("RS256");
      const keySet = createLocalJWKSet({ keys: [await exportJWK(keyPair.publicKey)] });
      const response = await callbackFixture(
        label,
        (state) => signedToken(keyPair, config, state.nonce, label, { hd, ...(email ? { email } : {}) }),
        200,
        keySet,
      );
      expect(response.status).toBe(400);
      expect(await response.text()).toBe("Authentication failed");
      await expectNoGoogleIdentity(label, email ?? `${label}@example.com`);
    }
  });

  it("rejects callback tokens with bad signature, issuer, audience, nonce, and expiry", async () => {
    const config = getRuntimeConfig(env);
    const cases: Array<[string, GoogleTokenOverrides, "signature" | "claims"]> = [
      ["bad-issuer", { iss: "https://accounts.example.invalid" }, "claims"],
      ["bad-audience", { aud: "another-client" }, "claims"],
      ["bad-nonce", { nonce: "different-nonce" }, "claims"],
      ["expired-token", { exp: Math.floor(Date.now() / 1000) - 60 }, "claims"],
    ];
    for (const [label, overrides, kind] of cases) {
      const keyPair = await generateKeyPair("RS256");
      const stateStart = await startGoogleLogin(new Request(`${config.issuer}/sign-in/google`), config, env.DB);
      const stateCookie = stateStart.headers.get("set-cookie");
      if (!stateCookie) throw new Error("Google state cookie was not set");
      const statePayload = await verifyVersionedValue(
        stateCookie.split(";", 1)[0]?.split("=", 2)[1] ?? "",
        config.secrets,
      );
      if (!statePayload) throw new Error("Google state could not be decoded");
      const nonce = (JSON.parse(statePayload) as { nonce: string }).nonce;
      const token = await signedToken(keyPair, config, nonce, label, overrides);
      const response = await completeGoogleLogin(
        new Request(
          `${config.issuer}/callback/google?code=fake-${label}&state=${encodeURIComponent((JSON.parse(statePayload) as { state: string }).state)}`,
          {
            headers: { cookie: stateCookie.split(";", 1)[0] ?? "" },
          },
        ),
        createAuth(env, createLocalJWKSet({ keys: [await exportJWK(keyPair.publicKey)] })),
        config,
        {
          fetch: async () =>
            new Response(JSON.stringify({ id_token: token }), { headers: { "content-type": "application/json" } }),
          keySet:
            kind === "signature"
              ? createLocalJWKSet({ keys: [] })
              : createLocalJWKSet({ keys: [await exportJWK(keyPair.publicKey)] }),
          stateStore: env.DB,
        },
      );
      expect(response.status).toBe(400);
      expect(await response.text()).toBe("Authentication failed");
      await expectNoGoogleIdentity(label);
    }
    const signedByOtherKey = await generateKeyPair("RS256");
    const response = await callbackFixture(
      "bad-signature",
      JSON.stringify({ id_token: await signedToken(signedByOtherKey, config, "wrong", "bad-signature") }),
      200,
      createLocalJWKSet({ keys: [await exportJWK((await generateKeyPair("RS256")).publicKey)] }),
    );
    expect(response.status).toBe(400);
    expect(await response.text()).toBe("Authentication failed");
    await expectNoGoogleIdentity("bad-signature");
  });

  it("rejects malformed, incomplete, failed, and oversized upstream responses", async () => {
    for (const [label, body, status] of [
      ["malformed-json", "not-json", 200],
      ["missing-id-token", JSON.stringify({ access_token: "marker-access-token" }), 200],
      ["upstream-error", JSON.stringify({ error: "invalid_grant" }), 400],
      ["oversized-response", "x".repeat(65 * 1024), 200],
    ] as const) {
      const response = await callbackFixture(label, body, status);
      expect(response.status).toBe(400);
      expect(await response.text()).toBe("Authentication failed");
      await expectNoGoogleIdentity(label);
    }
    let canceled = false;
    const oversizedStream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(65 * 1024));
      },
      cancel() {
        canceled = true;
      },
    });
    const streamed = await callbackFixture(
      "oversized-stream",
      JSON.stringify({ id_token: "unused" }),
      200,
      undefined,
      undefined,
      false,
      async () => new Response(oversizedStream, { headers: { "content-type": "application/json" } }),
    );
    expect(streamed.status).toBe(400);
    expect(canceled).toBe(true);
  });

  it("rejects missing and modified state without contacting the upstream or creating identity rows", async () => {
    const config = getRuntimeConfig(env);
    const start = await startGoogleLogin(new Request(`${config.issuer}/sign-in/google`), config, env.DB);
    const stateCookie = start.headers.get("set-cookie");
    if (!stateCookie) throw new Error("Google state cookie was not set");
    const cookie = stateCookie.split(";", 1)[0];
    if (!cookie) throw new Error("Google state cookie was empty");
    const fetcher = async () => {
      throw new Error("upstream must not be called");
    };
    const missingCookie = await completeGoogleLogin(
      new Request(`${config.issuer}/callback/google?code=missing-cookie&state=wrong`),
      createAuth(env),
      config,
      { fetch: fetcher, stateStore: env.DB },
    );
    expect(missingCookie.status).toBe(400);
    expect(await missingCookie.text()).toBe("Bad request");
    const modifiedState = await completeGoogleLogin(
      new Request(`${config.issuer}/callback/google?code=modified&state=wrong`, { headers: { cookie } }),
      createAuth(env),
      config,
      { fetch: fetcher, stateStore: env.DB },
    );
    expect(modifiedState.status).toBe(400);
    expect(await modifiedState.text()).toBe("Bad request");
    const statePayload = await verifyVersionedValue(cookie.split("=", 2)[1] ?? "", config.secrets);
    if (!statePayload) throw new Error("Google state could not be decoded");
    const validState = (JSON.parse(statePayload) as { state: string }).state;
    let duplicateCalls = 0;
    const duplicateState = await completeGoogleLogin(
      new Request(
        `${config.issuer}/callback/google?code=duplicate&state=${encodeURIComponent(validState)}&state=malicious`,
        { headers: { cookie } },
      ),
      createAuth(env),
      config,
      {
        stateStore: env.DB,
        fetch: async () => {
          duplicateCalls += 1;
          throw new Error("upstream must not be called");
        },
      },
    );
    expect(duplicateState.status).toBe(400);
    expect(await duplicateState.text()).toBe("Bad request");
    expect(duplicateCalls).toBe(0);
    await expectNoGoogleIdentity("missing-cookie");
    await expectNoGoogleIdentity("modified");
  });

  it("rejects expired, malformed, and future-dated signed state before upstream access", async () => {
    const config = getRuntimeConfig(env);
    const now = Math.floor(Date.now() / 1000);
    for (const [label, issuedAt] of [
      ["expired-state", now - 301],
      ["boundary-state", now - 300],
      ["future-state", now + 31],
      ["invalid-state-time", "not-a-time"],
    ] as const) {
      const start = await startGoogleLogin(new Request(`${config.issuer}/sign-in/google`), config, env.DB);
      const setCookie = start.headers.get("set-cookie");
      if (!setCookie) throw new Error("Google state cookie was not set");
      const originalValue = setCookie.split(";", 1)[0]?.split("=", 2)[1];
      if (!originalValue) throw new Error("Google state cookie was empty");
      const payload = await verifyVersionedValue(originalValue, config.secrets);
      if (!payload) throw new Error("Google state could not be decoded");
      const state = JSON.parse(payload) as { state: string; issuedAt: number | string };
      state.issuedAt = issuedAt;
      expect(state.issuedAt, label).toBe(issuedAt);
      const modifiedValue = await signVersionedValue(JSON.stringify(state), config.secrets[0]);
      let upstreamCalls = 0;
      const response = await completeGoogleLogin(
        new Request(`${config.issuer}/callback/google?code=${label}&state=${encodeURIComponent(state.state)}`, {
          headers: { cookie: `__Host-auth_google_state=${modifiedValue}` },
        }),
        createAuth(env),
        config,
        {
          stateStore: env.DB,
          now: () => now,
          fetch: async () => {
            upstreamCalls += 1;
            throw new Error("upstream must not be called");
          },
        },
      );
      expect(response.status).toBe(400);
      expect(await response.text(), label).toBe("Bad request");
      expect(upstreamCalls).toBe(0);
      const row = await env.DB.prepare("SELECT id FROM verification WHERE id = ? AND value = ?")
        .bind(`google-oauth-state:${state.state}`, state.state)
        .first();
      if (label === "expired-state" || label === "boundary-state") expect(row).toBeNull();
      else expect(row).not.toBeNull();
    }
  });

  it("enforces a bounded active Google state cap atomically and ignores expired rows", async () => {
    const config = getRuntimeConfig(env);
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare("DELETE FROM verification WHERE identifier = ?").bind("google-oauth-state").run();
    await env.DB.prepare(
      "INSERT INTO verification (id, identifier, value, expiresAt, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)",
    )
      .bind(
        "google-cap-active",
        "google-oauth-state",
        "google-cap-active-value",
        new Date((now + 300) * 1000).toISOString(),
        new Date(now * 1000).toISOString(),
        new Date(now * 1000).toISOString(),
      )
      .run();
    const rejected = await startGoogleLogin(new Request(`${config.issuer}/sign-in/google`), config, env.DB, {
      maxPendingStates: 1,
      now: () => now,
    });
    expect(rejected.status).toBe(429);
    expect(rejected.headers.has("set-cookie")).toBe(false);
    const rejectedRows = await env.DB.prepare("SELECT COUNT(*) AS count FROM verification WHERE identifier = ?")
      .bind("google-oauth-state")
      .first<{ count: number }>();
    expect(rejectedRows?.count).toBe(1);
    await env.DB.prepare("DELETE FROM verification WHERE id = ?").bind("google-cap-active").run();
    await env.DB.prepare(
      "INSERT INTO verification (id, identifier, value, expiresAt, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)",
    )
      .bind(
        "google-cap-expired",
        "google-oauth-state",
        "google-cap-expired-value",
        new Date((now - 1) * 1000).toISOString(),
        new Date((now - 300) * 1000).toISOString(),
        new Date((now - 300) * 1000).toISOString(),
      )
      .run();
    const accepted = await startGoogleLogin(new Request(`${config.issuer}/sign-in/google`), config, env.DB, {
      maxPendingStates: 1,
      now: () => now,
    });
    expect(accepted.status).toBe(302);
    expect(accepted.headers.get("set-cookie")).toContain("__Host-auth_google_state=");
  });

  it("admits only one concurrent state at the exact cap across different source IPs", async () => {
    const config = getRuntimeConfig(env);
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare("DELETE FROM verification WHERE identifier = ?").bind("google-oauth-state").run();
    const [first, second] = await Promise.all([
      startGoogleLogin(
        new Request(`${config.issuer}/sign-in/google`, { headers: { "cf-connecting-ip": "192.0.2.10" } }),
        config,
        env.DB,
        { maxPendingStates: 1, now: () => now },
      ),
      startGoogleLogin(
        new Request(`${config.issuer}/sign-in/google`, { headers: { "cf-connecting-ip": "192.0.2.11" } }),
        config,
        env.DB,
        { maxPendingStates: 1, now: () => now },
      ),
    ]);
    expect([first.status, second.status].sort((left, right) => left - right)).toEqual([302, 429]);
    const rows = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM verification WHERE identifier = ? AND expiresAt > ?",
    )
      .bind("google-oauth-state", new Date(now * 1000).toISOString())
      .first<{ count: number }>();
    expect(rows?.count).toBe(1);
  });

  it("enforces the standalone pending-state cap across different source IPs", async () => {
    const config = getRuntimeConfig(env);
    await env.DB.prepare("DELETE FROM verification WHERE identifier = ?").bind("google-oauth-state").run();
    const limits = {
      maxPendingStates: 10,
      maxPendingStandaloneStates: 1,
      maxPendingStatesPerSource: 10,
    } as const;
    const first = await startStandaloneLogin(config, "192.0.2.20", limits);
    const second = await startStandaloneLogin(config, "192.0.2.21", limits);
    expect(first.status).toBe(302);
    expect(second.status).toBe(429);
  });

  it("reserves pending-state capacity between standalone and relying-party flows", async () => {
    const config = getRuntimeConfig(env);
    const limits = {
      maxPendingStates: 3,
      maxPendingStandaloneStates: 1,
      maxPendingRelyingPartyStates: 2,
      maxPendingStatesPerSource: 3,
      maxPendingStatesPerClient: 2,
      maxPendingStatesPerSourceClient: 2,
    } as const;
    const clearPendingState = async () => {
      await env.DB.prepare("DELETE FROM verification WHERE identifier = ?").bind("google-oauth-state").run();
      await env.DB.prepare("DELETE FROM oauthAuthorizationAdmission").run();
    };

    await clearPendingState();
    expect((await startStandaloneLogin(config, "192.0.2.30", limits)).status).toBe(302);
    expect((await startStandaloneLogin(config, "192.0.2.31", limits)).status).toBe(429);
    expect((await startRelyingPartyLogin(config, "client-reserve-a", "reserve-a", "192.0.2.32", limits)).status).toBe(
      302,
    );

    await clearPendingState();
    for (const [label, address] of [
      ["reserve-b", "192.0.2.33"],
      ["reserve-c", "192.0.2.34"],
    ] as const) {
      expect((await startRelyingPartyLogin(config, `client-${label}`, label, address, limits)).status).toBe(302);
    }
    expect((await startRelyingPartyLogin(config, "client-reserve-d", "reserve-d", "192.0.2.35", limits)).status).toBe(
      429,
    );
    expect((await startStandaloneLogin(config, "192.0.2.36", limits)).status).toBe(302);
  });

  it("limits one source from reserving an entire relying-party client partition", async () => {
    const config = getRuntimeConfig(env);
    await env.DB.prepare("DELETE FROM verification WHERE identifier = ?").bind("google-oauth-state").run();
    await env.DB.prepare("DELETE FROM oauthAuthorizationAdmission").run();
    const limits = {
      maxPendingStates: 10,
      maxPendingStandaloneStates: 2,
      maxPendingRelyingPartyStates: 8,
      maxPendingStatesPerSource: 10,
      maxPendingStatesPerClient: 8,
      maxPendingStatesPerSourceClient: 1,
    } as const;
    const clientId = "client-source-partition";
    for (const [label, address, expected] of [
      ["source-partition-a", "192.0.2.40", 302],
      ["source-partition-b", "192.0.2.40", 429],
      ["source-partition-c", "192.0.2.41", 302],
    ] as const) {
      const response = await startRelyingPartyLogin(config, clientId, label, address, limits);
      expect(response.status, label).toBe(expected);
    }
  });

  it("contains active Google states by source and client while isolating unrelated sources", async () => {
    const config = getRuntimeConfig(env);
    await env.DB.prepare("DELETE FROM verification WHERE identifier = ?").bind("google-oauth-state").run();
    const sourceOptions = {
      maxPendingStates: 10,
      maxPendingStatesPerSource: 1,
      maxPendingStatesPerClient: 10,
    } as const;
    const first = await startGoogleLogin(
      new Request(`${config.issuer}/sign-in/google`, { headers: { "cf-connecting-ip": "192.0.2.70" } }),
      config,
      env.DB,
      sourceOptions,
    );
    const sameSource = await startGoogleLogin(
      new Request(`${config.issuer}/sign-in/google`, { headers: { "cf-connecting-ip": "192.0.2.70" } }),
      config,
      env.DB,
      sourceOptions,
    );
    const unrelatedSource = await startGoogleLogin(
      new Request(`${config.issuer}/sign-in/google`, { headers: { "cf-connecting-ip": "192.0.2.71" } }),
      config,
      env.DB,
      sourceOptions,
    );
    expect(first.status).toBe(302);
    expect(sameSource.status).toBe(429);
    expect(unrelatedSource.status).toBe(302);

    await env.DB.prepare("DELETE FROM verification WHERE identifier = ?").bind("google-oauth-state").run();
    await env.DB.prepare("DELETE FROM oauthAuthorizationAdmission").run();
    const client = "client-pending-cap";
    const firstQuery = await createAuthorizationContinuation(config, client, "client-cap-a", "192.0.2.72");
    const secondQuery = await createAuthorizationContinuation(config, client, "client-cap-b", "192.0.2.72");
    const clientCap = { maxPendingStates: 10, maxPendingStatesPerSource: 10, maxPendingStatesPerClient: 1 } as const;
    expect(
      (
        await startGoogleLogin(
          new Request(`${config.issuer}/sign-in/google?oauth_query=${encodeURIComponent(firstQuery)}`, {
            headers: { "cf-connecting-ip": "192.0.2.72" },
          }),
          config,
          env.DB,
          clientCap,
        )
      ).status,
    ).toBe(302);
    expect(
      (
        await startGoogleLogin(
          new Request(`${config.issuer}/sign-in/google?oauth_query=${encodeURIComponent(secondQuery)}`, {
            headers: { "cf-connecting-ip": "192.0.2.72" },
          }),
          config,
          env.DB,
          clientCap,
        )
      ).status,
    ).toBe(429);
  });

  it("drains expired state generations before enforcing the persisted cap", async () => {
    const config = getRuntimeConfig(env);
    const base = Math.floor(Date.now() / 1000);
    await env.DB.prepare("DELETE FROM verification WHERE identifier = ?").bind("google-oauth-state").run();
    for (const generation of [0, 301, 602]) {
      const response = await startGoogleLogin(new Request(`${config.issuer}/sign-in/google`), config, env.DB, {
        maxPendingStates: 1,
        now: () => base + generation,
      });
      expect(response.status, String(generation)).toBe(302);
    }
    const rows = await env.DB.prepare("SELECT COUNT(*) AS count FROM verification WHERE identifier = ?")
      .bind("google-oauth-state")
      .first<{ count: number }>();
    expect(rows?.count).toBe(1);
  });

  it("consumes the signed state once and rejects a repeated callback before upstream access", async () => {
    const config = getRuntimeConfig(env);
    const keyPair = await generateKeyPair("RS256");
    const keySet = createLocalJWKSet({ keys: [await exportJWK(keyPair.publicKey)] });
    const start = await startGoogleLogin(new Request(`${config.issuer}/sign-in/google`), config, env.DB);
    const setCookie = start.headers.get("set-cookie");
    if (!setCookie) throw new Error("Google state cookie was not set");
    const cookie = setCookie.split(";", 1)[0];
    if (!cookie) throw new Error("Google state cookie was empty");
    const encodedState = cookie.split("=", 2)[1];
    if (!encodedState) throw new Error("Google state cookie was empty");
    const payload = await verifyVersionedValue(encodedState, config.secrets);
    if (!payload) throw new Error("Google state could not be decoded");
    const state = JSON.parse(payload) as { state: string; nonce: string };
    const token = await signedToken(keyPair, config, state.nonce, "state-replay");
    let upstreamCalls = 0;
    const request = () =>
      new Request(`${config.issuer}/callback/google?code=state-replay&state=${encodeURIComponent(state.state)}`, {
        headers: { cookie },
      });
    const complete = () =>
      completeGoogleLogin(request(), createAuth(env, keySet), config, {
        stateStore: env.DB,
        keySet,
        fetch: async () => {
          upstreamCalls += 1;
          return Response.json({ id_token: token, access_token: "state-replay-access" });
        },
      });
    const first = await complete();
    expect(first.status).toBe(302);
    const second = await complete();
    expect(second.status).toBe(400);
    expect(await second.text()).toBe("Bad request");
    expect(upstreamCalls).toBe(1);
  });

  it("does not expose Google tokens or upstream secrets in callback responses or logs", async () => {
    const marker = "marker-google-id-token-secret";
    const logs: string[] = [];
    const spies = [
      vi.spyOn(console, "debug").mockImplementation((...values) => logs.push(values.join(" "))),
      vi.spyOn(console, "info").mockImplementation((...values) => logs.push(values.join(" "))),
      vi.spyOn(console, "warn").mockImplementation((...values) => logs.push(values.join(" "))),
      vi.spyOn(console, "error").mockImplementation((...values) => logs.push(values.join(" "))),
    ];
    try {
      const response = await callbackFixture(
        "redaction",
        JSON.stringify({ id_token: marker, access_token: "marker-google-access-token" }),
      );
      const body = await response.text();
      expect(body).toBe("Authentication failed");
      expect(body).not.toContain(marker);
      expect(body).not.toContain("marker-google-access-token");
      expect(logs.join("\n")).not.toContain(marker);
      expect(logs.join("\n")).not.toContain("marker-google-access-token");
    } finally {
      for (const spy of spies) spy.mockRestore();
    }
  });
});
