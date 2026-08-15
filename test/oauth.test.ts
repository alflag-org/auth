import { symmetricDecrypt } from "better-auth/crypto";
import { env } from "cloudflare:workers";
import {
  createLocalJWKSet,
  decodeJwt,
  decodeProtectedHeader,
  importJWK,
  SignJWT,
  type JSONWebKeySet,
  jwtVerify,
} from "jose";
import { describe, expect, it } from "vitest";
import { KEY_GRACE_TTL_SECONDS, KEY_ROTATION_TTL_SECONDS } from "../src/config";
import { createTestOAuthClient, dispatch, sessionCookie } from "./support";

const redirectURI = "https://app-a.example/callback";
const issuer = "https://auth.example.invalid";
const postLogoutRedirectURI = "https://app.example/signed-out";

async function signedSessionCookie(userId: string, email: string): Promise<string> {
  return sessionCookie({
    userId,
    email,
    token: `session-${userId}`,
    sessionId: `session-row-${userId}`,
    name: "Workspace user",
  });
}

async function createClient(name: string, redirectURI: string) {
  return createTestOAuthClient({
    name,
    redirectURI,
    postLogoutRedirectURI: "https://app.example/signed-out",
  });
}

describe("OAuth provider", () => {
  it("reuses one central session across two relying parties", async () => {
    const cookie = await signedSessionCookie("workspace-sso-user", "sso-user@example.com");
    const appA = await createClient("Application A", "https://app-a.example/callback");
    const appB = await createClient("Application B", "https://app-b.example/callback");
    const authorize = async (clientId: string, redirectURI: string, label: string) => {
      const verifier = `verifier-${label}-abcdefghijklmnopqrstuvwxyz-0123456789`;
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
      const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
        .replaceAll("+", "-")
        .replaceAll("/", "_")
        .replace(/=+$/u, "");
      const url = new URL("https://auth.example.invalid/oauth2/authorize");
      url.search = new URLSearchParams({
        client_id: clientId,
        response_type: "code",
        redirect_uri: redirectURI,
        scope: "openid profile email",
        state: `state-${label}`,
        nonce: `nonce-${label}`,
        code_challenge: challenge,
        code_challenge_method: "S256",
      }).toString();
      const response = await dispatch(new Request(url, { headers: { cookie }, redirect: "manual" }));
      expect(response.status, await response.clone().text()).toBe(302);
      const location = new URL(response.headers.get("location") ?? "https://invalid.example/");
      expect(location.origin).toBe(new URL(redirectURI).origin);
      expect(location.pathname).toBe(new URL(redirectURI).pathname);
      return location;
    };
    const first = await authorize(appA.client_id, "https://app-a.example/callback", "a");
    const second = await authorize(appB.client_id, "https://app-b.example/callback", "b");
    expect(first.searchParams.get("code")).toBeTruthy();
    expect(second.searchParams.get("code")).toBeTruthy();
    expect(first.searchParams.get("state")).toBe("state-a");
    expect(second.searchParams.get("state")).toBe("state-b");
  });

  it("creates a confidential web client through Better Auth and requires login", async () => {
    const created = await createClient("App A", redirectURI);
    expect(created.client_id).toBeTypeOf("string");
    expect(created.client_secret).toBeTypeOf("string");

    const authorize = await dispatch(
      new Request(
        `https://auth.example.invalid/oauth2/authorize?client_id=${encodeURIComponent(created.client_id)}&response_type=code&redirect_uri=${encodeURIComponent(redirectURI)}&scope=openid%20profile%20email&state=state-a&nonce=nonce-a&code_challenge=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG&code_challenge_method=S256`,
        { redirect: "manual" },
      ),
    );
    expect(authorize.status).toBe(302);
    expect(
      new URL(authorize.headers.get("location") ?? "https://invalid/", "https://auth.example.invalid").pathname,
    ).toBe("/sign-in");
  });

  it("runs authorization code, PKCE, ID token, UserInfo, and single-use code checks", async () => {
    const client = await createClient("Protocol App", "https://app.example/callback");
    const cookie = await signedSessionCookie("workspace-user", "user@example.com");
    const codeVerifier = "verifier-abcdefghijklmnopqrstuvwxyz-0123456789";
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
    const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replace(/=+$/u, "");
    const authorizeURL = new URL("https://auth.example.invalid/oauth2/authorize");
    authorizeURL.search = new URLSearchParams({
      client_id: client.client_id,
      response_type: "code",
      redirect_uri: "https://app.example/callback",
      scope: "openid profile email",
      state: "state-protocol",
      nonce: "nonce-protocol",
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    }).toString();
    const authorization = await dispatch(new Request(authorizeURL, { headers: { cookie }, redirect: "manual" }));
    expect(authorization.status, await authorization.clone().text()).toBe(302);
    expect(authorization.headers.get("cache-control")).toBe("no-store");
    const callback = new URL(authorization.headers.get("location") ?? "https://invalid/");
    expect(callback.origin + callback.pathname).toBe("https://app.example/callback");
    expect(callback.searchParams.get("state")).toBe("state-protocol");
    const code = callback.searchParams.get("code");
    expect(code).toBeTruthy();
    if (!code) throw new Error("authorization response did not include a code");

    const basic = btoa(`${client.client_id}:${client.client_secret}`);
    const tokenResponse = await dispatch(
      new Request("https://auth.example.invalid/oauth2/token", {
        method: "POST",
        headers: { authorization: `bAsIc ${basic}`, "content-type": "Application/X-WWW-Form-Urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: "https://app.example/callback",
          code_verifier: codeVerifier,
        }),
      }),
    );
    expect(tokenResponse.status).toBe(200);
    expect(tokenResponse.headers.get("cache-control")).toBe("no-store");
    const tokens = (await tokenResponse.json()) as {
      access_token: string;
      id_token: string;
      refresh_token?: string;
      token_type: string;
      expires_in: number;
    };
    expect(tokens.token_type.toLowerCase()).toBe("bearer");
    expect(tokens.expires_in).toBe(600);
    expect(tokens.refresh_token).toBeUndefined();
    const idPayload = decodeJwt(tokens.id_token);
    if (typeof idPayload.exp !== "number" || typeof idPayload.iat !== "number")
      throw new Error("ID token did not contain numeric lifetime claims");
    expect(idPayload.exp - idPayload.iat).toBe(300);
    const initialKid = decodeProtectedHeader(tokens.id_token).kid;
    if (typeof initialKid !== "string") throw new Error("ID token did not contain a key id");
    const initialKey = await env.DB.prepare("SELECT createdAt, expiresAt FROM jwks WHERE id = ?")
      .bind(initialKid)
      .first<{ createdAt: string; expiresAt: string }>();
    expect(initialKey).not.toBeNull();
    const rotationLifetime =
      new Date(initialKey?.expiresAt ?? 0).getTime() - new Date(initialKey?.createdAt ?? 0).getTime();
    expect(rotationLifetime).toBeGreaterThanOrEqual(KEY_ROTATION_TTL_SECONDS * 1000 - 1000);
    expect(rotationLifetime).toBeLessThanOrEqual(KEY_ROTATION_TTL_SECONDS * 1000);
    const v1Secret = env.BETTER_AUTH_SECRETS.split(":", 2)[1];
    if (!v1Secret) throw new Error("test secret was not configured");
    const initialPrivateRow = await env.DB.prepare("SELECT privateKey FROM jwks WHERE id = ?")
      .bind(initialKid)
      .first<{ privateKey: string }>();
    if (!initialPrivateRow) throw new Error("initial private key was not stored");
    const initialPrivateJSON = await symmetricDecrypt({
      key: { keys: new Map([[1, v1Secret]]), currentVersion: 1 },
      data: JSON.parse(initialPrivateRow.privateKey),
    });
    const initialPrivateKey = await importJWK(JSON.parse(initialPrivateJSON), "ES256");
    const initialJwks = (await (
      await dispatch(new Request("https://auth.example.invalid/jwks"))
    ).json()) as JSONWebKeySet;
    const verifiedInitial = await jwtVerify(tokens.id_token, createLocalJWKSet(initialJwks), {
      issuer: "https://auth.example.invalid",
      audience: client.client_id,
    });
    expect(verifiedInitial.payload.sub).toBe("workspace-user");
    expect(verifiedInitial.payload.nonce).toBe("nonce-protocol");
    expect(verifiedInitial.payload.email).toBe("user@example.com");
    expect(verifiedInitial.payload.email_verified).toBe(true);
    await env.DB.prepare("UPDATE jwks SET expiresAt = ? WHERE id = ?")
      .bind(new Date(Date.now() - 1000).toISOString(), initialKid)
      .run();
    const rotatedVerifier = "rotated-verifier-abcdefghijklmnopqrstuvwxyz-0123456789";
    const rotatedDigest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rotatedVerifier));
    const rotatedChallenge = btoa(String.fromCharCode(...new Uint8Array(rotatedDigest)))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replace(/=+$/u, "");
    const rotatedAuthorizationURL = new URL("https://auth.example.invalid/oauth2/authorize");
    rotatedAuthorizationURL.search = new URLSearchParams({
      client_id: client.client_id,
      response_type: "code",
      redirect_uri: "https://app.example/callback",
      scope: "openid profile email",
      state: "rotation-state",
      nonce: "rotation-nonce",
      code_challenge: rotatedChallenge,
      code_challenge_method: "S256",
    }).toString();
    const rotatedAuthorization = await dispatch(
      new Request(rotatedAuthorizationURL, { headers: { cookie }, redirect: "manual" }),
    );
    const rotatedCode = new URL(rotatedAuthorization.headers.get("location") ?? "https://invalid/").searchParams.get(
      "code",
    );
    if (!rotatedCode) throw new Error("rotation authorization did not return a code");
    const rotatedTokenResponse = await dispatch(
      new Request("https://auth.example.invalid/oauth2/token", {
        method: "POST",
        headers: { authorization: `Basic ${basic}`, "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: rotatedCode,
          redirect_uri: "https://app.example/callback",
          code_verifier: rotatedVerifier,
        }),
      }),
    );
    expect(rotatedTokenResponse.status).toBe(200);
    const rotatedTokens = (await rotatedTokenResponse.json()) as { id_token: string };
    const rotatedKid = decodeProtectedHeader(rotatedTokens.id_token).kid;
    expect(rotatedKid).toBeTypeOf("string");
    expect(rotatedKid).not.toBe(initialKid);
    const graceKeys = (await (
      await dispatch(new Request("https://auth.example.invalid/jwks"))
    ).json()) as JSONWebKeySet;
    expect(graceKeys.keys.map((key) => key.kid)).toEqual(expect.arrayContaining([initialKid, rotatedKid]));
    await env.DB.prepare("UPDATE jwks SET expiresAt = ? WHERE id = ?")
      .bind(new Date(Date.now() - (KEY_GRACE_TTL_SECONDS * 1000 + 1000)).toISOString(), initialKid)
      .run();
    const expiredGraceKeys = (await (
      await dispatch(new Request("https://auth.example.invalid/jwks"))
    ).json()) as JSONWebKeySet;
    expect(expiredGraceKeys.keys.map((key) => key.kid)).not.toContain(initialKid);
    expect(expiredGraceKeys.keys.map((key) => key.kid)).toContain(rotatedKid);
    const staleFreshHint = await new SignJWT({ aud: client.client_id, sid: "session-row-workspace-user" })
      .setProtectedHeader({ alg: "ES256", kid: initialKid })
      .setIssuer(issuer)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(initialPrivateKey);
    const staleLogout = new URL(`${issuer}/oauth2/end-session`);
    staleLogout.search = new URLSearchParams({
      id_token_hint: staleFreshHint,
      client_id: client.client_id,
      post_logout_redirect_uri: postLogoutRedirectURI,
    }).toString();
    const staleLogoutResponse = await dispatch(new Request(staleLogout, { redirect: "manual" }));
    expect(staleLogoutResponse.status).toBe(400);
    const retainedSession = await env.DB.prepare("SELECT id FROM session WHERE id = ?")
      .bind("session-row-workspace-user")
      .first();
    expect(retainedSession).not.toBeNull();

    const userInfo = await dispatch(
      new Request("https://auth.example.invalid/oauth2/userinfo", {
        headers: { authorization: `bEaReR ${tokens.access_token}` },
      }),
    );
    expect(userInfo.status).toBe(200);
    expect(userInfo.headers.get("cache-control")).toBe("no-store");
    const userInfoBody = (await userInfo.json()) as { sub?: string };
    expect(userInfoBody.sub).toBe("workspace-user");
    const jwks = (await (await dispatch(new Request("https://auth.example.invalid/jwks"))).json()) as JSONWebKeySet;
    const verified = await jwtVerify(rotatedTokens.id_token, createLocalJWKSet(jwks), {
      issuer: "https://auth.example.invalid",
      audience: client.client_id,
    });
    expect(verified.payload.sub).toBe("workspace-user");
    expect(verified.payload.nonce).toBe("rotation-nonce");
    expect(verified.payload.email).toBe("user@example.com");
    expect(verified.payload.email_verified).toBe(true);

    const tamperedAccessToken = await dispatch(
      new Request("https://auth.example.invalid/oauth2/userinfo", {
        headers: { authorization: `Bearer ${tokens.access_token}tampered` },
      }),
    );
    expect(tamperedAccessToken.status).toBe(401);
    expect(tamperedAccessToken.headers.get("www-authenticate")).toBe('Bearer error="invalid_token"');
    expect(await tamperedAccessToken.json()).toEqual({ error: "invalid_token" });

    const freshVerifier = "fresh-verifier-abcdefghijklmnopqrstuvwxyz-0123456789";
    const freshDigest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(freshVerifier));
    const freshChallenge = btoa(String.fromCharCode(...new Uint8Array(freshDigest)))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replace(/=+$/u, "");
    const freshAuthorizationURL = new URL("https://auth.example.invalid/oauth2/authorize");
    freshAuthorizationURL.search = new URLSearchParams({
      client_id: client.client_id,
      response_type: "code",
      redirect_uri: "https://app.example/callback",
      scope: "openid profile email",
      state: "fresh-state",
      nonce: "fresh-nonce",
      code_challenge: freshChallenge,
      code_challenge_method: "S256",
    }).toString();
    const freshAuthorization = await dispatch(
      new Request(freshAuthorizationURL, { headers: { cookie }, redirect: "manual" }),
    );
    const freshCallback = new URL(freshAuthorization.headers.get("location") ?? "https://invalid.example/");
    const freshCode = freshCallback.searchParams.get("code");
    if (!freshCode) throw new Error("fresh authorization response did not include a code");
    const wrongFreshPKCE = await dispatch(
      new Request("https://auth.example.invalid/oauth2/token", {
        method: "POST",
        headers: { authorization: `Basic ${basic}`, "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: freshCode,
          redirect_uri: "https://app.example/callback",
          code_verifier: "wrong-fresh-verifier",
        }),
      }),
    );
    expect(wrongFreshPKCE.status).toBe(400);
    expect(await wrongFreshPKCE.json()).toEqual({ error: "invalid_grant", error_description: "invalid code" });

    const wrongSecret = await dispatch(
      new Request("https://auth.example.invalid/oauth2/token", {
        method: "POST",
        headers: {
          authorization: `Basic ${btoa(`${client.client_id}:wrong-secret`)}`,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: "invalid-code",
          redirect_uri: "https://app.example/callback",
          code_verifier: freshVerifier,
        }),
      }),
    );
    expect(wrongSecret.status).toBe(401);
    expect(wrongSecret.headers.get("www-authenticate")).toBe('Basic realm="oauth2/token"');
    const unsupportedGrant = await dispatch(
      new Request("https://auth.example.invalid/oauth2/token", {
        method: "POST",
        headers: { authorization: `Basic ${basic}`, "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "client_credentials" }),
      }),
    );
    expect(unsupportedGrant.status).toBe(400);
    expect(await unsupportedGrant.json()).toEqual({ error: "unsupported_grant_type" });

    const invalidPostLogout = await dispatch(
      new Request(
        `https://auth.example.invalid/oauth2/end-session?id_token_hint=${encodeURIComponent(tokens.id_token)}&post_logout_redirect_uri=${encodeURIComponent("https://evil.example/callback")}&client_id=${encodeURIComponent(client.client_id)}`,
        { headers: { cookie }, redirect: "manual" },
      ),
    );
    expect(invalidPostLogout.status).toBe(400);
    expect(await invalidPostLogout.json()).toEqual({ error: "invalid_request" });

    const globalLogout = await dispatch(
      new Request(
        `https://auth.example.invalid/oauth2/end-session?id_token_hint=${encodeURIComponent(rotatedTokens.id_token)}&post_logout_redirect_uri=${encodeURIComponent("https://app.example/signed-out")}&client_id=${encodeURIComponent(client.client_id)}`,
        { headers: { cookie }, redirect: "manual" },
      ),
    );
    expect(globalLogout.status, await globalLogout.clone().text()).toBe(302);
    expect(globalLogout.headers.get("location")).toBe("https://app.example/signed-out");
    const revokedSession = await env.DB.prepare("SELECT id FROM session WHERE id = ?")
      .bind(verified.payload.sid)
      .first<{ id: string }>();
    expect(revokedSession).toBeNull();
  });
});
