import { env } from "cloudflare:workers";
import { createAuth } from "../../src/auth";

type SessionFixture = {
  userId: string;
  email: string;
  token: string;
  sessionId: string;
  name?: string;
  userAgent?: string;
  expiresAt?: Date;
};

async function signedSessionValue(token: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.BETTER_AUTH_SECRETS.split(":", 2)[1]),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(token));
  return `${token}.${btoa(String.fromCharCode(...new Uint8Array(signature)))}`;
}

export async function sessionCookie(fixture: SessionFixture): Promise<string> {
  const now = new Date();
  await env.DB.prepare(
    "INSERT OR IGNORE INTO user (id, name, email, emailVerified, image, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(fixture.userId, fixture.name ?? "Test user", fixture.email, 1, null, now.toISOString(), now.toISOString())
    .run();
  await env.DB.prepare(
    "INSERT OR REPLACE INTO session (id, expiresAt, token, createdAt, updatedAt, ipAddress, userAgent, userId) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(
      fixture.sessionId,
      (fixture.expiresAt ?? new Date(now.getTime() + 8 * 60 * 60 * 1000)).toISOString(),
      fixture.token,
      now.toISOString(),
      now.toISOString(),
      null,
      fixture.userAgent ?? "vitest",
      fixture.userId,
    )
    .run();
  return `__Host-better-auth.session_token=${await signedSessionValue(fixture.token)}`;
}

export async function operatorHeaders(label: string, userId = "test-operator"): Promise<Headers> {
  const cookie = await sessionCookie({
    userId,
    email: "operator@example.invalid",
    token: `operator-session-token-${label}`,
    sessionId: `operator-session-${label}`,
    name: "Test operator",
    userAgent: "operator-test",
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  });
  return new Headers({ cookie });
}

export async function createTestOAuthClient(options: {
  name: string;
  redirectURI: string;
  postLogoutRedirectURI?: string;
  scope?: string;
}) {
  return createAuth(env, undefined, { adminUserId: "test-operator" }).api.adminCreateOAuthClient({
    headers: await operatorHeaders(options.name),
    body: {
      client_name: options.name,
      redirect_uris: [options.redirectURI],
      post_logout_redirect_uris: [options.postLogoutRedirectURI ?? "https://app.example/signed-out"],
      scope: options.scope ?? "openid profile email",
      token_endpoint_auth_method: "client_secret_basic",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      type: "web",
      client_secret_expires_at: 0,
      skip_consent: true,
      enable_end_session: true,
      require_pkce: true,
    },
  });
}

export async function codeChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

export function cookieValue(header: string, name: string): string | null {
  for (const part of header.split(";")) {
    const [candidate, ...value] = part.trim().split("=");
    if (candidate === name) return value.join("=") || null;
  }
  return null;
}
