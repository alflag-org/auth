import type { Hono } from "hono";
import { createLocalJWKSet, type JSONWebKeySet, type JWTPayload, jwtVerify } from "jose";
import { getRuntimeConfig } from "../config";
import { KEY_GRACE_TTL_SECONDS } from "../config";
import type { AppBindings, AuthResolver } from "../http";
import { allowRateLimitedRequest, endSessionParameters, hasDuplicateParameter } from "../http";

const MAX_RP_LOGOUT_STATE_LENGTH = 256;

function noStoreResponse(body: BodyInit | null, init: ResponseInit): Response {
  const headers = new Headers(init.headers);
  headers.set("Cache-Control", "no-store");
  return new Response(body, { ...init, headers });
}

export function registerLogoutRoutes(app: Hono<AppBindings>, resolveAuth: AuthResolver): void {
  app.get("/sign-out", (context) =>
    context.html(
      '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Sign out</title></head><body><main><h1>Sign out</h1><form method="post" action="/sign-out"><button type="submit">Sign out</button></form></main></body></html>',
    ),
  );

  app.post("/sign-out", async (context) => {
    const issuer = getRuntimeConfig(context.env).issuer;
    if (context.req.header("origin") !== issuer)
      return context.json({ error: "forbidden" }, 403, { "Cache-Control": "no-store" });
    const authRequest = new Request(`${issuer}/sign-out`, {
      method: "POST",
      headers: {
        origin: issuer,
        ...(context.req.header("cookie") ? { cookie: context.req.header("cookie") as string } : {}),
      },
    });
    const response = await resolveAuth(context.env).handler(authRequest);
    const result = noStoreResponse(null, { status: 302, headers: { Location: `${issuer}/` } });
    for (const value of response.headers.getSetCookie()) result.headers.append("Set-Cookie", value);
    return result;
  });

  app.get("/oauth2/end-session", async (context) => {
    if (
      !(await allowRateLimitedRequest(context.req.raw, context.env.OAUTH_END_SESSION_RATE_LIMITER, "oauth:end-session"))
    )
      return context.json({ error: "temporarily_unavailable" }, 503);
    const config = getRuntimeConfig(context.env);
    const query = new URL(context.req.raw.url).searchParams;
    if (hasDuplicateParameter(query, endSessionParameters)) return context.json({ error: "invalid_request" }, 400);
    const idTokenHint = query.get("id_token_hint");
    const clientId = query.get("client_id");
    const postLogoutRedirectURI = query.get("post_logout_redirect_uri");
    const state = query.get("state");
    if (!idTokenHint || idTokenHint.length > 16_384 || (state && state.length > MAX_RP_LOGOUT_STATE_LENGTH))
      return context.json({ error: "invalid_request" }, 400);

    let idTokenPayload: JWTPayload;
    try {
      const jwksRows = await context.env.DB.prepare("SELECT id, publicKey, expiresAt, revokedAt FROM jwks").all<{
        id: string;
        publicKey: string;
        expiresAt: string | null;
        revokedAt: string | null;
      }>();
      const keys = jwksRows.results.flatMap((row) => {
        if (row.revokedAt !== null) return [];
        if (row.expiresAt && new Date(row.expiresAt).getTime() + KEY_GRACE_TTL_SECONDS * 1000 <= Date.now()) return [];
        try {
          const parsed = JSON.parse(row.publicKey) as Record<string, unknown>;
          return [{ ...parsed, kid: row.id }];
        } catch {
          return [];
        }
      });
      const verified = await jwtVerify(idTokenHint, createLocalJWKSet({ keys } satisfies JSONWebKeySet), {
        issuer: config.issuer,
        algorithms: ["ES256"],
      });
      idTokenPayload = verified.payload;
    } catch {
      return context.json({ error: "invalid_request" }, 400);
    }
    const audiences = typeof idTokenPayload.aud === "string" ? [idTokenPayload.aud] : idTokenPayload.aud;
    const resolvedClientId = clientId ?? (audiences?.length === 1 ? audiences[0] : undefined);
    if (!resolvedClientId || !audiences?.includes(resolvedClientId) || typeof idTokenPayload.sid !== "string")
      return context.json({ error: "invalid_request" }, 400);
    const client = await context.env.DB.prepare(
      "SELECT disabled, enableEndSession, postLogoutRedirectUris FROM oauthClient WHERE clientId = ? LIMIT 1",
    )
      .bind(resolvedClientId)
      .first<{ disabled: number | null; enableEndSession: number | null; postLogoutRedirectUris: string | null }>();
    if (!client || client.disabled === 1 || client.enableEndSession !== 1)
      return context.json({ error: "invalid_client" }, 400);
    if (postLogoutRedirectURI) {
      let allowed: unknown;
      try {
        allowed = client.postLogoutRedirectUris ? JSON.parse(client.postLogoutRedirectUris) : [];
      } catch {
        return context.json({ error: "invalid_client" }, 400);
      }
      if (!Array.isArray(allowed) || !allowed.includes(postLogoutRedirectURI))
        return context.json({ error: "invalid_request" }, 400);
    }
    await context.env.DB.prepare("DELETE FROM session WHERE id = ?").bind(idTokenPayload.sid).run();
    if (postLogoutRedirectURI) {
      const redirect = new URL(postLogoutRedirectURI);
      if (state) redirect.searchParams.set("state", state);
      return noStoreResponse(null, { status: 302, headers: { Location: redirect.toString() } });
    }
    return noStoreResponse(null, { status: 204 });
  });
}
