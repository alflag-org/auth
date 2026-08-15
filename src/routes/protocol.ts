import type { Context, Hono } from "hono";
import {
  admitAuthorizationRequest,
  bindAuthorizationAdmission,
  oauthQueryDigest,
  releaseAuthorizationAdmission,
} from "../admission";
import { constantTimeEqual, sha256Base64Url } from "../crypto";
import {
  AUTHORIZATION_CODE_TTL_SECONDS,
  CODE_VERIFIER_PATTERN,
  KEY_GRACE_TTL_SECONDS,
  MAX_AUTHORIZATION_NONCE_LENGTH,
  MAX_AUTHORIZATION_PARAMETER_LENGTH,
  MAX_AUTHORIZATION_STATE_LENGTH,
  getRuntimeConfig,
} from "../config";
import type { AppBindings, AuthResolver } from "../http";
import {
  authorizeParameters,
  boundedParameter,
  hasDuplicateParameter,
  MAX_FORM_BODY_BYTES,
  readBoundedRequestBody,
  tokenParameters,
  allowRateLimitedRequest,
} from "../http";

const AUTHORIZATION_RESPONSE_PARAMETERS = new Set([
  "code",
  "state",
  "iss",
  "error",
  "error_description",
  "error_uri",
  "session_state",
  "response",
]);

function hasReservedAuthorizationParameter(value: string): boolean {
  try {
    const url = new URL(value);
    for (const name of url.searchParams.keys()) {
      if (AUTHORIZATION_RESPONSE_PARAMETERS.has(name)) return true;
    }
    return false;
  } catch {
    return true;
  }
}

function sameQueryValues(left: URLSearchParams, right: URLSearchParams): boolean {
  const names = new Set([...left.keys(), ...right.keys()]);
  for (const name of names) {
    if (left.getAll(name).length !== right.getAll(name).length) return false;
    if (left.getAll(name).some((value, index) => value !== right.getAll(name)[index])) return false;
  }
  return true;
}

type ProjectJWKSRow = {
  id: string;
  publicKey: string;
};

function publicJWK(row: ProjectJWKSRow): Record<string, string> | null {
  try {
    const parsed: unknown = JSON.parse(row.publicKey);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    const candidate = parsed as Record<string, unknown>;
    if (
      candidate.kty !== "EC" ||
      candidate.crv !== "P-256" ||
      typeof candidate.x !== "string" ||
      typeof candidate.y !== "string" ||
      !/^[A-Za-z0-9_-]+$/u.test(candidate.x) ||
      !/^[A-Za-z0-9_-]+$/u.test(candidate.y) ||
      (candidate.alg !== undefined && candidate.alg !== "ES256") ||
      (candidate.use !== undefined && candidate.use !== "sig") ||
      ["d", "p", "q", "dp", "dq", "qi", "k"].some((field) => field in candidate)
    )
      return null;
    return {
      kty: "EC",
      crv: "P-256",
      x: candidate.x,
      y: candidate.y,
      alg: "ES256",
      kid: row.id,
      ...(candidate.use === "sig" ? { use: "sig" } : {}),
    };
  } catch {
    return null;
  }
}

async function projectJWKS(database: D1Database, now = new Date()): Promise<Record<string, string>[]> {
  const cutoff = new Date(now.getTime() - KEY_GRACE_TTL_SECONDS * 1000).toISOString();
  const rows = await database
    .prepare(
      "SELECT id, publicKey, expiresAt FROM jwks WHERE revokedAt IS NULL AND (expiresAt IS NULL OR expiresAt > ?)",
    )
    .bind(cutoff)
    .all<ProjectJWKSRow>();
  return rows.results.flatMap((row) => {
    const key = publicJWK(row);
    return key ? [key] : [];
  });
}

async function wrapAuthorizationResponse(
  response: Response,
  redirectURI: string,
  issuer: string,
  database: D1Database,
  admission: Awaited<ReturnType<typeof admitAuthorizationRequest>>,
): Promise<Response> {
  const location = response.headers.get("location");
  if (!location) return response;
  let registered: URL;
  let callback: URL;
  try {
    registered = new URL(redirectURI);
    callback = new URL(location, issuer);
  } catch {
    return new Response(null, { status: 500, headers: { "Cache-Control": "no-store" } });
  }
  const issuerURL = new URL(issuer);
  if (callback.origin === issuerURL.origin && callback.pathname === "/sign-in") {
    if (admission) {
      const digest = await oauthQueryDigest(callback.searchParams.toString());
      if (!digest || !(await bindAuthorizationAdmission(database, admission.id, digest)))
        return new Response("Service unavailable", { status: 503, headers: { "Cache-Control": "no-store" } });
    }
    return response;
  }
  if (
    callback.origin !== registered.origin ||
    callback.pathname !== registered.pathname ||
    callback.hash ||
    hasReservedAuthorizationParameter(registered.toString())
  ) {
    return new Response(null, { status: 500, headers: { "Cache-Control": "no-store" } });
  }
  const registeredQuery = new URLSearchParams(registered.searchParams);
  const callbackQuery = new URLSearchParams(callback.searchParams);
  for (const name of AUTHORIZATION_RESPONSE_PARAMETERS) {
    if (callbackQuery.getAll(name).length > 1 || registeredQuery.has(name))
      return new Response(null, { status: 500, headers: { "Cache-Control": "no-store" } });
  }
  for (const name of callbackQuery.keys()) {
    if (!registeredQuery.has(name) && !AUTHORIZATION_RESPONSE_PARAMETERS.has(name))
      return new Response(null, { status: 500, headers: { "Cache-Control": "no-store" } });
  }
  const callbackRegisteredQuery = new URLSearchParams();
  for (const [name, value] of callbackQuery) {
    if (registeredQuery.has(name)) callbackRegisteredQuery.append(name, value);
  }
  if (!sameQueryValues(callbackRegisteredQuery, registeredQuery))
    return new Response(null, { status: 500, headers: { "Cache-Control": "no-store" } });
  callback.searchParams.set("iss", issuer);
  const headers = new Headers(response.headers);
  headers.set("location", callback.toString());
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

type OAuthClientRow = {
  redirectUris: string;
  disabled: number | null;
  clientSecret: string | null;
  public: number | null;
};

type AuthorizationCodeRow = {
  value: string;
  createdAt: string;
  expiresAt: string;
};

function errorRedirect(
  redirectURI: string,
  issuer: string,
  error: string,
  description: string,
  state: string | null,
): Response {
  const redirect = new URL(redirectURI);
  redirect.searchParams.set("error", error);
  redirect.searchParams.set("error_description", description);
  if (state) redirect.searchParams.set("state", state);
  redirect.searchParams.set("iss", issuer);
  return new Response(null, { status: 302, headers: { Location: redirect.toString(), "Cache-Control": "no-store" } });
}

async function verifiedAuthorizationTarget(
  database: D1Database,
  clientId: string | null,
  redirectURI: string | null,
): Promise<{ redirectURI: string; client: OAuthClientRow } | null> {
  if (!clientId || !redirectURI) return null;
  const client = await database
    .prepare("SELECT redirectUris, disabled, clientSecret, public FROM oauthClient WHERE clientId = ? LIMIT 1")
    .bind(clientId)
    .first<OAuthClientRow>();
  if (!client || client.disabled === 1) return null;
  let redirectURIs: unknown;
  try {
    redirectURIs = JSON.parse(client.redirectUris);
  } catch {
    return null;
  }
  if (!Array.isArray(redirectURIs) || !redirectURIs.includes(redirectURI)) return null;
  return { redirectURI, client };
}

function authorizationFailure(
  issuer: string,
  target: Awaited<ReturnType<typeof verifiedAuthorizationTarget>>,
  state: string | null,
  error: string,
  description: string,
): Response {
  return target
    ? errorRedirect(target.redirectURI, issuer, error, description, state)
    : new Response("Bad request", { status: 400 });
}

function invalidTokenResponse(): Response {
  return new Response(JSON.stringify({ error: "invalid_token" }), {
    status: 401,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json",
      "WWW-Authenticate": 'Bearer error="invalid_token"',
    },
  });
}

function invalidClientResponse(): Response {
  return new Response(JSON.stringify({ error: "invalid_client", error_description: "invalid client" }), {
    status: 401,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json",
      "WWW-Authenticate": 'Basic realm="oauth2/token"',
    },
  });
}

function invalidGrantResponse(): Response {
  return new Response(JSON.stringify({ error: "invalid_grant", error_description: "invalid code" }), {
    status: 400,
    headers: { "Cache-Control": "no-store", "Content-Type": "application/json" },
  });
}

async function normalizedAuthorizationRequest(request: Request): Promise<Request | Response> {
  if (request.method === "GET") return request;
  if (request.method !== "POST")
    return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, POST" } });
  const contentType = request.headers.get("content-type");
  if (contentType?.split(";", 1)[0]?.trim().toLowerCase() !== "application/x-www-form-urlencoded")
    return new Response("Bad request", { status: 400 });
  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (!Number.isFinite(contentLength) || contentLength > MAX_FORM_BODY_BYTES)
    return new Response("Bad request", { status: 400 });
  const body = await readBoundedRequestBody(request, MAX_FORM_BODY_BYTES);
  if (body === null) return new Response("Bad request", { status: 400 });
  const url = new URL(request.url);
  const form = new URLSearchParams(body);
  const names = new Set([...url.searchParams.keys(), ...form.keys()]);
  for (const name of names) {
    if (
      url.searchParams.getAll(name).length > 1 ||
      form.getAll(name).length > 1 ||
      (url.searchParams.has(name) && form.has(name))
    )
      return new Response("Bad request", { status: 400 });
  }
  for (const [name, value] of form) url.searchParams.set(name, value);
  const headers = new Headers(request.headers);
  headers.delete("content-length");
  return new Request(url, { method: "GET", headers, redirect: request.redirect });
}

async function validateAuthorizationCodeProof(
  database: D1Database,
  clientId: string,
  clientSecret: string,
  code: string,
  redirectURI: string,
  codeVerifier: string,
): Promise<{ ok: true } | { ok: false; client: boolean }> {
  const client = await database
    .prepare("SELECT clientSecret, disabled, public FROM oauthClient WHERE clientId = ? LIMIT 1")
    .bind(clientId)
    .first<{ clientSecret: string | null; disabled: number | null; public: number | null }>();
  if (!client || client.disabled === 1 || client.public === 1 || !client.clientSecret)
    return { ok: false, client: true };
  const suppliedSecret = await sha256Base64Url(clientSecret);
  if (!constantTimeEqual(suppliedSecret, client.clientSecret)) return { ok: false, client: true };
  const identifier = await sha256Base64Url(code);
  const verification = await database
    .prepare("SELECT value, createdAt, expiresAt FROM verification WHERE identifier = ? LIMIT 1")
    .bind(identifier)
    .first<AuthorizationCodeRow>();
  const now = Date.now();
  const createdAt = verification ? new Date(verification.createdAt).getTime() : Number.NaN;
  const expiresAt = verification ? new Date(verification.expiresAt).getTime() : Number.NaN;
  if (
    !verification ||
    !Number.isFinite(createdAt) ||
    !Number.isFinite(expiresAt) ||
    createdAt > now ||
    createdAt + AUTHORIZATION_CODE_TTL_SECONDS * 1000 <= now ||
    expiresAt <= now
  )
    return { ok: false, client: false };
  let value: {
    query?: { client_id?: string; redirect_uri?: string; code_challenge?: string; code_challenge_method?: string };
  };
  try {
    value = JSON.parse(verification.value) as typeof value;
  } catch {
    return { ok: false, client: false };
  }
  if (value.query?.client_id !== clientId) return { ok: false, client: false };
  if (value.query.redirect_uri !== redirectURI) return { ok: false, client: false };
  if (value.query.code_challenge !== undefined) {
    if (!CODE_VERIFIER_PATTERN.test(codeVerifier)) return { ok: false, client: false };
    const challenge = await sha256Base64Url(codeVerifier);
    if (value.query.code_challenge_method !== "S256" || !constantTimeEqual(challenge, value.query.code_challenge))
      return { ok: false, client: false };
  } else if (codeVerifier !== "") return { ok: false, client: false };
  return { ok: true };
}

export function registerProtocolRoutes(app: Hono<AppBindings>, resolveAuth: AuthResolver): void {
  const authorize = async (context: Context<AppBindings>) => {
    if (!(await allowRateLimitedRequest(context.req.raw, context.env.OAUTH_AUTHORIZE_RATE_LIMITER, "oauth:authorize")))
      return context.json({ error: "temporarily_unavailable" }, 503);
    const request = await normalizedAuthorizationRequest(context.req.raw);
    if (request instanceof Response) return request;
    const query = new URL(request.url).searchParams;
    const issuer = getRuntimeConfig(context.env).issuer;
    const target = await verifiedAuthorizationTarget(context.env.DB, query.get("client_id"), query.get("redirect_uri"));
    const state = query.getAll("state").length === 1 ? query.get("state") : null;
    if (hasDuplicateParameter(query, authorizeParameters))
      return authorizationFailure(issuer, target, state, "invalid_request", "duplicate parameter");
    if (query.has("resource"))
      return authorizationFailure(issuer, target, state, "invalid_request", "resource is not supported");
    const responseType = query.get("response_type");
    const nonce = query.get("nonce");
    const codeChallenge = query.get("code_challenge");
    if (responseType === null)
      return authorizationFailure(issuer, target, state, "invalid_request", "response_type is required");
    if (responseType !== "code")
      return authorizationFailure(issuer, target, state, "unsupported_response_type", "response_type is not supported");
    if (
      !boundedParameter(state, MAX_AUTHORIZATION_STATE_LENGTH) ||
      !boundedParameter(nonce, MAX_AUTHORIZATION_NONCE_LENGTH) ||
      !boundedParameter(codeChallenge, 128) ||
      query.get("code_challenge_method") !== "S256"
    )
      return authorizationFailure(issuer, target, state, "invalid_request", "authorization parameters are invalid");
    if (codeChallenge === null || !/^[A-Za-z0-9_-]{43}$/u.test(codeChallenge))
      return authorizationFailure(issuer, target, state, "invalid_request", "code_challenge is invalid");
    if (query.has("response_mode") && query.get("response_mode") !== "query")
      return authorizationFailure(issuer, target, state, "unsupported_response_mode", "response_mode is not supported");
    if (query.get("prompt") === "create")
      return authorizationFailure(issuer, target, state, "invalid_request", "authorization parameters are invalid");
    if (query.has("request") || query.has("request_uri"))
      return authorizationFailure(issuer, target, state, "invalid_request", "request objects are not supported");
    const scopes = (query.get("scope") ?? "").split(" ").filter(Boolean);
    if (
      new Set(scopes).size !== scopes.length ||
      !scopes.includes("openid") ||
      scopes.some((scope) => !["openid", "profile", "email"].includes(scope))
    )
      return authorizationFailure(issuer, target, state, "invalid_scope", "requested scope is not allowed");
    const clientId = query.get("client_id");
    const redirectURI = query.get("redirect_uri");
    if (
      !boundedParameter(clientId, 256) ||
      !boundedParameter(redirectURI, MAX_AUTHORIZATION_PARAMETER_LENGTH) ||
      !boundedParameter(query.get("scope"), MAX_AUTHORIZATION_PARAMETER_LENGTH)
    )
      return authorizationFailure(issuer, target, state, "invalid_request", "authorization parameters are invalid");
    if (clientId === null || redirectURI === null)
      return authorizationFailure(issuer, target, state, "invalid_request", "authorization parameters are invalid");
    const client = await context.env.DB.prepare(
      "SELECT redirectUris, disabled, tokenEndpointAuthMethod, grantTypes, responseTypes, public, type, requirePKCE, scopes FROM oauthClient WHERE clientId = ? LIMIT 1",
    )
      .bind(clientId)
      .first<{
        redirectUris: string;
        disabled: number | null;
        tokenEndpointAuthMethod: string | null;
        grantTypes: string | null;
        responseTypes: string | null;
        public: number | null;
        type: string | null;
        requirePKCE: number | null;
        scopes: string | null;
      }>();
    if (!client || client.disabled === 1) return context.json({ error: "invalid_client" }, 400);
    let redirectURIs: unknown;
    let grantTypes: unknown;
    let responseTypes: unknown;
    let allowedScopes: unknown;
    try {
      redirectURIs = JSON.parse(client.redirectUris);
      grantTypes = client.grantTypes ? JSON.parse(client.grantTypes) : [];
      responseTypes = client.responseTypes ? JSON.parse(client.responseTypes) : [];
      allowedScopes = client.scopes ? JSON.parse(client.scopes) : [];
    } catch {
      return authorizationFailure(issuer, target, state, "invalid_client", "client metadata is invalid");
    }
    if (
      client.tokenEndpointAuthMethod !== "client_secret_basic" ||
      client.public === 1 ||
      client.type !== "web" ||
      client.requirePKCE !== 1 ||
      !Array.isArray(grantTypes) ||
      grantTypes.length !== 1 ||
      grantTypes[0] !== "authorization_code" ||
      !Array.isArray(responseTypes) ||
      responseTypes.length !== 1 ||
      responseTypes[0] !== "code" ||
      !Array.isArray(allowedScopes) ||
      scopes.some((scope) => !allowedScopes.includes(scope)) ||
      !Array.isArray(redirectURIs) ||
      !redirectURIs.every((value): value is string => typeof value === "string") ||
      redirectURIs.some(hasReservedAuthorizationParameter) ||
      !redirectURIs.includes(redirectURI)
    )
      return authorizationFailure(issuer, target, state, "invalid_request", "client metadata is invalid");
    let admission: Awaited<ReturnType<typeof admitAuthorizationRequest>>;
    try {
      admission = await admitAuthorizationRequest(context.env.DB, request, clientId);
    } catch {
      return context.json({ error: "temporarily_unavailable" }, 503);
    }
    if (!admission) return context.json({ error: "temporarily_unavailable" }, 503);
    try {
      const response = await resolveAuth(context.env).handler(request);
      const wrapped = await wrapAuthorizationResponse(response, redirectURI, issuer, context.env.DB, admission);
      const location = wrapped.headers.get("location");
      const isSignInRedirect = (() => {
        if (!location) return false;
        try {
          const url = new URL(location, issuer);
          const issuerURL = new URL(issuer);
          return url.origin === issuerURL.origin && url.pathname === "/sign-in";
        } catch {
          return false;
        }
      })();
      if (wrapped.status >= 400 || !isSignInRedirect) await releaseAuthorizationAdmission(context.env.DB, admission.id);
      return wrapped;
    } catch (error) {
      await releaseAuthorizationAdmission(context.env.DB, admission.id);
      throw error;
    }
  };
  app.on(["GET", "POST"], "/oauth2/authorize", authorize);

  app.on(["GET", "POST"], "/oauth2/userinfo", async (context) => {
    if (!(await allowRateLimitedRequest(context.req.raw, context.env.OAUTH_USERINFO_RATE_LIMITER, "oauth:userinfo")))
      return context.json({ error: "temporarily_unavailable" }, 503);
    const requestURL = new URL(context.req.raw.url);
    if ([...requestURL.searchParams.keys()].length > 0) return context.json({ error: "invalid_request" }, 400);
    let userInfoBody: string | undefined;
    if (context.req.method === "POST") {
      const contentType = context.req.header("content-type");
      if (contentType?.split(";", 1)[0]?.trim().toLowerCase() !== "application/x-www-form-urlencoded")
        return context.json({ error: "invalid_request" }, 400);
      const contentLength = Number(context.req.header("content-length") ?? "0");
      if (!Number.isFinite(contentLength) || contentLength > MAX_FORM_BODY_BYTES)
        return context.json({ error: "invalid_request" }, 400);
      const body = await readBoundedRequestBody(context.req.raw, MAX_FORM_BODY_BYTES);
      if (body === null || new URLSearchParams(body).size > 0) return context.json({ error: "invalid_request" }, 400);
      userInfoBody = body;
    }
    const authorization = context.req.header("authorization") ?? "";
    const bearerMatch = /^Bearer[ \t]+([^ \t]+)$/iu.exec(authorization);
    const token = bearerMatch?.[1] ?? "";
    if (!token) return invalidTokenResponse();
    const stored = await context.env.DB.prepare("SELECT expiresAt FROM oauthAccessToken WHERE token = ? LIMIT 1")
      .bind(await sha256Base64Url(token))
      .first<{ expiresAt: string }>();
    const expiresAt = stored ? new Date(stored.expiresAt).getTime() : Number.NaN;
    if (!stored || !Number.isFinite(expiresAt) || expiresAt <= Date.now()) return invalidTokenResponse();
    const headers = new Headers(context.req.raw.headers);
    headers.set("authorization", `Bearer ${token}`);
    if (userInfoBody !== undefined) {
      headers.delete("content-length");
      headers.delete("content-type");
    }
    const response = await resolveAuth(context.env).handler(
      userInfoBody === undefined
        ? new Request(context.req.raw, { headers })
        : new Request(requestURL, { method: "GET", headers }),
    );
    if (response.status >= 400 && response.status < 500) return invalidTokenResponse();
    return response;
  });

  app.post("/oauth2/token", async (context) => {
    if (!(await allowRateLimitedRequest(context.req.raw, context.env.OAUTH_TOKEN_RATE_LIMITER, "oauth:token")))
      return context.json({ error: "temporarily_unavailable" }, 503);
    const authorization = context.req.header("authorization") ?? "";
    const basicMatch = /^Basic[ \t]+([^ \t]+)$/iu.exec(authorization);
    if (!basicMatch)
      return context.json({ error: "invalid_client" }, 401, { "WWW-Authenticate": 'Basic realm="oauth2/token"' });
    const encodedAuthorization = basicMatch[1];
    if (!encodedAuthorization)
      return context.json({ error: "invalid_client" }, 401, { "WWW-Authenticate": 'Basic realm="oauth2/token"' });
    let decodedAuthorization: string;
    try {
      decodedAuthorization = atob(encodedAuthorization);
    } catch {
      return context.json({ error: "invalid_client" }, 401, { "WWW-Authenticate": 'Basic realm="oauth2/token"' });
    }
    if (!decodedAuthorization.includes(":") || decodedAuthorization.startsWith(":"))
      return context.json({ error: "invalid_client" }, 401, { "WWW-Authenticate": 'Basic realm="oauth2/token"' });
    const contentType = context.req.header("content-type");
    if (contentType?.split(";", 1)[0]?.trim().toLowerCase() !== "application/x-www-form-urlencoded")
      return context.json({ error: "invalid_request" }, 400);
    const contentLength = Number(context.req.header("content-length") ?? "0");
    if (!Number.isFinite(contentLength) || contentLength > MAX_FORM_BODY_BYTES)
      return context.json({ error: "invalid_request" }, 400);
    const body = await readBoundedRequestBody(context.req.raw, MAX_FORM_BODY_BYTES);
    if (body === null) return context.json({ error: "invalid_request" }, 400);
    const query = new URL(context.req.raw.url).searchParams;
    if (hasDuplicateParameter(query, tokenParameters) || query.has("resource"))
      return context.json({ error: "invalid_request" }, 400);
    const params = new URLSearchParams(body);
    if (hasDuplicateParameter(params, tokenParameters)) return context.json({ error: "invalid_request" }, 400);
    if (params.has("resource")) return context.json({ error: "invalid_request" }, 400);
    if (params.has("client_secret") || params.has("client_id")) return context.json({ error: "invalid_client" }, 401);
    if (params.get("grant_type") !== "authorization_code")
      return context.json({ error: "unsupported_grant_type" }, 400);
    const clientID = decodedAuthorization.slice(0, decodedAuthorization.indexOf(":"));
    const clientSecret = decodedAuthorization.slice(decodedAuthorization.indexOf(":") + 1);
    const code = params.get("code");
    const redirectURI = params.get("redirect_uri");
    const codeVerifier = params.get("code_verifier") ?? "";
    if (
      !code ||
      code.length > MAX_AUTHORIZATION_PARAMETER_LENGTH ||
      !redirectURI ||
      redirectURI.length > MAX_AUTHORIZATION_PARAMETER_LENGTH
    )
      return context.json({ error: "invalid_request" }, 400);
    const proof = await validateAuthorizationCodeProof(
      context.env.DB,
      clientID,
      clientSecret,
      code,
      redirectURI,
      codeVerifier,
    );
    if (!proof.ok) return proof.client ? invalidClientResponse() : invalidGrantResponse();
    const headers = new Headers(context.req.raw.headers);
    headers.set("authorization", `Basic ${encodedAuthorization}`);
    headers.set("content-type", "application/x-www-form-urlencoded");
    const response = await resolveAuth(context.env).handler(
      new Request(context.req.raw, { body, headers, method: "POST" }),
    );
    if (response.status >= 400 && response.status < 500) return invalidGrantResponse();
    return response;
  });

  app.get("/jwks", async (context) => {
    const response = await resolveAuth(context.env).handler(context.req.raw);
    if (!response.ok) return response;
    try {
      const keys = await projectJWKS(context.env.DB);
      const headers = new Headers(response.headers);
      headers.set("content-type", "application/json");
      return new Response(JSON.stringify({ keys }), {
        status: response.status,
        statusText: response.statusText,
        headers,
      });
    } catch {
      return new Response(null, { status: 500 });
    }
  });
}
