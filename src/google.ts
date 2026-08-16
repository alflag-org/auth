import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";
import { z } from "zod";
import {
  GOOGLE_AUTHORIZATION_URL,
  GOOGLE_CALLBACK_PATH,
  GOOGLE_CERTS_URL,
  GOOGLE_ISSUERS,
  GOOGLE_TOKEN_URL,
  GOOGLE_LOGIN_TRANSACTION_TTL_SECONDS,
  MAX_AUTHORIZATION_PARAMETER_LENGTH,
  MAX_AUTHORIZATION_STATE_LENGTH,
  MAX_AUTHORIZATION_NONCE_LENGTH,
  MAX_CODE_VERIFIER_LENGTH,
  MAX_PENDING_GOOGLE_STATES,
  MAX_PENDING_RELYING_PARTY_GOOGLE_STATES,
  MAX_PENDING_STANDALONE_GOOGLE_STATES,
  SCOPES,
  type RuntimeConfig,
} from "./config";
import { randomString, sha256Base64Url, signVersionedValue, verifyVersionedValue } from "./crypto";
import type { AuthInstance } from "./auth";
import {
  claimAuthorizationAdmission,
  consumeAuthorizationAdmission,
  MAX_PENDING_GOOGLE_STATES_PER_CLIENT,
  MAX_PENDING_GOOGLE_STATES_PER_SOURCE,
  MAX_PENDING_GOOGLE_STATES_PER_SOURCE_CLIENT,
  releaseAuthorizationContinuation,
  releaseUnstartedAuthorizationContinuation,
  requestSourceKey,
  oauthQueryDigest,
} from "./admission";

const GOOGLE_STATE_COOKIE = "__Host-auth_google_state";
const GOOGLE_STATE_FUTURE_SKEW_SECONDS = 30;
const GOOGLE_STATE_IDENTIFIER = "google-oauth-state";
const GOOGLE_STATE_PURGE_BATCH_SIZE = 50;
const GOOGLE_CODE_MAX_LENGTH = MAX_AUTHORIZATION_PARAMETER_LENGTH;
const googleKeys = createRemoteJWKSet(new URL(GOOGLE_CERTS_URL));
const googleClaimsSchema = z.object({
  iss: z.union([z.literal(GOOGLE_ISSUERS[0]), z.literal(GOOGLE_ISSUERS[1])]),
  aud: z.string(),
  exp: z.number().int(),
  iat: z.number().int(),
  nonce: z.string(),
  sub: z.string().min(1),
  email: z.string().email(),
  email_verified: z.literal(true),
  name: z.string().min(1),
  hd: z.string().min(1),
  picture: z.string().url().optional(),
  given_name: z.string().optional(),
  family_name: z.string().optional(),
});

const googleTokenResponseSchema = z.object({
  id_token: z.string().min(1),
  access_token: z.string().optional(),
  token_type: z.string().optional(),
  expires_in: z.number().optional(),
  scope: z.string().optional(),
});

type GoogleState = {
  state: string;
  nonce: string;
  codeVerifier: string;
  issuedAt: number;
  oauthQuery?: string;
  oauthQueryDigest?: string;
  sourceKey: string;
  admissionId?: string;
};

type GoogleDependencies = {
  fetch?: typeof fetch;
  keySet?: JWTVerifyGetKey;
  now?: () => number;
  stateStore?: D1Database;
  rateLimiter?: RateLimit;
  requireRateLimiter?: boolean;
  maxPendingStates?: number;
  maxPendingStandaloneStates?: number;
  maxPendingRelyingPartyStates?: number;
  maxPendingStatesPerSource?: number;
  maxPendingStatesPerClient?: number;
  maxPendingStatesPerSourceClient?: number;
};

async function admitGoogleRequest(
  request: Request,
  rateLimiter: RateLimit | undefined,
  requireRateLimiter: boolean,
  operation: "start" | "callback",
): Promise<boolean> {
  if (!rateLimiter) return !requireRateLimiter;
  try {
    const address = request.headers.get("cf-connecting-ip");
    if (!address) return false;
    return (await rateLimiter.limit({ key: `google:${operation}:${address}` })).success;
  } catch {
    return false;
  }
}

function cookieValue(request: Request): string | null {
  const cookieHeader = request.headers.get("cookie") ?? "";
  for (const part of cookieHeader.split(";")) {
    const [name, ...value] = part.trim().split("=");
    if (name === GOOGLE_STATE_COOKIE) return value.join("=") || null;
  }
  return null;
}

function stateCookie(value: string, maxAge: number): string {
  return `${GOOGLE_STATE_COOKIE}=${value}; Max-Age=${maxAge}; Path=/; Secure; HttpOnly; SameSite=Lax`;
}

function clearStateCookie(): string {
  return stateCookie("", 0);
}

async function readBoundedText(response: Response, maxBytes: number): Promise<string> {
  const contentLengthHeader = response.headers.get("content-length");
  const contentLength = contentLengthHeader === null ? 0 : Number(contentLengthHeader);
  if (!Number.isFinite(contentLength) || contentLength > maxBytes) throw new Error("upstream response too large");
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      size += result.value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        throw new Error("upstream response too large");
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

export async function startGoogleLogin(
  request: Request,
  config: RuntimeConfig,
  stateStore: D1Database,
  dependencies: Pick<
    GoogleDependencies,
    | "rateLimiter"
    | "requireRateLimiter"
    | "maxPendingStates"
    | "maxPendingStandaloneStates"
    | "maxPendingRelyingPartyStates"
    | "maxPendingStatesPerSource"
    | "maxPendingStatesPerClient"
    | "maxPendingStatesPerSourceClient"
    | "now"
  > = {},
): Promise<Response> {
  if (!(await admitGoogleRequest(request, dependencies.rateLimiter, dependencies.requireRateLimiter ?? false, "start")))
    return new Response("Too many requests", { status: 429, headers: { "Cache-Control": "no-store" } });
  const requestURL = new URL(request.url);
  const oauthQuery = requestURL.searchParams.get("oauth_query") ?? undefined;
  if (oauthQuery && oauthQuery.length > MAX_AUTHORIZATION_PARAMETER_LENGTH * 2)
    return new Response("Bad request", { status: 400 });
  const sourceKey = requestSourceKey(request);
  const state: GoogleState = {
    state: randomString(),
    nonce: randomString(),
    codeVerifier: randomString(48),
    issuedAt: dependencies.now?.() ?? Math.floor(Date.now() / 1000),
    sourceKey,
    ...(oauthQuery ? { oauthQuery } : {}),
  };
  let admission: Awaited<ReturnType<typeof claimAuthorizationAdmission>> = null;
  if (oauthQuery) {
    const oauthParams = new URLSearchParams(oauthQuery);
    const clientId = oauthParams.get("client_id");
    const digest = await oauthQueryDigest(oauthQuery);
    if (
      !clientId ||
      oauthParams.getAll("sig").length !== 1 ||
      oauthParams.getAll("exp").length !== 1 ||
      oauthParams.getAll("ba_iat").length !== 1 ||
      !digest
    )
      return new Response("Bad request", { status: 400, headers: { "Cache-Control": "no-store" } });
    try {
      admission = await claimAuthorizationAdmission(stateStore, digest, clientId, state.state, new Date());
    } catch {
      return new Response("Service unavailable", { status: 503, headers: { "Cache-Control": "no-store" } });
    }
    if (!admission) return new Response("Bad request", { status: 400, headers: { "Cache-Control": "no-store" } });
    state.oauthQueryDigest = digest;
    state.admissionId = admission.id;
  }
  const stateNow = new Date(state.issuedAt * 1000).toISOString();
  const stateExpiresAt = new Date((state.issuedAt + GOOGLE_LOGIN_TRANSACTION_TTL_SECONDS) * 1000).toISOString();
  const maxPendingStates = dependencies.maxPendingStates ?? MAX_PENDING_GOOGLE_STATES;
  const maxPendingStandaloneStates =
    dependencies.maxPendingStandaloneStates ?? Math.min(MAX_PENDING_STANDALONE_GOOGLE_STATES, maxPendingStates);
  const maxPendingRelyingPartyStates =
    dependencies.maxPendingRelyingPartyStates ?? Math.min(MAX_PENDING_RELYING_PARTY_GOOGLE_STATES, maxPendingStates);
  const maxPendingStatesPerSource = dependencies.maxPendingStatesPerSource ?? MAX_PENDING_GOOGLE_STATES_PER_SOURCE;
  const maxPendingStatesPerClient = dependencies.maxPendingStatesPerClient ?? MAX_PENDING_GOOGLE_STATES_PER_CLIENT;
  const maxPendingStatesPerSourceClient =
    dependencies.maxPendingStatesPerSourceClient ?? MAX_PENDING_GOOGLE_STATES_PER_SOURCE_CLIENT;
  if (
    !Number.isSafeInteger(maxPendingStates) ||
    maxPendingStates <= 0 ||
    !Number.isSafeInteger(maxPendingStandaloneStates) ||
    maxPendingStandaloneStates <= 0 ||
    maxPendingStandaloneStates > maxPendingStates ||
    !Number.isSafeInteger(maxPendingRelyingPartyStates) ||
    maxPendingRelyingPartyStates <= 0 ||
    maxPendingRelyingPartyStates > maxPendingStates ||
    !Number.isSafeInteger(maxPendingStatesPerSource) ||
    maxPendingStatesPerSource <= 0 ||
    !Number.isSafeInteger(maxPendingStatesPerClient) ||
    maxPendingStatesPerClient <= 0 ||
    !Number.isSafeInteger(maxPendingStatesPerSourceClient) ||
    maxPendingStatesPerSourceClient <= 0
  ) {
    if (admission) await releaseUnstartedAuthorizationContinuation(stateStore, admission.id, state.state);
    return new Response("Service unavailable", { status: 503, headers: { "Cache-Control": "no-store" } });
  }
  let inserted: D1Result<unknown>;
  try {
    const stateID = `${GOOGLE_STATE_IDENTIFIER}:${state.state}`;
    const clientId = admission?.clientId ?? null;
    const insertState =
      clientId !== null
        ? stateStore
            .prepare(
              `INSERT INTO verification
               (id, identifier, value, expiresAt, createdAt, updatedAt, googleSourceKey, googleClientId, googleAdmissionId)
             SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?
             WHERE (SELECT COUNT(*) FROM verification WHERE identifier = ?) < ?
               AND (SELECT COUNT(*) FROM verification WHERE identifier = ? AND googleSourceKey = ?) < ?
               AND (SELECT COUNT(*) FROM verification WHERE identifier = ? AND googleClientId IS NOT NULL) < ?
               AND (SELECT COUNT(*) FROM verification WHERE identifier = ? AND googleClientId = ?) < ?
               AND (SELECT COUNT(*) FROM verification
                    WHERE identifier = ? AND googleClientId = ? AND googleSourceKey = ?) < ?`,
            )
            .bind(
              stateID,
              GOOGLE_STATE_IDENTIFIER,
              state.state,
              stateExpiresAt,
              stateNow,
              stateNow,
              sourceKey,
              clientId,
              admission?.id ?? null,
              GOOGLE_STATE_IDENTIFIER,
              maxPendingStates,
              GOOGLE_STATE_IDENTIFIER,
              sourceKey,
              maxPendingStatesPerSource,
              GOOGLE_STATE_IDENTIFIER,
              maxPendingRelyingPartyStates,
              GOOGLE_STATE_IDENTIFIER,
              clientId,
              maxPendingStatesPerClient,
              GOOGLE_STATE_IDENTIFIER,
              clientId,
              sourceKey,
              maxPendingStatesPerSourceClient,
            )
        : stateStore
            .prepare(
              `INSERT INTO verification
               (id, identifier, value, expiresAt, createdAt, updatedAt, googleSourceKey, googleClientId, googleAdmissionId)
             SELECT ?, ?, ?, ?, ?, ?, ?, NULL, NULL
             WHERE (SELECT COUNT(*) FROM verification WHERE identifier = ?) < ?
               AND (SELECT COUNT(*) FROM verification WHERE identifier = ? AND googleSourceKey = ?) < ?
               AND (SELECT COUNT(*) FROM verification WHERE identifier = ? AND googleClientId IS NULL) < ?`,
            )
            .bind(
              stateID,
              GOOGLE_STATE_IDENTIFIER,
              state.state,
              stateExpiresAt,
              stateNow,
              stateNow,
              sourceKey,
              GOOGLE_STATE_IDENTIFIER,
              maxPendingStates,
              GOOGLE_STATE_IDENTIFIER,
              sourceKey,
              maxPendingStatesPerSource,
              GOOGLE_STATE_IDENTIFIER,
              maxPendingStandaloneStates,
            );
    const results = await stateStore.batch([
      stateStore
        .prepare(
          `DELETE FROM verification WHERE id IN (
             SELECT id FROM verification
             WHERE identifier = ? AND expiresAt <= ?
             ORDER BY expiresAt ASC, id ASC LIMIT ?
           )`,
        )
        .bind(GOOGLE_STATE_IDENTIFIER, stateNow, GOOGLE_STATE_PURGE_BATCH_SIZE),
      insertState,
    ]);
    inserted = results[1] as D1Result<unknown>;
  } catch {
    if (admission) await releaseUnstartedAuthorizationContinuation(stateStore, admission.id, state.state);
    return new Response("Service unavailable", { status: 503, headers: { "Cache-Control": "no-store" } });
  }
  if (inserted.meta.changes !== 1) {
    if (admission) await releaseUnstartedAuthorizationContinuation(stateStore, admission.id, state.state);
    return new Response("Too many requests", { status: 429, headers: { "Cache-Control": "no-store" } });
  }
  let encodedState: string;
  try {
    encodedState = await signVersionedValue(JSON.stringify(state), config.secrets[0]);
  } catch (error) {
    await stateStore
      .prepare("DELETE FROM verification WHERE id = ? AND value = ?")
      .bind(`${GOOGLE_STATE_IDENTIFIER}:${state.state}`, state.state)
      .run();
    if (admission) await releaseUnstartedAuthorizationContinuation(stateStore, admission.id, state.state);
    throw error;
  }
  const authorizationURL = new URL(GOOGLE_AUTHORIZATION_URL);
  authorizationURL.searchParams.set("client_id", config.googleClientId);
  authorizationURL.searchParams.set("redirect_uri", `${config.issuer}${GOOGLE_CALLBACK_PATH}`);
  authorizationURL.searchParams.set("response_type", "code");
  authorizationURL.searchParams.set("scope", SCOPES.join(" "));
  authorizationURL.searchParams.set("state", state.state);
  authorizationURL.searchParams.set("nonce", state.nonce);
  authorizationURL.searchParams.set("code_challenge", await sha256Base64Url(state.codeVerifier));
  authorizationURL.searchParams.set("code_challenge_method", "S256");
  authorizationURL.searchParams.set("hd", config.allowedGoogleDomain);
  return new Response(null, {
    status: 302,
    headers: {
      Location: authorizationURL.toString(),
      "Set-Cookie": stateCookie(encodedState, GOOGLE_LOGIN_TRANSACTION_TTL_SECONDS),
      "Cache-Control": "no-store",
    },
  });
}

export async function verifyGoogleIdentityToken(
  token: string,
  nonce: string,
  config: RuntimeConfig,
  keySet: JWTVerifyGetKey = googleKeys,
): Promise<void> {
  const result = await jwtVerify(token, keySet, {
    algorithms: ["RS256"],
    issuer: [...GOOGLE_ISSUERS],
    audience: config.googleClientId,
  });
  const audience = result.payload.aud;
  if (Array.isArray(audience) && (audience.length !== 1 || audience[0] !== config.googleClientId)) {
    throw new Error("Google identity verification failed");
  }
  const claims = googleClaimsSchema.parse({ ...result.payload, aud: audience });
  if (
    claims.aud !== config.googleClientId ||
    claims.nonce !== nonce ||
    claims.hd !== config.allowedGoogleDomain ||
    claims.iat > Math.floor(Date.now() / 1000) + GOOGLE_STATE_FUTURE_SKEW_SECONDS
  ) {
    throw new Error("Google identity verification failed");
  }
}

async function exchangeCode(
  code: string,
  state: GoogleState,
  config: RuntimeConfig,
  fetcher: typeof fetch,
): Promise<string> {
  const body = new URLSearchParams({
    code,
    client_id: config.googleClientId,
    client_secret: config.googleClientSecret,
    redirect_uri: `${config.issuer}${GOOGLE_CALLBACK_PATH}`,
    grant_type: "authorization_code",
    code_verifier: state.codeVerifier,
  });
  const response = await fetcher(GOOGLE_TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body,
  });
  const text = await readBoundedText(response, 64 * 1024);
  if (!response.ok) throw new Error("Google token exchange failed");
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error("Google token exchange failed");
  }
  const parsed = googleTokenResponseSchema.safeParse(json);
  if (!parsed.success) throw new Error("Google token exchange failed");
  return parsed.data.id_token;
}

function responseWithClearedState(response: Response): Response {
  const headers = new Headers(response.headers);
  const result = new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  result.headers.delete("Set-Cookie");
  for (const value of response.headers.getSetCookie()) result.headers.append("Set-Cookie", value);
  result.headers.append("Set-Cookie", clearStateCookie());
  result.headers.set("Cache-Control", "no-store");
  return result;
}

export async function completeGoogleLogin(
  request: Request,
  auth: AuthInstance,
  config: RuntimeConfig,
  dependencies: GoogleDependencies = {},
): Promise<Response> {
  const requestURL = new URL(request.url);
  if (
    !(await admitGoogleRequest(request, dependencies.rateLimiter, dependencies.requireRateLimiter ?? false, "callback"))
  )
    return new Response("Too many requests", { status: 429, headers: { "Cache-Control": "no-store" } });
  if (["state", "code", "error"].some((name) => requestURL.searchParams.getAll(name).length > 1))
    return new Response("Bad request", { status: 400 });
  const callbackState = requestURL.searchParams.get("state");
  const callbackCode = requestURL.searchParams.get("code");
  const callbackError = requestURL.searchParams.get("error");
  if (
    (callbackState !== null && !boundedString(callbackState, MAX_AUTHORIZATION_STATE_LENGTH)) ||
    (callbackCode !== null && !boundedString(callbackCode, GOOGLE_CODE_MAX_LENGTH)) ||
    (callbackError !== null && !boundedString(callbackError, 128))
  )
    return new Response("Bad request", { status: 400 });
  const encodedState = cookieValue(request);
  if (!encodedState) return new Response("Bad request", { status: 400 });
  const statePayload = await verifyVersionedValue(encodedState, config.secrets);
  if (!statePayload) return new Response("Bad request", { status: 400 });
  let state: GoogleState;
  try {
    const parsed: unknown = JSON.parse(statePayload);
    if (!parsed || typeof parsed !== "object") throw new Error("invalid state");
    const candidate = parsed as Partial<GoogleState>;
    if (
      typeof candidate.state !== "string" ||
      typeof candidate.nonce !== "string" ||
      typeof candidate.codeVerifier !== "string" ||
      !Number.isSafeInteger(candidate.issuedAt) ||
      (candidate.oauthQuery !== undefined && typeof candidate.oauthQuery !== "string") ||
      typeof candidate.sourceKey !== "string" ||
      (candidate.admissionId !== undefined && typeof candidate.admissionId !== "string") ||
      (candidate.oauthQueryDigest !== undefined && typeof candidate.oauthQueryDigest !== "string")
    )
      throw new Error("invalid state");
    state = candidate as GoogleState;
  } catch {
    return new Response("Bad request", { status: 400, headers: { "Set-Cookie": clearStateCookie() } });
  }
  const now = dependencies.now?.() ?? Math.floor(Date.now() / 1000);
  if (
    state.issuedAt > now + GOOGLE_STATE_FUTURE_SKEW_SECONDS ||
    !boundedString(state.state, MAX_AUTHORIZATION_STATE_LENGTH) ||
    !boundedString(state.nonce, MAX_AUTHORIZATION_NONCE_LENGTH) ||
    !boundedString(state.codeVerifier, MAX_CODE_VERIFIER_LENGTH) ||
    (state.oauthQuery !== undefined && state.oauthQuery.length > MAX_AUTHORIZATION_PARAMETER_LENGTH * 2) ||
    !boundedString(state.sourceKey, 128) ||
    (state.admissionId !== undefined && !boundedString(state.admissionId, 256)) ||
    (state.oauthQueryDigest !== undefined && !/^[A-Za-z0-9_-]{43}$/u.test(state.oauthQueryDigest)) ||
    (state.admissionId !== undefined && (state.oauthQuery === undefined || state.oauthQueryDigest === undefined)) ||
    (state.oauthQuery === undefined && (state.admissionId !== undefined || state.oauthQueryDigest !== undefined))
  ) {
    return new Response("Bad request", { status: 400, headers: { "Set-Cookie": clearStateCookie() } });
  }
  if (requestURL.searchParams.get("state") !== state.state)
    return new Response("Bad request", { status: 400, headers: { "Set-Cookie": clearStateCookie() } });
  const stateStore = dependencies.stateStore;
  if (!stateStore) return new Response("Bad request", { status: 400, headers: { "Set-Cookie": clearStateCookie() } });
  const stateID = `${GOOGLE_STATE_IDENTIFIER}:${state.state}`;
  if (state.issuedAt + GOOGLE_LOGIN_TRANSACTION_TTL_SECONDS <= now) {
    await stateStore.prepare("DELETE FROM verification WHERE id = ? AND value = ?").bind(stateID, state.state).run();
    if (state.admissionId && state.oauthQueryDigest)
      await releaseAuthorizationContinuation(stateStore, state.admissionId, state.oauthQueryDigest, state.state);
    return new Response("Bad request", { status: 400, headers: { "Set-Cookie": clearStateCookie() } });
  }
  const consumed = await stateStore
    .prepare("DELETE FROM verification WHERE id = ? AND value = ? AND expiresAt > ?")
    .bind(stateID, state.state, new Date(now * 1000).toISOString())
    .run();
  if (consumed.meta.changes !== 1)
    return new Response("Bad request", { status: 400, headers: { "Set-Cookie": clearStateCookie() } });
  if (
    state.admissionId &&
    state.oauthQueryDigest &&
    !(await consumeAuthorizationAdmission(
      stateStore,
      state.admissionId,
      state.oauthQueryDigest,
      state.state,
      new Date(now * 1000),
    ))
  ) {
    await releaseAuthorizationContinuation(stateStore, state.admissionId, state.oauthQueryDigest, state.state);
    return new Response("Bad request", { status: 400, headers: { "Set-Cookie": clearStateCookie() } });
  }
  const abortAdmission = async (): Promise<void> => {
    if (state.admissionId && state.oauthQueryDigest)
      await releaseAuthorizationContinuation(stateStore, state.admissionId, state.oauthQueryDigest, state.state);
  };
  const error = requestURL.searchParams.get("error");
  if (error) {
    await abortAdmission();
    return new Response(null, {
      status: 302,
      headers: { Location: `${config.issuer}/sign-in?error=google`, "Set-Cookie": clearStateCookie() },
    });
  }
  const code = requestURL.searchParams.get("code");
  if (!code) {
    await abortAdmission();
    return new Response("Bad request", { status: 400, headers: { "Set-Cookie": clearStateCookie() } });
  }
  try {
    const fetcher = dependencies.fetch ?? fetch;
    const idToken = await exchangeCode(code, state, config, fetcher);
    await verifyGoogleIdentityToken(idToken, state.nonce, config, dependencies.keySet);
    const authRequest = new Request(`${config.issuer}/sign-in/social`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "text/html",
        "sec-fetch-mode": "navigate",
        origin: config.issuer,
        ...(request.headers.get("cookie") ? { cookie: request.headers.get("cookie") as string } : {}),
      },
      body: JSON.stringify({
        provider: "google",
        callbackURL: "/",
        ...(state.oauthQuery ? { oauth_query: state.oauthQuery } : {}),
        idToken: { token: idToken, nonce: state.nonce },
      }),
    });
    const authResponse = await auth.handler(authRequest);
    if (!authResponse.ok && ![301, 302, 303, 307, 308].includes(authResponse.status)) {
      await abortAdmission();
      return new Response("Authentication failed", {
        status: 400,
        headers: { "Set-Cookie": clearStateCookie(), "Cache-Control": "no-store" },
      });
    }
    if (!state.oauthQuery && authResponse.status === 200) {
      await abortAdmission();
      const result = new Response(null, { status: 302, headers: { Location: `${config.issuer}/` } });
      for (const value of authResponse.headers.getSetCookie()) result.headers.append("Set-Cookie", value);
      result.headers.append("Set-Cookie", clearStateCookie());
      result.headers.set("Cache-Control", "no-store");
      return result;
    }
    await abortAdmission();
    return responseWithClearedState(authResponse);
  } catch {
    await abortAdmission();
    return new Response("Authentication failed", {
      status: 400,
      headers: { "Set-Cookie": clearStateCookie(), "Cache-Control": "no-store" },
    });
  }
}

function boundedString(value: string, maximum: number): boolean {
  return value.length > 0 && value.length <= maximum;
}

export function oauthQueryFromSignIn(request: Request): string | null {
  const rawQuery = new URL(request.url).search.slice(1);
  if (!rawQuery) return null;
  const entries = rawQuery.split("&").filter((entry) => {
    const separator = entry.indexOf("=");
    const encodedName = separator === -1 ? entry : entry.slice(0, separator);
    try {
      return decodeURIComponent(encodedName.replaceAll("+", " ")) !== "error";
    } catch {
      return false;
    }
  });
  return entries.length > 0 ? entries.join("&") : null;
}
