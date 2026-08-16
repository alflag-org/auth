import { Hono } from "hono";
import { timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { createAuth } from "./auth";
import { getRuntimeConfig } from "./config";
import { randomString } from "./crypto";
import { revokeSigningKey, rotateSigningKey } from "./jwk";
import { MAX_FORM_BODY_BYTES, readBoundedRequestBody } from "./http";

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

function httpsUri(value: string, reservedParameters: ReadonlySet<string>): boolean {
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      !url.username &&
      !url.password &&
      !url.hash &&
      !value.includes("*") &&
      [...url.searchParams.keys()].every((name) => !reservedParameters.has(name))
    );
  } catch {
    return false;
  }
}

const clientInput = z.object({
  client_name: z.string().min(1).max(120),
  redirect_uris: z
    .array(
      z
        .string()
        .max(2048)
        .refine(
          (value) => httpsUri(value, AUTHORIZATION_RESPONSE_PARAMETERS),
          "redirect URI must be an HTTPS URL without a wildcard, fragment, or reserved response parameter",
        ),
    )
    .min(1)
    .max(8),
  post_logout_redirect_uris: z
    .array(
      z
        .string()
        .max(2048)
        .refine(
          (value) => httpsUri(value, new Set(["state"])),
          "post-logout redirect URI must be an HTTPS URL without a wildcard, fragment, or state parameter",
        ),
    )
    .min(1)
    .max(8),
});

const clientOutput = z.object({
  client_id: z.string().min(1),
  client_secret: z.string().min(1),
  client_secret_expires_at: z.number().int(),
});
const revokeInput = z.object({ key_id: z.string().min(1).max(128) }).strict();

async function signSessionCookie(value: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return `${value}.${btoa(String.fromCharCode(...new Uint8Array(signature)))}`;
}

async function operatorCookie(env: OperatorEnv): Promise<{ cookie: string; sessionId: string }> {
  const now = new Date();
  const userId = "local-operator";
  const userEmail = "local-operator@example.invalid";
  const sessionToken = randomString(48);
  const sessionId = randomString(32);
  await env.DB.prepare(
    "INSERT OR IGNORE INTO user (id, name, email, emailVerified, image, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(userId, "Local operator", userEmail, 1, null, now.toISOString(), now.toISOString())
    .run();
  const operator = await env.DB.prepare("SELECT id FROM user WHERE id = ? LIMIT 1")
    .bind(userId)
    .first<{ id: string }>();
  if (!operator) throw new Error("operator identity could not be created");
  await env.DB.prepare(
    "INSERT INTO session (id, expiresAt, token, createdAt, updatedAt, ipAddress, userAgent, userId) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(
      sessionId,
      new Date(now.getTime() + 5 * 60 * 1000).toISOString(),
      sessionToken,
      now.toISOString(),
      now.toISOString(),
      "127.0.0.1",
      "operator-cli",
      operator.id,
    )
    .run();
  const config = getRuntimeConfig(env);
  const signed = await signSessionCookie(sessionToken, config.secrets[0].value);
  return { cookie: `__Host-better-auth.session_token=${signed}`, sessionId };
}

function nonceMatches(candidate: string, expected: string): boolean {
  const candidateBytes = new TextEncoder().encode(candidate);
  const expectedBytes = new TextEncoder().encode(expected);
  return candidateBytes.byteLength === expectedBytes.byteLength && timingSafeEqual(candidateBytes, expectedBytes);
}

function operatorActionMatches(
  context: { env: OperatorEnv; req: { header(name: string): string | undefined } },
  action: string,
): boolean {
  const nonce = context.req.header("x-operator-nonce") ?? "";
  return (
    context.env.OPERATOR_ACTION === action &&
    context.env.OPERATOR_NONCE !== "set-by-client-create" &&
    /^[A-Za-z0-9_-]{43}$/u.test(context.env.OPERATOR_NONCE) &&
    nonceMatches(nonce, context.env.OPERATOR_NONCE)
  );
}

function strictJson<T extends z.ZodType>(schema: T, value: unknown): Response {
  return Response.json(schema.parse(value), { headers: { "Cache-Control": "no-store" } });
}

export function createOperatorApp(): Hono<{ Bindings: OperatorEnv }> {
  const app = new Hono<{ Bindings: OperatorEnv }>();
  const authByEnvironment = new WeakMap<object, ReturnType<typeof createAuth>>();
  app.get("/__operator/health", (context) => context.json({ status: "ok" }));
  app.post("/__operator/client-create", async (context) => {
    if (!operatorActionMatches(context, "client-create")) return context.text("Not Found", 404);
    const contentType = context.req.header("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
    const contentLength = Number(context.req.header("content-length") ?? "0");
    if (contentType !== "application/json" || !Number.isFinite(contentLength) || contentLength > MAX_FORM_BODY_BYTES)
      return context.json({ error: "invalid_request" }, 400);
    const rawBody = await readBoundedRequestBody(context.req.raw, MAX_FORM_BODY_BYTES);
    let parsedBody: unknown = null;
    try {
      parsedBody = rawBody === null ? null : JSON.parse(rawBody);
    } catch {
      parsedBody = null;
    }
    const body = clientInput.safeParse(parsedBody);
    if (!body.success) return context.json({ error: "invalid_request" }, 400);
    const operatorSession = await operatorCookie(context.env);
    try {
      const auth =
        authByEnvironment.get(context.env) ??
        (() => {
          const created = createAuth(context.env, undefined, { allowOperatorPrivileges: true });
          authByEnvironment.set(context.env, created);
          return created;
        })();
      const client = await auth.api.adminCreateOAuthClient({
        headers: new Headers({ cookie: operatorSession.cookie }),
        body: {
          ...body.data,
          scope: "openid profile email",
          token_endpoint_auth_method: "client_secret_basic",
          grant_types: ["authorization_code"],
          response_types: ["code"],
          type: "web",
          require_pkce: true,
          skip_consent: true,
          enable_end_session: true,
          client_secret_expires_at: 0,
        },
      });
      return strictJson(clientOutput, {
        client_id: client.client_id,
        client_secret: client.client_secret,
        client_secret_expires_at: client.client_secret_expires_at,
      });
    } finally {
      await context.env.DB.prepare("DELETE FROM session WHERE id = ?").bind(operatorSession.sessionId).run();
    }
  });
  app.post("/__operator/jwk-rotate", async (context) => {
    if (!operatorActionMatches(context, "jwk-rotate")) return context.text("Not Found", 404);
    const body = await readBoundedRequestBody(context.req.raw, 1);
    if (body === null || body !== "") return context.text("Not Found", 404);
    const config = getRuntimeConfig(context.env);
    const record = await rotateSigningKey(context.env.DB, config.secrets);
    return strictJson(z.object({ key_id: z.string().min(1) }), { key_id: record.id });
  });
  app.post("/__operator/jwk-revoke", async (context) => {
    if (!operatorActionMatches(context, "jwk-revoke")) return context.text("Not Found", 404);
    const body = await readBoundedRequestBody(context.req.raw, 256);
    if (body === null) return context.json({ error: "invalid_request" }, 400);
    let parsed: unknown = null;
    try {
      parsed = JSON.parse(body);
    } catch {
      parsed = null;
    }
    const input = revokeInput.safeParse(parsed);
    if (!input.success) return context.json({ error: "invalid_request" }, 400);
    const revoked = await revokeSigningKey(context.env.DB, input.data.key_id);
    if (!revoked) return context.json({ error: "invalid_request" }, 400);
    return strictJson(z.object({ key_id: z.string().min(1), revoked: z.literal(true) }), {
      key_id: input.data.key_id,
      revoked: true,
    });
  });
  return app;
}

const app = createOperatorApp();

export default {
  fetch: app.fetch,
} satisfies ExportedHandler<OperatorEnv>;
