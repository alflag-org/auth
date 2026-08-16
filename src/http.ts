import type { Hono } from "hono";
import type { AuthInstance } from "./auth";

export type AppBindings = {
  Bindings: Env;
};

export type AuthResolver = (environment: Env) => AuthInstance;

export const authorizeParameters = [
  "client_id",
  "redirect_uri",
  "response_type",
  "scope",
  "state",
  "nonce",
  "code_challenge",
  "code_challenge_method",
  "response_mode",
  "prompt",
  "request",
  "request_uri",
  "resource",
] as const;
export const tokenParameters = [
  "grant_type",
  "code",
  "redirect_uri",
  "code_verifier",
  "client_id",
  "client_secret",
  "resource",
] as const;
export const endSessionParameters = ["id_token_hint", "client_id", "post_logout_redirect_uri", "state"] as const;

export const securityHeaders = {
  "Content-Security-Policy":
    "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
} as const;

export const MAX_FORM_BODY_BYTES = 16_384 as const;

export function hasTrustedMutationOrigin(request: Request, issuer: string): boolean {
  const origin = request.headers.get("origin");
  return origin === issuer || (origin === "null" && request.headers.get("sec-fetch-site") === "same-origin");
}

const noStorePaths = new Set([
  "/",
  "/sign-in",
  "/sign-out",
  "/sign-in/google",
  "/callback/google",
  "/oauth2/authorize",
  "/oauth2/token",
  "/oauth2/userinfo",
  "/oauth2/end-session",
]);

export async function allowRateLimitedRequest(
  request: Request,
  limiter: RateLimit | undefined,
  operation: string,
): Promise<boolean> {
  const address = request.headers.get("cf-connecting-ip");
  if (!limiter || !address || address.length > 128) return false;
  try {
    return (await limiter.limit({ key: `${operation}:${address}` })).success;
  } catch {
    return false;
  }
}

export function hasDuplicateParameter(parameters: URLSearchParams, names: readonly string[]): boolean {
  return names.some((name) => parameters.getAll(name).length > 1);
}

export async function readBoundedRequestBody(request: Request, maxBytes: number): Promise<string | null> {
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      size += result.value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        return null;
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

export function boundedParameter(value: string | null, maximum: number): value is string {
  return value !== null && value.length > 0 && value.length <= maximum;
}

export function registerSecurityMiddleware(app: Hono<AppBindings>): void {
  app.use("*", async (context, next) => {
    await next();
    for (const [name, value] of Object.entries(securityHeaders)) context.header(name, value);
    const contentType = context.res.headers.get("content-type") ?? "";
    if (noStorePaths.has(context.req.path) || contentType.toLowerCase().startsWith("text/html"))
      context.header("Cache-Control", "no-store");
  });
}
