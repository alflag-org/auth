import type { AuthInstance } from "../auth";
import { getRuntimeConfig } from "../config";
import { hasTrustedMutationOrigin, type AppBindings, MAX_FORM_BODY_BYTES } from "../http";
import { createCSRFToken, CSRF_FIELD, readAdminForm, verifyCSRFToken } from "./csrf";

export type AuthSession = NonNullable<Awaited<ReturnType<AuthInstance["api"]["getSession"]>>>;

export type AdminAccess = {
  session: AuthSession;
  csrfToken: string;
};

export type AdminMutation = AdminAccess & {
  form: URLSearchParams;
};

function noStoreHeaders(contentType = "text/plain; charset=UTF-8"): Headers {
  return new Headers({ "Cache-Control": "no-store", "Content-Type": contentType });
}

export function forbiddenResponse(): Response {
  return new Response("Forbidden", { status: 403, headers: noStoreHeaders() });
}

export function badRequestResponse(): Response {
  return new Response("Bad request", { status: 400, headers: noStoreHeaders() });
}

export function serviceUnavailableResponse(): Response {
  return new Response("Service unavailable", { status: 503, headers: noStoreHeaders() });
}

export function signInRedirect(): Response {
  return new Response(null, {
    status: 302,
    headers: new Headers({ Location: "/sign-in", "Cache-Control": "no-store" }),
  });
}

export async function getSession(request: Request, auth: AuthInstance): Promise<AuthSession | null> {
  try {
    return await auth.api.getSession({ headers: new Headers(request.headers) });
  } catch {
    return null;
  }
}

export async function requireSession(request: Request, auth: AuthInstance): Promise<AuthSession | Response> {
  const session = await getSession(request, auth);
  return session ?? signInRedirect();
}

export async function requireAdmin(
  request: Request,
  environment: Env,
  auth: AuthInstance,
): Promise<AdminAccess | Response> {
  const session = await requireSession(request, auth);
  if (session instanceof Response) return session;
  const adminUserId = environment.AUTH_ADMIN_USER_ID;
  if (!adminUserId || session.user.id !== adminUserId) return forbiddenResponse();
  return {
    session,
    csrfToken: await createCSRFToken(session.session.id, environment),
  };
}

export async function requireAdminMutation(
  request: Request,
  environment: Env,
  auth: AuthInstance,
): Promise<AdminMutation | Response> {
  const issuer = getRuntimeConfig(environment).issuer;
  if (!hasTrustedMutationOrigin(request, issuer)) return forbiddenResponse();
  const access = await requireAdmin(request, environment, auth);
  if (access instanceof Response) return access;
  const form = await readAdminForm(request);
  if (!form) return badRequestResponse();
  const csrfToken = form.get(CSRF_FIELD);
  if (!(await verifyCSRFToken(csrfToken, access.session.session.id, environment))) return forbiddenResponse();
  return { ...access, form };
}

export function adminRequestId(request: Request): string {
  const cloudflareRequestId = request.headers.get("cf-ray");
  return cloudflareRequestId && cloudflareRequestId.length <= MAX_FORM_BODY_BYTES
    ? cloudflareRequestId
    : crypto.randomUUID();
}

export function logAdminFailure(request: Request, operation: string, error: unknown): void {
  const errorClass = error instanceof Error ? error.constructor.name : "UnknownError";
  console.error(
    JSON.stringify({
      event: "admin_operation_failed",
      operation,
      errorClass,
      requestId: adminRequestId(request),
    }),
  );
}

export function uiUser(session: AuthSession): { id: string; name: string; email: string } {
  return { id: session.user.id, name: session.user.name, email: session.user.email };
}

export type UIEnvironment = AppBindings["Bindings"];
