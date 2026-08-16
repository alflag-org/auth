import { getRuntimeConfig } from "../config";
import { signVersionedValue, verifyVersionedValue } from "../crypto";
import { MAX_FORM_BODY_BYTES, readBoundedRequestBody } from "../http";

export const CSRF_FIELD = "csrf_token";
export const MAX_ADMIN_FORM_BODY_BYTES = 64 * 1024;

export async function createCSRFToken(
  sessionId: string,
  environment: Parameters<typeof getRuntimeConfig>[0],
): Promise<string> {
  const config = getRuntimeConfig(environment);
  return signVersionedValue(`admin:${sessionId}`, config.secrets[0]);
}

export async function verifyCSRFToken(
  candidate: string | null,
  sessionId: string,
  environment: Parameters<typeof getRuntimeConfig>[0],
): Promise<boolean> {
  if (!candidate || candidate.length > MAX_FORM_BODY_BYTES) return false;
  const config = getRuntimeConfig(environment);
  return (await verifyVersionedValue(candidate, config.secrets)) === `admin:${sessionId}`;
}

export async function readAdminForm(request: Request): Promise<URLSearchParams | null> {
  const contentType = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/x-www-form-urlencoded") return null;
  const contentLengthHeader = request.headers.get("content-length");
  const contentLength = contentLengthHeader === null ? 0 : Number(contentLengthHeader);
  if (!Number.isFinite(contentLength) || contentLength > MAX_ADMIN_FORM_BODY_BYTES) return null;
  const body = await readBoundedRequestBody(request, MAX_ADMIN_FORM_BODY_BYTES);
  if (body === null) return null;
  const form = new URLSearchParams(body);
  for (const key of form.keys()) if (form.getAll(key).length > 1) return null;
  return form;
}
