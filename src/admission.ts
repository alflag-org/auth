import { GOOGLE_LOGIN_TRANSACTION_TTL_SECONDS } from "./config";
import { randomString, sha256Base64Url } from "./crypto";

export const MAX_AUTHORIZATION_ADMISSIONS = 1_000 as const;
export const MAX_AUTHORIZATION_ADMISSIONS_PER_SOURCE_CLIENT = 20 as const;
export const AUTHORIZATION_ADMISSION_PURGE_BATCH_SIZE = 50 as const;
export const MAX_PENDING_GOOGLE_STATES_PER_SOURCE = 25 as const;
export const MAX_PENDING_GOOGLE_STATES_PER_CLIENT = 50 as const;
export const MAX_PENDING_GOOGLE_STATES_PER_SOURCE_CLIENT = 10 as const;

export type AuthorizationAdmissionLimits = {
  globalCap?: number;
  perSourceClientCap?: number;
};

export type AuthorizationAdmission = {
  id: string;
  sourceKey: string;
  clientId: string;
  expiresAt: string;
};

export function requestSourceKey(request: Request): string {
  const address = request.headers.get("cf-connecting-ip")?.trim();
  return address && address.length <= 128 ? address : "unknown";
}

export function normalizeOAuthQuery(query: string): string | null {
  try {
    const entries = [...new URLSearchParams(query).entries()]
      .filter(([name]) => name !== "error")
      .sort(([leftName, leftValue], [rightName, rightValue]) =>
        leftName === rightName ? leftValue.localeCompare(rightValue) : leftName.localeCompare(rightName),
      );
    return new URLSearchParams(entries).toString();
  } catch {
    return null;
  }
}

export async function oauthQueryDigest(query: string): Promise<string | null> {
  const normalized = normalizeOAuthQuery(query);
  return normalized === null ? null : sha256Base64Url(normalized);
}

export async function admitAuthorizationRequest(
  database: D1Database,
  request: Request,
  clientId: string,
  now = new Date(),
  limits: AuthorizationAdmissionLimits = {},
): Promise<AuthorizationAdmission | null> {
  const globalCap = limits.globalCap ?? MAX_AUTHORIZATION_ADMISSIONS;
  const perSourceClientCap = limits.perSourceClientCap ?? MAX_AUTHORIZATION_ADMISSIONS_PER_SOURCE_CLIENT;
  if (
    !Number.isSafeInteger(globalCap) ||
    globalCap <= 0 ||
    !Number.isSafeInteger(perSourceClientCap) ||
    perSourceClientCap <= 0
  )
    return null;
  const admission: AuthorizationAdmission = {
    id: `oauth-authorization-admission:${randomString(16)}`,
    sourceKey: requestSourceKey(request),
    clientId,
    expiresAt: new Date(now.getTime() + GOOGLE_LOGIN_TRANSACTION_TTL_SECONDS * 1000).toISOString(),
  };
  const nowISO = now.toISOString();
  const results = await database.batch([
    database
      .prepare(
        `DELETE FROM oauthAuthorizationAdmission WHERE id IN (
           SELECT id FROM oauthAuthorizationAdmission
           WHERE expiresAt <= ? ORDER BY expiresAt ASC, id ASC LIMIT ?
         )`,
      )
      .bind(nowISO, AUTHORIZATION_ADMISSION_PURGE_BATCH_SIZE),
    database
      .prepare(
        `INSERT INTO oauthAuthorizationAdmission (id, sourceKey, clientId, expiresAt, createdAt)
         SELECT ?, ?, ?, ?, ?
         WHERE (SELECT COUNT(*) FROM oauthAuthorizationAdmission WHERE consumedAt IS NULL) < ?
           AND (SELECT COUNT(*) FROM oauthAuthorizationAdmission WHERE sourceKey = ? AND clientId = ? AND consumedAt IS NULL) < ?`,
      )
      .bind(
        admission.id,
        admission.sourceKey,
        admission.clientId,
        admission.expiresAt,
        nowISO,
        globalCap,
        admission.sourceKey,
        admission.clientId,
        perSourceClientCap,
      ),
  ]);
  return results[1]?.meta.changes === 1 ? admission : null;
}

export async function releaseAuthorizationAdmission(database: D1Database, id: string): Promise<void> {
  await database.prepare("DELETE FROM oauthAuthorizationAdmission WHERE id = ?").bind(id).run();
}

export async function bindAuthorizationAdmission(
  database: D1Database,
  id: string,
  digest: string,
  now = new Date(),
): Promise<boolean> {
  const result = await database
    .prepare(
      `UPDATE oauthAuthorizationAdmission
       SET continuationDigest = ?
       WHERE id = ? AND expiresAt > ? AND continuationDigest IS NULL`,
    )
    .bind(digest, id, now.toISOString())
    .run();
  return result.meta.changes === 1;
}

export async function claimAuthorizationAdmission(
  database: D1Database,
  digest: string,
  clientId: string,
  stateId: string,
  now = new Date(),
): Promise<AuthorizationAdmission | null> {
  const candidate = await database
    .prepare(
      `SELECT id, sourceKey, clientId, expiresAt
       FROM oauthAuthorizationAdmission
       WHERE continuationDigest = ? AND clientId = ? AND continuationStateId IS NULL AND expiresAt > ?
       ORDER BY createdAt ASC, id ASC LIMIT 1`,
    )
    .bind(digest, clientId, now.toISOString())
    .first<AuthorizationAdmission>();
  if (!candidate) return null;
  const result = await database
    .prepare(
      `UPDATE oauthAuthorizationAdmission
       SET continuationStateId = ?
       WHERE id = ? AND continuationDigest = ? AND continuationStateId IS NULL AND expiresAt > ?`,
    )
    .bind(stateId, candidate.id, digest, now.toISOString())
    .run();
  return result.meta.changes === 1 ? candidate : null;
}

export async function releaseUnstartedAuthorizationContinuation(
  database: D1Database,
  id: string,
  stateId: string,
): Promise<void> {
  await database
    .prepare(
      `UPDATE oauthAuthorizationAdmission
       SET continuationStateId = NULL
       WHERE id = ? AND continuationStateId = ? AND consumedAt IS NULL`,
    )
    .bind(id, stateId)
    .run();
}

export async function consumeAuthorizationAdmission(
  database: D1Database,
  id: string,
  digest: string,
  stateId: string,
  now = new Date(),
): Promise<boolean> {
  const result = await database
    .prepare(
      `UPDATE oauthAuthorizationAdmission
       SET consumedAt = ?
       WHERE id = ? AND continuationDigest = ? AND continuationStateId = ?
         AND consumedAt IS NULL AND expiresAt > ?`,
    )
    .bind(now.toISOString(), id, digest, stateId, now.toISOString())
    .run();
  return result.meta.changes === 1;
}

export async function releaseAuthorizationContinuation(
  database: D1Database,
  id: string,
  digest: string,
  stateId: string,
): Promise<void> {
  await database
    .prepare(
      `DELETE FROM oauthAuthorizationAdmission
       WHERE id = ? AND continuationDigest = ? AND continuationStateId = ?`,
    )
    .bind(id, digest, stateId)
    .run();
}
