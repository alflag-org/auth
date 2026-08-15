import { KEY_GRACE_TTL_SECONDS } from "./config";

export const VERIFICATION_CLEANUP_BATCH_SIZE = 500 as const;

export async function cleanupExpiredVerification(
  database: D1Database,
  now = new Date(),
  batchSize: number = VERIFICATION_CLEANUP_BATCH_SIZE,
  maxRounds = 1,
): Promise<number> {
  let total = 0;
  for (let round = 0; round < maxRounds; round += 1) {
    const cutoff = new Date(now.getTime() - KEY_GRACE_TTL_SECONDS * 1000).toISOString();
    const results = await database.batch([
      database
        .prepare(
          `DELETE FROM verification WHERE id IN (
             SELECT id FROM verification WHERE expiresAt <= ? ORDER BY expiresAt ASC, id ASC LIMIT ?
           )`,
        )
        .bind(now.toISOString(), batchSize),
      database
        .prepare(
          `DELETE FROM oauthAccessToken WHERE id IN (
             SELECT id FROM oauthAccessToken WHERE expiresAt <= ? ORDER BY expiresAt ASC, id ASC LIMIT ?
           )`,
        )
        .bind(now.toISOString(), batchSize),
      database
        .prepare(
          `DELETE FROM oauthAuthorizationAdmission WHERE id IN (
             SELECT id FROM oauthAuthorizationAdmission WHERE expiresAt <= ? ORDER BY expiresAt ASC, id ASC LIMIT ?
           )`,
        )
        .bind(now.toISOString(), batchSize),
      database
        .prepare(
          `DELETE FROM session WHERE id IN (
             SELECT id FROM session WHERE expiresAt <= ? ORDER BY expiresAt ASC, id ASC LIMIT ?
           )`,
        )
        .bind(now.toISOString(), batchSize),
      database
        .prepare(
          `DELETE FROM jwks WHERE id IN (
             SELECT id FROM jwks
             WHERE id NOT IN (SELECT id FROM jwks ORDER BY createdAt DESC, id DESC LIMIT 1)
               AND (revokedAt IS NOT NULL OR (expiresAt IS NOT NULL AND expiresAt <= ?))
             ORDER BY COALESCE(revokedAt, expiresAt) ASC, id ASC LIMIT ?
           )`,
        )
        .bind(cutoff, batchSize),
    ]);
    const roundTotal = results.reduce((sum, result) => sum + result.meta.changes, 0);
    total += roundTotal;
    if (roundTotal === 0) break;
  }
  return total;
}
