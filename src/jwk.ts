import { symmetricEncrypt, type SecretConfig } from "better-auth/crypto";
import { exportJWK, generateKeyPair } from "jose";
import type { SecretVersion } from "./config";
import { KEY_ROTATION_TTL_SECONDS } from "./config";
import { randomString } from "./crypto";

export type SigningKeyRecord = {
  id: string;
  publicKey: string;
  privateKey: string;
  createdAt: string;
  expiresAt: string;
};

function secretConfig(secrets: SecretVersion[]): SecretConfig {
  return {
    keys: new Map(secrets.map((secret) => [secret.version, secret.value])),
    currentVersion: secrets[0]?.version ?? 0,
  };
}

export async function createRotatedSigningKey(secrets: SecretVersion[], now = new Date()): Promise<SigningKeyRecord> {
  if (secrets.length < 2) throw new Error("JWK rotation requires current and previous BETTER_AUTH_SECRETS versions");
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const createdAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + KEY_ROTATION_TTL_SECONDS * 1000).toISOString();
  const privateKeyJSON = JSON.stringify(await exportJWK(privateKey));
  return {
    id: randomString(16),
    publicKey: JSON.stringify(await exportJWK(publicKey)),
    privateKey: JSON.stringify(await symmetricEncrypt({ key: secretConfig(secrets), data: privateKeyJSON })),
    createdAt,
    expiresAt,
  };
}

export async function rotateSigningKey(
  database: D1Database,
  secrets: SecretVersion[],
  now = new Date(),
  batchExecutor: (statements: D1PreparedStatement[]) => Promise<D1Result<unknown>[]> = (statements) =>
    database.batch(statements),
): Promise<SigningKeyRecord> {
  const record = await createRotatedSigningKey(secrets, now);
  const statements = [
    database
      .prepare("INSERT INTO jwks (id, publicKey, privateKey, createdAt, expiresAt) VALUES (?, ?, ?, ?, ?)")
      .bind(record.id, record.publicKey, record.privateKey, record.createdAt, record.expiresAt),
  ];
  statements.push(
    database
      .prepare(
        `UPDATE jwks
         SET expiresAt = CASE
           WHEN expiresAt IS NULL OR expiresAt > ? THEN ?
           ELSE expiresAt
         END
         WHERE id != ? AND revokedAt IS NULL`,
      )
      .bind(now.toISOString(), now.toISOString(), record.id),
  );
  await batchExecutor(statements);
  return record;
}

export async function revokeSigningKey(database: D1Database, keyId: string, now = new Date()): Promise<boolean> {
  const result = await database
    .prepare(
      `UPDATE jwks SET revokedAt = ?
       WHERE id = ?
         AND createdAt < (SELECT MAX(createdAt) FROM jwks)
         AND revokedAt IS NULL`,
    )
    .bind(now.toISOString(), keyId)
    .run();
  return result.meta.changes === 1;
}
