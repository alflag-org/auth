import { spawn } from "node:child_process";
import { readdir } from "node:fs/promises";
import { join } from "node:path";

const command = [
  "SELECT name FROM sqlite_master WHERE type = 'index' AND name IN ('verification_expiresAt_idx', 'verification_identifier_expiresAt_idx', 'verification_google_state_source_idx', 'verification_google_state_client_idx', 'oauthAuthorizationAdmission_expiresAt_idx', 'oauthAuthorizationAdmission_sourceKey_expiresAt_idx', 'oauthAuthorizationAdmission_clientId_expiresAt_idx', 'oauthAuthorizationAdmission_continuation_idx', 'oauthAccessToken_expiresAt_idx', 'session_expiresAt_idx', 'jwks_expiresAt_idx', 'adminAudit_createdAt_idx') ORDER BY name;",
].join(" ");
const persistTo = process.env.D1_PERSIST_TO;
const child = spawn(
  "pnpm",
  [
    "exec",
    "wrangler",
    ...(persistTo ? ["--persist-to", persistTo] : []),
    "d1",
    "execute",
    "DB",
    "--local",
    "--command",
    command,
    "--config",
    "wrangler.jsonc",
  ],
  { stdio: ["ignore", "pipe", "pipe"] },
);
let output = "";
child.stdout.on("data", (chunk: Buffer) => {
  output += chunk.toString();
});
child.stderr.on("data", (chunk: Buffer) => {
  output += chunk.toString();
});
const exitCode = await new Promise<number>((resolve, reject) => {
  child.once("error", reject);
  child.once("exit", (code) => resolve(code ?? 1));
});
if (exitCode !== 0) throw new Error(`local D1 schema check failed: ${output}`);
for (const index of [
  "verification_expiresAt_idx",
  "verification_identifier_expiresAt_idx",
  "verification_google_state_source_idx",
  "verification_google_state_client_idx",
  "oauthAuthorizationAdmission_expiresAt_idx",
  "oauthAuthorizationAdmission_sourceKey_expiresAt_idx",
  "oauthAuthorizationAdmission_clientId_expiresAt_idx",
  "oauthAuthorizationAdmission_continuation_idx",
  "oauthAccessToken_expiresAt_idx",
  "session_expiresAt_idx",
  "jwks_expiresAt_idx",
  "adminAudit_createdAt_idx",
]) {
  if (!output.includes(index)) throw new Error(`local D1 index is missing: ${index}`);
}
if (persistTo) {
  async function findDatabase(directory: string): Promise<string | null> {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        const nested = await findDatabase(path);
        if (nested) return nested;
      } else if (
        entry.name.endsWith(".sqlite") &&
        entry.name !== "metadata.sqlite" &&
        path.includes("miniflare-D1DatabaseObject")
      ) {
        return path;
      }
    }
    return null;
  }
  const databasePath = await findDatabase(persistTo);
  if (!databasePath) throw new Error("local D1 sqlite file was not created");
  const integrity = spawn("sqlite3", [databasePath, "PRAGMA integrity_check;"], { stdio: ["ignore", "pipe", "pipe"] });
  let integrityOutput = "";
  integrity.stdout.on("data", (chunk: Buffer) => {
    integrityOutput += chunk.toString();
  });
  integrity.stderr.on("data", (chunk: Buffer) => {
    integrityOutput += chunk.toString();
  });
  const integrityExit = await new Promise<number>((resolve, reject) => {
    integrity.once("error", reject);
    integrity.once("exit", (code) => resolve(code ?? 1));
  });
  if (integrityExit !== 0 || !integrityOutput.includes("ok"))
    throw new Error(`local D1 integrity check failed: ${integrityOutput}`);
}
console.log("Fresh local D1 integrity and security indexes are present");
