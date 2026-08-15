import { spawnSync } from "node:child_process";
import { operatorChildEnvironment, registerOperatorLifecycle, withOperatorEnvFile } from "./operator-env";
import { findLoopbackPort, spawnOwnedWorker } from "./operator-process";
import {
  assertOperatorRemoteTarget,
  remoteConfirmation,
  remoteTargetFromArgs,
  type OperatorRemoteTarget,
} from "./operator-target";

const CONFIRMATION = "REVOKE-JWK";

function parseArguments(argv: string[]): { keyId: string; remote: boolean; remoteTarget: OperatorRemoteTarget | null } {
  const keyIndex = argv.indexOf("--key-id");
  const keyId = keyIndex >= 0 ? argv[keyIndex + 1] : undefined;
  const remote = argv.includes("--remote");
  const remoteTarget = remoteTargetFromArgs(argv);
  if (!keyId || !/^[A-Za-z0-9_-]{1,128}$/u.test(keyId)) throw new Error("JWK revoke requires --key-id KEY_ID");
  const action = remoteTarget
    ? remoteConfirmation(`${CONFIRMATION}:${keyId}`, remoteTarget)
    : `${CONFIRMATION}:${keyId}`;
  const confirmation = `--confirm=${action}`;
  const second = `--confirm-again=${action}`;
  if (!argv.includes(confirmation) || (remote && (!remoteTarget || !argv.includes(second))))
    throw new Error("JWK revoke requires explicit confirmation including the key id, account, and D1");
  if (!remote && remoteTarget) throw new Error("--account-id and --d1-database-id require --remote");
  return { keyId, remote, remoteTarget };
}

function nonce(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

const args = parseArguments(process.argv.slice(2));
if (args.remoteTarget) await assertOperatorRemoteTarget(args.remoteTarget);
if (!args.remote) {
  const migration = spawnSync(
    "pnpm",
    ["exec", "wrangler", "d1", "migrations", "apply", "DB", "--local", "--config", "wrangler.operator.jsonc"],
    { stdio: "inherit", env: operatorChildEnvironment({ cloudflareAccountId: args.remoteTarget?.accountId }) },
  );
  if (migration.status !== 0) throw new Error("local D1 migration failed");
}
const operatorNonce = nonce();
const port = await findLoopbackPort();
await withOperatorEnvFile(operatorNonce, "jwk-revoke", async (envFile, childEnvironment, signal) => {
  const wranglerArgs = [
    "exec",
    "wrangler",
    "dev",
    "--config",
    "wrangler.operator.jsonc",
    args.remote ? "--remote" : "--local",
    "--ip",
    "127.0.0.1",
    "--port",
    String(port),
    "--env-file",
    envFile,
  ];
  const worker = await spawnOwnedWorker(
    wranglerArgs,
    { ...childEnvironment, ...(args.remoteTarget ? { CLOUDFLARE_ACCOUNT_ID: args.remoteTarget.accountId } : {}) },
    port,
  );
  const unregister = registerOperatorLifecycle(worker);
  try {
    await worker.waitForReady(signal);
    const response = await fetch(`http://127.0.0.1:${port}/__operator/jwk-revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-operator-nonce": operatorNonce },
      body: JSON.stringify({ key_id: args.keyId }),
      signal,
    });
    if (!response.ok) throw new Error("JWK revoke failed");
    const result: unknown = await response.json();
    if (!result || typeof result !== "object" || (result as { revoked?: unknown }).revoked !== true)
      throw new Error("JWK revoke returned an invalid response");
  } finally {
    unregister();
    await worker.stop();
  }
});
