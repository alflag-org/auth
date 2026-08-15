import { spawnSync } from "node:child_process";
import { operatorChildEnvironment, registerOperatorLifecycle, withOperatorEnvFile } from "./operator-env";
import { findLoopbackPort, spawnOwnedWorker } from "./operator-process";
import {
  assertOperatorRemoteTarget,
  remoteConfirmation,
  remoteTargetFromArgs,
  type OperatorRemoteTarget,
} from "./operator-target";

const CONFIRMATION = "ROTATE-JWK";

type Arguments = {
  remote: boolean;
  remoteTarget: OperatorRemoteTarget | null;
};

function parseArguments(argv: string[]): Arguments {
  const remote = argv.includes("--remote");
  const remoteTarget = remoteTargetFromArgs(argv);
  const hasConfirmation = argv.includes(`--confirm=${CONFIRMATION}`);
  const confirmation = remoteTarget ? remoteConfirmation(CONFIRMATION, remoteTarget) : CONFIRMATION;
  const hasTargetedConfirmation = argv.includes(`--confirm=${confirmation}`);
  const hasSecondConfirmation = argv.includes(`--confirm-again=${confirmation}`);
  if ((!remote && !hasConfirmation) || (remote && !hasTargetedConfirmation))
    throw new Error(`JWK rotation requires --confirm=${CONFIRMATION}`);
  if (remote && (!remoteTarget || !hasTargetedConfirmation || !hasSecondConfirmation))
    throw new Error("Remote JWK rotation requires account, D1, and both explicit confirmation flags");
  if (!remote && remoteTarget) throw new Error("--account-id and --d1-database-id require --remote");
  return { remote, remoteTarget };
}

function createNonce(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

async function main(): Promise<void> {
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
  const nonce = createNonce();
  const port = await findLoopbackPort();
  const wranglerArguments = [
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
  ];
  await withOperatorEnvFile(nonce, "jwk-rotate", async (envFile, childEnvironment, signal) => {
    wranglerArguments.push("--env-file", envFile);
    const worker = await spawnOwnedWorker(
      wranglerArguments,
      { ...childEnvironment, ...(args.remoteTarget ? { CLOUDFLARE_ACCOUNT_ID: args.remoteTarget.accountId } : {}) },
      port,
    );
    const unregister = registerOperatorLifecycle(worker);
    try {
      await worker.waitForReady(signal);
      const response = await fetch(`http://127.0.0.1:${port}/__operator/jwk-rotate`, {
        method: "POST",
        headers: { "content-length": "0", "x-operator-nonce": nonce },
        signal,
      });
      if (!response.ok) throw new Error("JWK rotation failed");
      const result = (await response.json()) as { key_id: string };
      console.log(`key_id=${result.key_id}`);
    } finally {
      unregister();
      await worker.stop();
    }
  });
}

await main();
