import { spawnSync } from "node:child_process";
import { operatorChildEnvironment, registerOperatorLifecycle, withOperatorEnvFile } from "./operator-env";
import { findLoopbackPort, spawnOwnedWorker } from "./operator-process";
import {
  assertOperatorRemoteTarget,
  remoteConfirmation,
  remoteTargetFromArgs,
  type OperatorRemoteTarget,
} from "./operator-target";

type Args = {
  name: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  remote: boolean;
  confirmRemote: boolean;
  confirmRemoteAgain: boolean;
  remoteTarget: OperatorRemoteTarget | null;
};

type CreatedClient = {
  client_id: string;
  client_secret: string;
  client_secret_expires_at: number;
};

function parseArgs(argv: string[]): Args {
  const nameIndex = argv.indexOf("--name");
  const name = nameIndex >= 0 ? argv[nameIndex + 1] : undefined;
  const redirectUris = argv
    .flatMap((value, index) => (value === "--redirect-uri" ? [argv[index + 1]] : []))
    .filter((value): value is string => Boolean(value));
  const postLogoutRedirectUris = argv
    .flatMap((value, index) => (value === "--post-logout-redirect-uri" ? [argv[index + 1]] : []))
    .filter((value): value is string => Boolean(value));
  const remote = argv.includes("--remote");
  const remoteTarget = remoteTargetFromArgs(argv);
  const confirmation = remoteTarget ? remoteConfirmation("CREATE-OAUTH-CLIENT-REMOTE", remoteTarget) : null;
  const confirmRemote = confirmation !== null && argv.includes(`--confirm-remote=${confirmation}`);
  const confirmRemoteAgain = confirmation !== null && argv.includes(`--confirm-remote-again=${confirmation}`);
  if (!name || redirectUris.length === 0 || postLogoutRedirectUris.length === 0)
    throw new Error("Usage: pnpm client:create --name NAME --redirect-uri URL --post-logout-redirect-uri URL");
  if (remote && (!remoteTarget || !confirmRemote || !confirmRemoteAgain))
    throw new Error("Remote client creation requires account, D1, and both explicit confirmation flags");
  if (!remote && remoteTarget) throw new Error("--account-id and --d1-database-id require --remote");
  return { name, redirectUris, postLogoutRedirectUris, remote, confirmRemote, confirmRemoteAgain, remoteTarget };
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.remoteTarget) await assertOperatorRemoteTarget(args.remoteTarget);
  const migration = spawnSync(
    "pnpm",
    [
      "exec",
      "wrangler",
      "d1",
      "migrations",
      "apply",
      "DB",
      args.remote ? "--remote" : "--local",
      "--config",
      "wrangler.operator.jsonc",
    ],
    { stdio: "inherit", env: operatorChildEnvironment({ cloudflareAccountId: args.remoteTarget?.accountId }) },
  );
  if (migration.status !== 0) throw new Error("D1 migration failed");
  const nonceBytes = new Uint8Array(32);
  crypto.getRandomValues(nonceBytes);
  const nonce = btoa(String.fromCharCode(...nonceBytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
  const port = await findLoopbackPort();
  await withOperatorEnvFile(nonce, "client-create", async (envFile, childEnvironment, signal) => {
    const wranglerArgs = [
      "exec",
      "wrangler",
      "dev",
      "--config",
      "wrangler.operator.jsonc",
      "--local",
      "--ip",
      "127.0.0.1",
      "--port",
      String(port),
      "--env-file",
      envFile,
    ];
    if (args.remote) wranglerArgs.splice(wranglerArgs.indexOf("--local"), 1, "--remote");
    const worker = await spawnOwnedWorker(
      wranglerArgs,
      { ...childEnvironment, ...(args.remoteTarget ? { CLOUDFLARE_ACCOUNT_ID: args.remoteTarget.accountId } : {}) },
      port,
    );
    const unregister = registerOperatorLifecycle(worker);
    try {
      await worker.waitForReady(signal);
      const response = await fetch(`http://127.0.0.1:${port}/__operator/client-create`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-operator-nonce": nonce },
        body: JSON.stringify({
          client_name: args.name,
          redirect_uris: args.redirectUris,
          post_logout_redirect_uris: args.postLogoutRedirectUris,
        }),
        signal,
      });
      if (!response.ok) throw new Error("client creation failed");
      const result = (await response.json()) as CreatedClient;
      console.log(`client_id=${result.client_id}`);
      console.log(`client_secret=${result.client_secret}`);
      console.log(`client_secret_expires_at=${result.client_secret_expires_at}`);
    } finally {
      unregister();
      await worker.stop();
    }
  });
}

await main();
