import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const WORKER_SECRET_NAMES = [
  "BETTER_AUTH_SECRETS",
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "ALLOWED_GOOGLE_DOMAIN",
] as const;
const CHILD_ENV_NAMES = [
  "PATH",
  "HOME",
  "CLOUDFLARE_API_TOKEN",
  "CLOUDFLARE_ACCOUNT_ID",
  "TMPDIR",
  "TEMP",
  "TMP",
  "XDG_CACHE_HOME",
  "WRANGLER_LOG",
  "CI",
] as const;

export type OperatorLifecycle = { stop: () => Promise<void> };

let activeLifecycle: OperatorLifecycle | undefined;

export function registerOperatorLifecycle(lifecycle: OperatorLifecycle): () => void {
  if (activeLifecycle) throw new Error("an operator lifecycle is already registered");
  activeLifecycle = lifecycle;
  return () => {
    if (activeLifecycle === lifecycle) activeLifecycle = undefined;
  };
}

function envValue(name: string): string | undefined {
  const value = process.env[name];
  if (value === undefined || value.length === 0) return undefined;
  if (value.includes("\0") || value.includes("\r") || value.includes("\n"))
    throw new Error(`invalid operator environment value: ${name}`);
  return value;
}

export function operatorChildEnvironment(
  overrides: { cloudflareAccountId?: string | undefined } = {},
): NodeJS.ProcessEnv {
  const environment = Object.create(null) as NodeJS.ProcessEnv;
  for (const name of CHILD_ENV_NAMES) {
    const value = envValue(name);
    if (value !== undefined) environment[name] = value;
  }
  if (overrides.cloudflareAccountId !== undefined) environment.CLOUDFLARE_ACCOUNT_ID = overrides.cloudflareAccountId;
  return environment;
}

export async function withOperatorEnvFile<Result>(
  nonce: string,
  action: "client-create" | "jwk-rotate" | "jwk-revoke",
  callback: (envFile: string, childEnvironment: NodeJS.ProcessEnv, signal: AbortSignal) => Promise<Result>,
): Promise<Result> {
  if (!/^[A-Za-z0-9_-]{43}$/u.test(nonce)) throw new Error("invalid operator nonce");
  const directory = await mkdtemp(join(tmpdir(), "example-sso-operator-"));
  const envFile = join(directory, "worker.env");
  const controller = new AbortController();
  let interrupted: { signal: NodeJS.Signals; exitCode: number } | undefined;
  let signalStop: Promise<void> | undefined;
  let removed = false;
  const cleanup = async (): Promise<void> => {
    if (removed) return;
    await rm(directory, { recursive: true, force: true });
    removed = true;
  };
  const signalExitCodes: ReadonlyMap<NodeJS.Signals, number> = new Map([
    ["SIGINT", 130],
    ["SIGTERM", 143],
    ["SIGHUP", 129],
  ]);
  const onSignal = (signal: NodeJS.Signals): void => {
    if (interrupted) return;
    interrupted = { signal, exitCode: signalExitCodes.get(signal) ?? 1 };
    controller.abort(new Error(`operator interrupted by ${signal}`));
    signalStop = activeLifecycle?.stop() ?? Promise.resolve();
  };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);
  process.on("SIGHUP", onSignal);
  let result!: Result;
  let operationError: unknown;
  let operationFailed = false;
  let lifecycleError: unknown;
  let lifecycleFailed = false;
  let cleanupError: unknown;
  let cleanupFailed = false;
  try {
    await chmod(directory, 0o700);
    const entries = [
      ...WORKER_SECRET_NAMES.map((name) => {
        const value = envValue(name);
        if (value === undefined) throw new Error(`required operator Worker secret is missing: ${name}`);
        return [name, value] as const;
      }),
      ["AUTH_ISSUER", envValue("AUTH_ISSUER") ?? "https://auth.example.invalid"] as const,
      ["OPERATOR_NONCE", nonce] as const,
      ["OPERATOR_ACTION", action] as const,
    ];
    await writeFile(envFile, `${entries.map(([name, value]) => `${name}=${JSON.stringify(value)}`).join("\n")}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    await chmod(envFile, 0o600);
    result = await callback(envFile, operatorChildEnvironment(), controller.signal);
  } catch (error) {
    operationError = error;
    operationFailed = true;
  } finally {
    if (signalStop) {
      try {
        await signalStop;
      } catch (error) {
        lifecycleError = error;
        lifecycleFailed = true;
      }
    }
    process.removeListener("SIGINT", onSignal);
    process.removeListener("SIGTERM", onSignal);
    process.removeListener("SIGHUP", onSignal);
    try {
      await cleanup();
    } catch (error) {
      cleanupError = error;
      cleanupFailed = true;
    }
    if (interrupted) process.exitCode = interrupted.exitCode;
  }
  if (operationFailed && !interrupted) throw operationError;
  if (lifecycleFailed) throw lifecycleError;
  if (cleanupFailed) throw cleanupError;
  if (operationFailed) return undefined as Result;
  return result;
}
