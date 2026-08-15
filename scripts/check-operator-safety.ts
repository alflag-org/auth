import { spawn } from "node:child_process";
import { access, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { operatorChildEnvironment, withOperatorEnvFile } from "./operator-env";
import { findLoopbackPort, spawnOwnedWorker } from "./operator-process";

async function run(arguments_: string[]): Promise<{ code: number; output: string }> {
  const child = spawn(process.execPath, ["node_modules/tsx/dist/cli.mjs", "scripts/client-create.ts", ...arguments_], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (chunk: Buffer) => {
    output += chunk.toString();
  });
  child.stderr.on("data", (chunk: Buffer) => {
    output += chunk.toString();
  });
  const code = await new Promise<number>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (exitCode) => resolve(exitCode ?? 1));
  });
  return { code, output };
}

const common = [
  "--name",
  "Example App",
  "--redirect-uri",
  "https://app.example/callback",
  "--post-logout-redirect-uri",
  "https://app.example/signed-out",
];
const remoteTarget = {
  accountId: "0123456789abcdef0123456789abcdef",
  d1DatabaseId: "01234567-89ab-cdef-0123-456789abcdef",
};
const confirmation = `${remoteTarget.accountId}:${remoteTarget.d1DatabaseId}`;
const oneConfirmation = await run([
  ...common,
  "--remote",
  `--account-id=${remoteTarget.accountId}`,
  `--d1-database-id=${remoteTarget.d1DatabaseId}`,
  `--confirm-remote=CREATE-OAUTH-CLIENT-REMOTE:${confirmation}`,
]);
if (oneConfirmation.code === 0 || !oneConfirmation.output.includes("both explicit confirmation flags"))
  throw new Error(`single remote confirmation was accepted: ${oneConfirmation.output}`);

const missingName = await run([
  "--redirect-uri",
  "https://app.example/callback",
  "--post-logout-redirect-uri",
  "https://app.example/signed-out",
]);
if (missingName.code === 0 || !missingName.output.includes("Usage: pnpm client:create"))
  throw new Error(`invalid arguments were accepted: ${missingName.output}`);

const source = await readFile(new URL("./client-create.ts", import.meta.url), "utf8");
const secretPrints = source.match(/console\.log\(`client_secret=/gu) ?? [];
if (secretPrints.length !== 1)
  throw new Error(`expected one client secret delivery print, found ${secretPrints.length}`);
if (!source.includes("--env-file") || source.includes("--var") || source.includes("OPERATOR_NONCE:" + "$" + "{nonce}"))
  throw new Error("client creation must transport its nonce through the temporary env file");
const operatorSource = await readFile(new URL("../src/operator.ts", import.meta.url), "utf8");
for (const required of [
  'token_endpoint_auth_method: "client_secret_basic"',
  'grant_types: ["authorization_code"]',
  'response_types: ["code"]',
  'type: "web"',
  "require_pkce: true",
]) {
  if (!operatorSource.includes(required)) throw new Error(`operator restriction missing: ${required}`);
}
const rotationSource = await readFile(new URL("./rotate-jwk.ts", import.meta.url), "utf8");
for (const required of [
  "--local",
  "--remote",
  "--confirm-again=" + "$" + "{confirmation}",
  "--env-file",
  "x-operator-nonce",
]) {
  if (!rotationSource.includes(required)) throw new Error(`operator JWK rotation safety missing: ${required}`);
}
if (rotationSource.includes("--var") || rotationSource.includes("console.log(nonce)"))
  throw new Error("operator JWK rotation must not expose its nonce through argv or logs");
const envSource = await readFile(new URL("./operator-env.ts", import.meta.url), "utf8");
for (const required of [
  "0o600",
  "finally",
  "SIGINT",
  "SIGTERM",
  "SIGHUP",
  "BETTER_AUTH_SECRETS",
  "CI",
  "CLOUDFLARE_API_TOKEN",
  "mkdtemp",
]) {
  if (!envSource.includes(required)) throw new Error(`operator environment safety missing: ${required}`);
}
if (
  envSource.includes("...process.env") ||
  rotationSource.includes("...process.env") ||
  source.includes("...process.env")
)
  throw new Error("operator Worker startup must not inherit the full process environment");
if (envSource.includes("process.exit("))
  throw new Error("operator cleanup must not call process.exit before owned resources stop");
if (rotationSource.includes("CLOUDFLARE_INCLUDE_PROCESS_ENV") || source.includes("CLOUDFLARE_INCLUDE_PROCESS_ENV"))
  throw new Error("operator Worker startup must not include the full process environment");

async function assertMissing(path: string): Promise<void> {
  try {
    await access(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  throw new Error("operator temporary material was not removed");
}

const operatorValues = {
  BETTER_AUTH_SECRETS: "1:operator-runtime-secret-1234567890abcdef1234567890abcdef",
  GOOGLE_CLIENT_ID: "operator-runtime-client",
  GOOGLE_CLIENT_SECRET: "operator-runtime-google-secret",
  ALLOWED_GOOGLE_DOMAIN: "example.com",
  AUTH_ISSUER: "https://auth.example.invalid",
  OPERATOR_CHECK_UNRELATED: "must-not-cross-boundary",
  CI: "true",
} as const;
const previousValues = new Map<string, string | undefined>();
const runtimeNonce = "n".repeat(43);
try {
  for (const [name, value] of Object.entries(operatorValues)) {
    previousValues.set(name, process.env[name]);
    process.env[name] = value;
  }
  let normalFile = "";
  await withOperatorEnvFile(runtimeNonce, "client-create", async (envFile, childEnvironment) => {
    normalFile = envFile;
    const directoryMode = (await stat(dirname(envFile))).mode & 0o777;
    const fileMode = (await stat(envFile)).mode & 0o777;
    if (directoryMode !== 0o700 || fileMode !== 0o600) throw new Error("operator temporary permissions are unsafe");
    const lines = (await readFile(envFile, "utf8"))
      .split("\n")
      .filter((line) => line.length > 0)
      .map((line) => line.slice(0, line.indexOf("=")));
    const expectedNames = [
      "BETTER_AUTH_SECRETS",
      "GOOGLE_CLIENT_ID",
      "GOOGLE_CLIENT_SECRET",
      "ALLOWED_GOOGLE_DOMAIN",
      "AUTH_ISSUER",
      "OPERATOR_NONCE",
      "OPERATOR_ACTION",
    ];
    if (JSON.stringify(lines) !== JSON.stringify(expectedNames)) throw new Error("operator env allowlist changed");
    const contents = await readFile(envFile, "utf8");
    if (contents.includes(operatorValues.OPERATOR_CHECK_UNRELATED))
      throw new Error("unrelated operator environment crossed the file boundary");
    for (const name of [
      "BETTER_AUTH_SECRETS",
      "GOOGLE_CLIENT_ID",
      "GOOGLE_CLIENT_SECRET",
      "ALLOWED_GOOGLE_DOMAIN",
      "AUTH_ISSUER",
      "OPERATOR_NONCE",
      "OPERATOR_ACTION",
      "OPERATOR_CHECK_UNRELATED",
    ]) {
      if (childEnvironment[name] !== undefined) throw new Error("operator values crossed the child boundary");
    }
    if (childEnvironment.CI !== "true") throw new Error("CI package-manager mode was not preserved for the child");
  });
  await assertMissing(normalFile);
  await assertMissing(dirname(normalFile));

  let throwingFile = "";
  let callbackFailed = false;
  try {
    await withOperatorEnvFile(runtimeNonce, "jwk-rotate", async (envFile) => {
      throwingFile = envFile;
      throw new Error("operator callback failure");
    });
  } catch (error) {
    callbackFailed = error instanceof Error && error.message === "operator callback failure";
  }
  if (!callbackFailed) throw new Error("operator callback failure was not propagated");
  await assertMissing(throwingFile);
  await assertMissing(dirname(throwingFile));
} finally {
  for (const [name, value] of previousValues) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
}
const processSource = await readFile(new URL("./operator-process.ts", import.meta.url), "utf8");
if (processSource.includes("/__operator/health") || !processSource.includes("detached: true"))
  throw new Error("operator readiness must be owned by the spawned process, not a fixed health listener");
const processPort = await findLoopbackPort();
const worker = await spawnOwnedWorker(
  [
    "exec",
    "node",
    "-e",
    `console.log("Ready on http://127.0.0.1:${processPort + 1}"); setTimeout(() => console.log("Ready on http://127.0.0.1:${processPort}"), 25); setTimeout(() => {}, 5000)`,
  ],
  operatorChildEnvironment(),
  processPort,
);
await worker.waitForReady();
await worker.stop();
if (worker.child.exitCode === null && worker.child.signalCode === null) throw new Error("owned worker did not stop");
const failedPort = await findLoopbackPort();
const failedWorker = await spawnOwnedWorker(
  ["exec", "node", "-e", "process.exit(2)"],
  operatorChildEnvironment(),
  failedPort,
);
let failedBeforeReady = false;
try {
  await failedWorker.waitForReady();
} catch (error) {
  failedBeforeReady = error instanceof Error && error.message.includes("exited before ready");
}
if (!failedBeforeReady) throw new Error("operator spawn failure was not detected before readiness");
await failedWorker.stop();
const waitForPath = async (path: string): Promise<void> => {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    try {
      await access(path);
      return;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    await new Promise<void>((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`operator signal fixture did not create ${path}`);
};
const waitForGone = async (pid: number): Promise<void> => {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    try {
      process.kill(pid, 0);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ESRCH") return;
      throw error;
    }
    await new Promise<void>((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`operator signal fixture descendant ${pid} survived cleanup`);
};
const orphanDirectory = await mkdtemp(join(tmpdir(), "operator-group-check-"));
const orphanPidPath = join(orphanDirectory, "descendant-pid");
const orphanPort = await findLoopbackPort();
const orphanWorker = await spawnOwnedWorker(
  [
    "exec",
    "node",
    "-e",
    [
      'const { spawn } = require("node:child_process");',
      'const descendant = spawn(process.execPath, ["-e", "process.on(\\"SIGTERM\\", () => {}); setInterval(() => {}, 1000)"], { stdio: "ignore" });',
      `require("node:fs").writeFileSync(${JSON.stringify(orphanPidPath)}, String(descendant.pid));`,
      `console.log(${JSON.stringify(`Ready on http://127.0.0.1:${orphanPort}`)});`,
      'process.on("SIGTERM", () => process.exit(0));',
      "setInterval(() => {}, 1000);",
    ].join("\n"),
  ],
  operatorChildEnvironment(),
  orphanPort,
);
try {
  await orphanWorker.waitForReady();
  await orphanWorker.stop();
  const orphanPid = Number.parseInt((await readFile(orphanPidPath, "utf8")).trim(), 10);
  if (!Number.isSafeInteger(orphanPid) || orphanPid <= 0)
    throw new Error("group cleanup wrote an invalid descendant pid");
  await waitForGone(orphanPid);
} finally {
  await orphanWorker.stop();
  await rm(orphanDirectory, { recursive: true, force: true });
}
for (const [signal, expectedCode] of [
  ["SIGINT", 130],
  ["SIGTERM", 143],
  ["SIGHUP", 129],
] as const) {
  const signalFixtureDirectory = await mkdtemp(join(tmpdir(), "operator-signal-check-"));
  const signalFixtureResult = join(signalFixtureDirectory, "env-path");
  const signalFixtureDescendant = join(signalFixtureDirectory, "descendant-pid");
  const signalFixtureReady = join(signalFixtureDirectory, "ready");
  const signalFixtureEnvironment = {
    ...process.env,
    ...operatorValues,
    SIGNAL_FIXTURE_RESULT_PATH: signalFixtureResult,
    SIGNAL_FIXTURE_DESCENDANT_PATH: signalFixtureDescendant,
    SIGNAL_FIXTURE_READY_PATH: signalFixtureReady,
  };
  const signalFixture = spawn(process.execPath, ["--import", "tsx", "scripts/operator-signal-fixture.ts"], {
    env: signalFixtureEnvironment,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let signalFixtureOutput = "";
  signalFixture.stdout.on("data", (chunk: Buffer) => {
    signalFixtureOutput += chunk.toString();
  });
  signalFixture.stderr.on("data", (chunk: Buffer) => {
    signalFixtureOutput += chunk.toString();
  });
  try {
    await waitForPath(signalFixtureReady);
    signalFixture.kill(signal);
    signalFixture.kill(signal);
    const signalExit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
      signalFixture.once("error", reject);
      signalFixture.once("exit", (code, receivedSignal) => resolve({ code, signal: receivedSignal }));
    });
    if (signalExit.code !== expectedCode || signalExit.signal !== null)
      throw new Error(`${signal} fixture exited unexpectedly: ${JSON.stringify(signalExit)}`);
    if (signalFixtureOutput.includes(operatorValues.BETTER_AUTH_SECRETS))
      throw new Error(`${signal} fixture exposed a Worker secret`);
    const signalEnvFile = (await readFile(signalFixtureResult, "utf8")).trim();
    await assertMissing(signalEnvFile);
    await assertMissing(dirname(signalEnvFile));
    const descendantPid = Number.parseInt((await readFile(signalFixtureDescendant, "utf8")).trim(), 10);
    if (!Number.isSafeInteger(descendantPid) || descendantPid <= 0)
      throw new Error(`${signal} fixture wrote an invalid descendant pid`);
    await waitForGone(descendantPid);
  } finally {
    await rm(signalFixtureDirectory, { recursive: true, force: true });
  }
}
console.log("Operator local-default, argument, fixed-client, and remote-confirmation checks passed");
