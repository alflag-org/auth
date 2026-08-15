import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { hasExactRateLimitBindings, hasMatchingD1Binding } from "../src/preflight";
import { parseWranglerConfig } from "./preflight-config";

const child = spawn("pnpm", ["exec", "tsx", "scripts/deploy-preflight.ts"], {
  env: {
    ...process.env,
    AUTH_ISSUER: "https://auth.example.invalid",
    BETTER_AUTH_SECRETS: "replace-with-secret",
    GOOGLE_CLIENT_ID: "replace-with-client-id",
    GOOGLE_CLIENT_SECRET: "replace-with-client-secret",
    ALLOWED_GOOGLE_DOMAIN: "example.com",
  },
  stdio: ["ignore", "pipe", "pipe"],
});
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
if (exitCode === 0) throw new Error("deploy preflight unexpectedly accepted placeholders");
for (const required of [
  "rate-limit bindings and exact limits",
  "D1 database_id",
  "AUTH_ISSUER",
  "BETTER_AUTH_SECRETS",
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "ALLOWED_GOOGLE_DOMAIN",
]) {
  if (!output.includes(required)) throw new Error(`negative preflight did not report ${required}: ${output}`);
}
console.log("Deploy preflight rejects placeholders and missing production configuration");

const config = parseWranglerConfig(await readFile("wrangler.jsonc", "utf8"));
const operatorConfig = parseWranglerConfig(await readFile("wrangler.operator.jsonc", "utf8"));
if (
  hasMatchingD1Binding(config, {
    ...operatorConfig,
    d1_databases: operatorConfig.d1_databases?.map((entry) => ({ ...entry, database_name: "drifted" })),
  })
)
  throw new Error("negative preflight accepted main/operator D1 binding drift");
for (const [name, mutate] of [
  [
    "oversized limit",
    (entry: { simple?: { limit?: number; period?: number } }) => ({ ...entry, simple: { limit: 31, period: 60 } }),
  ],
  [
    "shortened period",
    (entry: { simple?: { limit?: number; period?: number } }) => ({ ...entry, simple: { limit: 30, period: 30 } }),
  ],
] as const) {
  const changed = {
    ...config,
    ratelimits: config.ratelimits?.map((entry, index) => (index === 0 ? mutate(entry) : entry)),
  };
  if (hasExactRateLimitBindings(changed)) throw new Error(`negative preflight accepted ${name}`);
}
console.log("Deploy preflight rejects oversized and shortened rate-limit policies");
