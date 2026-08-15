import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";

const packageJSON = JSON.parse(await readFile("package.json", "utf8")) as {
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
};
const lockfile = await readFile("pnpm-lock.yaml", "utf8");
for (const [name, version] of Object.entries({ ...packageJSON.dependencies, ...packageJSON.devDependencies })) {
  if (!/^\d+\.\d+\.\d+$/u.test(version)) throw new Error(`dependency is not an exact pin: ${name}@${version}`);
  if (!lockfile.includes(`${name}@${version}`) && !lockfile.includes(`${name}:`))
    throw new Error(`dependency is missing from the lockfile: ${name}@${version}`);
}
const workspace = await readFile("pnpm-workspace.yaml", "utf8");
for (const setting of [
  "minimumReleaseAge: 1440",
  "minimumReleaseAgeIgnoreMissingTime: false",
  "trustPolicy: no-downgrade",
  "blockExoticSubdeps: true",
  "trustLockfile: false",
]) {
  const separator = setting.indexOf(": ");
  const key = setting.slice(0, separator);
  const value = setting.slice(separator + 2);
  if (!new RegExp(`^${key}\\s*:\\s*${value}\\s*$`, "mu").test(workspace))
    throw new Error(`supply-chain setting is missing: ${setting}`);
}
const auditConfig = workspace.match(/^auditConfig:\n((?:^[ \t].*\n?)*)/mu)?.[1] ?? "";
if (!/^\s+ignoreGhsas\s*:\s*$/mu.test(auditConfig)) throw new Error("auditConfig.ignoreGhsas is missing");
const ignoredGhsas = [...auditConfig.matchAll(/^\s*-\s*(GHSA-[A-Za-z0-9-]+)\s*$/gmu)].map((match) => match[1]);
if (JSON.stringify(ignoredGhsas) !== JSON.stringify(["GHSA-p2fr-6hmx-4528"]))
  throw new Error("auditConfig.ignoreGhsas must contain only the approved GHSA");
const patchPath = "patches/@better-auth__oauth-provider@1.6.28.patch";
const patchHash = createHash("sha256")
  .update(await readFile(patchPath))
  .digest("hex");
if (!workspace.includes(`'@better-auth/oauth-provider@1.6.28': ${patchPath}`))
  throw new Error("oauth-provider patch is not declared in pnpm-workspace.yaml");
if (!lockfile.includes(`'@better-auth/oauth-provider@1.6.28': ${patchHash}`))
  throw new Error("oauth-provider patch hash is not pinned in pnpm-lock.yaml");
const patchFiles = (await readdir("patches")).filter((file) => file.endsWith(".patch"));
if (patchFiles.length !== 1 || patchFiles[0] !== "@better-auth__oauth-provider@1.6.28.patch")
  throw new Error("unexpected dependency patch files are present");
const packageJSONText = await readFile("package.json", "utf8");
for (const script of [
  '"audit:prod": "pnpm audit --prod --audit-level moderate"',
  '"audit:signatures": "pnpm audit signatures"',
]) {
  if (!packageJSONText.includes(script)) throw new Error(`audit script is missing: ${script}`);
}
console.log("Supply-chain pins, fail-closed audit policy, and minimum release age are configured");
