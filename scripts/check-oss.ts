import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const { stdout } = await execFileAsync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"]);
const paths = stdout.split("\0").filter(Boolean);
const canonicalDocumentation = new Set([
  "README.md",
  "SECURITY.md",
  "CONTRIBUTING.md",
  ".github/pull_request_template.md",
]);
const remote = await execFileAsync("git", ["remote", "get-url", "origin"]).catch(() => ({ stdout: "" }));
const remoteOwner = /(?:github\.com[:/])([^/]+)\//iu.exec(remote.stdout)?.[1]?.toLowerCase();
const forbiddenNames = new Set(
  [remoteOwner, ...(remoteOwner?.split(/[^a-z0-9]+/giu) ?? [])].filter((value): value is string =>
    Boolean(value && value.length >= 4),
  ),
);
const leaked: string[] = [];
const unsafePaths: string[] = [];
const unsafeContent: string[] = [];
for (const path of paths) {
  if (
    (path.endsWith(".md") && !canonicalDocumentation.has(path)) ||
    /(?:^|\/)(?:\.wrangler|coverage|dist|output|tmp|temp)(?:\/|$)/iu.test(path) ||
    /(?:^|\/)(?:audit|report|plan|adr|temporary|temp|notes)[^/]*\.md$/iu.test(path) ||
    /(?:\.sqlite(?:-.+)?|\.sqlite3?|\.db|\.log|\.cpuprofile)$/iu.test(path)
  ) {
    unsafePaths.push(path);
  }
  const data = await readFile(path);
  const text = new TextDecoder().decode(data);
  if (path !== "scripts/check-oss.ts") {
    const lower = text.toLowerCase();
    if ([...forbiddenNames].some((name) => lower.includes(name))) leaked.push(path);
    if (
      /-----begin [a-z0-9 ]*private key-----/iu.test(text) ||
      /(?:ghp_|github_pat_|xox[baprs]-|akia[0-9a-z]{16})/iu.test(text)
    )
      unsafeContent.push(path);
  }
  if (/\.(?:env|dev\.vars)$/u.test(path) && !path.endsWith(".example")) unsafePaths.push(path);
}
if (leaked.length > 0) throw new Error(`organization-specific name found in candidate files: ${leaked.join(", ")}`);
if (unsafeContent.length > 0)
  throw new Error(`credential or private-key marker found in candidate files: ${unsafeContent.join(", ")}`);
if (unsafePaths.length > 0) throw new Error(`unsafe or non-canonical candidate files: ${unsafePaths.join(", ")}`);
console.log(`OSS-neutral scan passed for ${paths.length} candidate files`);
