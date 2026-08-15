import { readFile } from "node:fs/promises";
import { isValidD1Id, hasMatchingD1Binding } from "../src/preflight";
import { parseWranglerConfig } from "./preflight-config";

const CLOUDFLARE_ACCOUNT_ID_PATTERN = /^[0-9a-f]{32}$/u;

export type OperatorRemoteTarget = {
  accountId: string;
  d1DatabaseId: string;
};

export async function assertOperatorRemoteTarget(target: OperatorRemoteTarget): Promise<void> {
  if (!CLOUDFLARE_ACCOUNT_ID_PATTERN.test(target.accountId))
    throw new Error("remote actions require a 32-character hexadecimal Cloudflare account ID");
  if (!isValidD1Id(target.d1DatabaseId) || /^0+$/.test(target.d1DatabaseId.replaceAll("-", "")))
    throw new Error("remote actions require a non-placeholder D1 database ID");
  const main = parseWranglerConfig(await readFile("wrangler.jsonc", "utf8"));
  const operator = parseWranglerConfig(await readFile("wrangler.operator.jsonc", "utf8"));
  if (!hasMatchingD1Binding(main, operator)) throw new Error("main/operator D1 binding parity check failed");
  const configured = operator.d1_databases?.[0]?.database_id;
  if (configured !== target.d1DatabaseId) throw new Error("explicit D1 database ID does not match Wrangler config");
}

export function remoteTargetFromArgs(argv: string[]): OperatorRemoteTarget | null {
  const value = (name: string): string | undefined => {
    const index = argv.indexOf(name);
    if (index >= 0) return argv[index + 1];
    return argv.find((argument) => argument.startsWith(`${name}=`))?.slice(name.length + 1);
  };
  const accountId = value("--account-id");
  const d1DatabaseId = value("--d1-database-id");
  if (accountId === undefined && d1DatabaseId === undefined) return null;
  if (!accountId || !d1DatabaseId) throw new Error("remote actions require --account-id and --d1-database-id");
  return { accountId, d1DatabaseId };
}

export function remoteConfirmation(action: string, target: OperatorRemoteTarget): string {
  return `${action}:${target.accountId}:${target.d1DatabaseId}`;
}
