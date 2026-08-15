import { readFile } from "node:fs/promises";
import { parseIssuer, parseVersionedSecrets } from "../src/config";
import {
  hasExactRateLimitBindings,
  hasMatchingD1Binding,
  isProductionGoogleDomain,
  isValidD1Id,
} from "../src/preflight";
import { parseWranglerConfig } from "./preflight-config";

function isPlaceholder(value: string | undefined): boolean {
  return (
    !value || value.includes("replace-with") || value.includes("00000000000000000000000000000000") || value === "unset"
  );
}

function hasValidSecrets(value: string | undefined): boolean {
  if (isPlaceholder(value)) return false;
  try {
    parseVersionedSecrets(value ?? "");
    return true;
  } catch {
    return false;
  }
}

const config = parseWranglerConfig(await readFile("wrangler.jsonc", "utf8"));
const operatorConfig = parseWranglerConfig(await readFile("wrangler.operator.jsonc", "utf8"));
const databaseId = config.d1_databases?.[0]?.database_id;
const issuer = config.vars?.AUTH_ISSUER;
let validIssuer = false;
try {
  parseIssuer(issuer ?? "");
  validIssuer = true;
} catch {
  validIssuer = false;
}
const missing = [
  config.observability?.enabled !== true || config.observability.logs?.invocation_logs !== false
    ? "observability invocation logs must be disabled"
    : null,
  !hasExactRateLimitBindings(config) ? "rate-limit bindings and exact limits" : null,
  !hasMatchingD1Binding(config, operatorConfig) ? "main/operator D1 binding parity" : null,
  !isValidD1Id(databaseId) || isPlaceholder(databaseId) ? "D1 database_id" : null,
  !validIssuer || issuer?.includes("example.invalid") ? "AUTH_ISSUER" : null,
  !hasValidSecrets(process.env.BETTER_AUTH_SECRETS) ? "BETTER_AUTH_SECRETS" : null,
  isPlaceholder(process.env.GOOGLE_CLIENT_ID) ? "GOOGLE_CLIENT_ID" : null,
  isPlaceholder(process.env.GOOGLE_CLIENT_SECRET) ? "GOOGLE_CLIENT_SECRET" : null,
  !isProductionGoogleDomain(process.env.ALLOWED_GOOGLE_DOMAIN) ? "ALLOWED_GOOGLE_DOMAIN" : null,
].filter((value): value is string => value !== null);

if (missing.length > 0) {
  console.error(`Deploy preflight failed: ${missing.join(", ")}`);
  process.exitCode = 1;
} else {
  console.log("Deploy preflight passed");
}
