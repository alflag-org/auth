import { parse, type ParseError } from "jsonc-parser";

export type WranglerConfig = {
  d1_databases?: Array<{ binding?: string; database_name?: string; database_id?: string }>;
  vars?: { AUTH_ISSUER?: string };
  observability?: { enabled?: boolean; logs?: { invocation_logs?: boolean } };
  ratelimits?: Array<{ name?: string; namespace_id?: string; simple?: { limit?: number; period?: number } }>;
};

export function parseWranglerConfig(source: string): WranglerConfig {
  const errors: ParseError[] = [];
  const value = parse(source, errors, { allowTrailingComma: true, disallowComments: false });
  if (errors.length > 0 || !value || typeof value !== "object" || Array.isArray(value))
    throw new Error("wrangler.jsonc is invalid JSONC");
  return value as WranglerConfig;
}
