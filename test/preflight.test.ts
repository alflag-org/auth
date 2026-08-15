import { describe, expect, it } from "vitest";
import {
  hasExactRateLimitBindings,
  hasMatchingD1Binding,
  isProductionGoogleDomain,
  isValidD1Id,
} from "../src/preflight";
import { parseWranglerConfig } from "../scripts/preflight-config";

describe("production preflight validation", () => {
  it("accepts canonical D1 UUID forms and rejects zero placeholders", () => {
    expect(isValidD1Id("0123456789abcdef0123456789abcdef")).toBe(true);
    expect(isValidD1Id("01234567-89ab-cdef-0123-456789abcdef")).toBe(true);
    expect(isValidD1Id("00000000000000000000000000000000")).toBe(false);
    expect(isValidD1Id("00000000-0000-0000-0000-000000000000")).toBe(false);
  });

  it("rejects reserved example and invalid Google domains", () => {
    for (const domain of ["example.com", "tenant.example.net", "example.org", "tenant.invalid"]) {
      expect(isProductionGoogleDomain(domain), domain).toBe(false);
    }
    expect(isProductionGoogleDomain("workspace.example.co.uk")).toBe(true);
  });

  it("parses Wrangler JSONC comments and trailing commas", () => {
    const config = parseWranglerConfig(`{
      // local fixture
      "vars": { "AUTH_ISSUER": "https://auth.example.invalid", },
      "d1_databases": [{ "database_id": "01234567-89ab-cdef-0123-456789abcdef", }],
    }`);
    expect(config.vars?.AUTH_ISSUER).toBe("https://auth.example.invalid");
    expect(config.d1_databases?.[0]?.database_id).toBe("01234567-89ab-cdef-0123-456789abcdef");
  });

  it("requires the exact limiter policy and main/operator D1 parity", () => {
    const config = parseWranglerConfig(`{
      "ratelimits": [
        { "name": "GOOGLE_LOGIN_RATE_LIMITER", "namespace_id": "1", "simple": { "limit": 30, "period": 60 } },
        { "name": "OAUTH_AUTHORIZE_RATE_LIMITER", "namespace_id": "2", "simple": { "limit": 60, "period": 60 } },
        { "name": "OAUTH_TOKEN_RATE_LIMITER", "namespace_id": "3", "simple": { "limit": 30, "period": 60 } },
        { "name": "OAUTH_USERINFO_RATE_LIMITER", "namespace_id": "4", "simple": { "limit": 60, "period": 60 } },
        { "name": "OAUTH_END_SESSION_RATE_LIMITER", "namespace_id": "5", "simple": { "limit": 30, "period": 60 } }
      ],
      "d1_databases": [{ "binding": "DB", "database_name": "example-sso", "database_id": "db-id" }]
    }`);
    expect(hasExactRateLimitBindings(config)).toBe(true);
    expect(
      hasExactRateLimitBindings({
        ...config,
        ratelimits: config.ratelimits?.map((entry) =>
          entry.name === "GOOGLE_LOGIN_RATE_LIMITER" ? { ...entry, simple: { limit: 31, period: 60 } } : entry,
        ),
      }),
    ).toBe(false);
    expect(
      hasExactRateLimitBindings({
        ...config,
        ratelimits: config.ratelimits?.map((entry) =>
          entry.name === "OAUTH_END_SESSION_RATE_LIMITER" ? { ...entry, simple: { limit: 30, period: 30 } } : entry,
        ),
      }),
    ).toBe(false);
    expect(hasMatchingD1Binding(config, config)).toBe(true);
    expect(
      hasMatchingD1Binding(config, {
        ...config,
        d1_databases: [{ binding: "DB", database_name: "other", database_id: "db-id" }],
      }),
    ).toBe(false);
  });
});
