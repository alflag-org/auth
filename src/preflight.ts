const domainPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/u;

export const EXPECTED_RATE_LIMITS = {
  GOOGLE_LOGIN_RATE_LIMITER: { limit: 30, period: 60 },
  OAUTH_AUTHORIZE_RATE_LIMITER: { limit: 60, period: 60 },
  OAUTH_TOKEN_RATE_LIMITER: { limit: 30, period: 60 },
  OAUTH_USERINFO_RATE_LIMITER: { limit: 60, period: 60 },
  OAUTH_END_SESSION_RATE_LIMITER: { limit: 30, period: 60 },
} as const;

type WranglerD1 = {
  binding?: string;
  database_name?: string;
  database_id?: string;
};

type WranglerRateLimit = {
  name?: string;
  namespace_id?: string;
  simple?: { limit?: number; period?: number };
};

export type WranglerBindingConfig = {
  d1_databases?: WranglerD1[] | undefined;
  ratelimits?: WranglerRateLimit[] | undefined;
};

export function hasExactRateLimitBindings(config: WranglerBindingConfig): boolean {
  const bindings = config.ratelimits ?? [];
  const expectedNames = Object.keys(EXPECTED_RATE_LIMITS);
  return (
    bindings.length === expectedNames.length &&
    expectedNames.every((name) => {
      const expected = EXPECTED_RATE_LIMITS[name as keyof typeof EXPECTED_RATE_LIMITS];
      const matches = bindings.filter((binding) => binding.name === name);
      return (
        matches.length === 1 &&
        Boolean(matches[0]?.namespace_id) &&
        !/^0+$/u.test(matches[0]?.namespace_id ?? "") &&
        matches[0]?.simple?.limit === expected.limit &&
        matches[0]?.simple?.period === expected.period
      );
    })
  );
}

export function hasMatchingD1Binding(main: WranglerBindingConfig, operator: WranglerBindingConfig): boolean {
  const mainD1 = main.d1_databases ?? [];
  const operatorD1 = operator.d1_databases ?? [];
  if (mainD1.length !== 1 || operatorD1.length !== 1) return false;
  const left = mainD1[0];
  const right = operatorD1[0];
  return (
    left?.binding === right?.binding &&
    left?.database_name === right?.database_name &&
    left?.database_id === right?.database_id
  );
}

export function isValidD1Id(value: string | undefined): boolean {
  if (typeof value !== "string") return false;
  if (/^0+$/.test(value.replaceAll("-", ""))) return false;
  return /^[0-9a-f]{32}$/u.test(value) || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value);
}

export function isProductionGoogleDomain(value: string | undefined): boolean {
  if (typeof value !== "string" || !domainPattern.test(value)) return false;
  const lower = value.toLowerCase();
  return !(
    lower === "example.com" ||
    lower.endsWith(".example.com") ||
    lower === "example.net" ||
    lower.endsWith(".example.net") ||
    lower === "example.org" ||
    lower.endsWith(".example.org") ||
    lower.endsWith(".invalid")
  );
}
