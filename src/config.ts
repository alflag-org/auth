import { z } from "zod";

export const GOOGLE_ISSUER = "https://accounts.google.com" as const;
export const GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"] as const;
export const GOOGLE_CERTS_URL = "https://www.googleapis.com/oauth2/v3/certs" as const;
export const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token" as const;
export const GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth" as const;
export const GOOGLE_CALLBACK_PATH = "/callback/google" as const;
export const SCOPES = ["openid", "profile", "email"] as const;
export const AUTHORIZATION_CODE_TTL_SECONDS = 60 as const;
export const GOOGLE_LOGIN_TRANSACTION_TTL_SECONDS = 5 * 60;
export const MAX_PENDING_STANDALONE_GOOGLE_STATES = 100 as const;
export const MAX_PENDING_RELYING_PARTY_GOOGLE_STATES = 400 as const;
export const MAX_PENDING_GOOGLE_STATES = MAX_PENDING_STANDALONE_GOOGLE_STATES + MAX_PENDING_RELYING_PARTY_GOOGLE_STATES;
export const ID_TOKEN_TTL_SECONDS = 300 as const;
export const ACCESS_TOKEN_TTL_SECONDS = 600 as const;
export const SESSION_TTL_SECONDS = 8 * 60 * 60;
export const KEY_ROTATION_TTL_SECONDS = 90 * 24 * 60 * 60;
export const KEY_GRACE_TTL_SECONDS = 30 * 24 * 60 * 60;
export const MAX_AUTHORIZATION_PARAMETER_LENGTH = 2048 as const;
export const MAX_AUTHORIZATION_STATE_LENGTH = 256 as const;
export const MAX_AUTHORIZATION_NONCE_LENGTH = 256 as const;
export const MAX_CODE_VERIFIER_LENGTH = 128 as const;
export const CODE_VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/u;

export type ProductBrand = {
  name: string;
  workspaceLabel: string;
};

const configSchema = z.object({
  AUTH_ISSUER: z.string().min(1),
  BETTER_AUTH_SECRETS: z.string().min(1),
  GOOGLE_CLIENT_ID: z.string().min(1),
  GOOGLE_CLIENT_SECRET: z.string().min(1),
  ALLOWED_GOOGLE_DOMAIN: z
    .string()
    .regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/),
});

export type SecretVersion = {
  version: number;
  value: string;
};

export type RuntimeConfig = {
  issuer: string;
  secrets: [SecretVersion, ...SecretVersion[]];
  googleClientId: string;
  googleClientSecret: string;
  allowedGoogleDomain: string;
  brand: ProductBrand;
};

export function brandForIssuer(issuer: string): ProductBrand {
  const hostname = new URL(issuer).hostname;
  const labels = hostname.split(".");
  const organization = labels[0] === "auth" && labels.length >= 3 ? labels.at(-2) : undefined;
  if (!organization || organization === "example" || organization === "invalid") {
    return { name: "Auth", workspaceLabel: "Workspace only" };
  }
  const displayOrganization = organization.toUpperCase();
  return {
    name: `${displayOrganization} Auth`,
    workspaceLabel: `${displayOrganization} Workspace only`,
  };
}

export function parseIssuer(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("AUTH_ISSUER must be an HTTPS origin");
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    (url.pathname !== "" && url.pathname !== "/")
  ) {
    throw new Error("AUTH_ISSUER must be an HTTPS origin");
  }
  return url.origin;
}

export function parseVersionedSecrets(raw: string): [SecretVersion, ...SecretVersion[]] {
  const entries = raw
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
  const secrets: SecretVersion[] = [];
  const versions = new Set<number>();
  for (const entry of entries) {
    const separator = entry.indexOf(":");
    if (separator <= 0) throw new Error("BETTER_AUTH_SECRETS must use version:value entries");
    const version = Number(entry.slice(0, separator));
    const value = entry.slice(separator + 1);
    if (!Number.isSafeInteger(version) || version <= 0 || value.length < 32 || versions.has(version)) {
      throw new Error("BETTER_AUTH_SECRETS contains an invalid versioned secret");
    }
    versions.add(version);
    const previous = secrets.at(-1);
    if (previous && version >= previous.version)
      throw new Error("BETTER_AUTH_SECRETS versions must be strictly descending");
    secrets.push({ version, value });
  }
  if (secrets.length === 0) throw new Error("BETTER_AUTH_SECRETS is required");
  return secrets as [SecretVersion, ...SecretVersion[]];
}

export function getRuntimeConfig(env: {
  AUTH_ISSUER: string;
  BETTER_AUTH_SECRETS: string;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  ALLOWED_GOOGLE_DOMAIN: string;
}): RuntimeConfig {
  const parsed = configSchema.safeParse(env);
  if (!parsed.success) throw new Error("Required auth configuration is missing or invalid");
  const issuer = parseIssuer(parsed.data.AUTH_ISSUER);
  return {
    issuer,
    secrets: parseVersionedSecrets(parsed.data.BETTER_AUTH_SECRETS),
    googleClientId: parsed.data.GOOGLE_CLIENT_ID,
    googleClientSecret: parsed.data.GOOGLE_CLIENT_SECRET,
    allowedGoogleDomain: parsed.data.ALLOWED_GOOGLE_DOMAIN,
    brand: brandForIssuer(issuer),
  };
}
