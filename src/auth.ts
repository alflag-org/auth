import { oauthProvider } from "@better-auth/oauth-provider";
import { betterAuth, type User } from "better-auth";
import { jwt } from "better-auth/plugins";
import type { JWTVerifyGetKey } from "jose";
import {
  ACCESS_TOKEN_TTL_SECONDS,
  AUTHORIZATION_CODE_TTL_SECONDS,
  GOOGLE_LOGIN_TRANSACTION_TTL_SECONDS,
  ID_TOKEN_TTL_SECONDS,
  KEY_GRACE_TTL_SECONDS,
  KEY_ROTATION_TTL_SECONDS,
  SCOPES,
  SESSION_TTL_SECONDS,
  getRuntimeConfig,
} from "./config";
import { verifyGoogleIdentityToken } from "./google";

export type AuthOptions = {
  allowOperatorPrivileges?: boolean;
};

export type AuthEnvironment = {
  DB: D1Database;
  AUTH_ISSUER: string;
  BETTER_AUTH_SECRETS: string;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  ALLOWED_GOOGLE_DOMAIN: string;
};

export function createAuth(env: AuthEnvironment, googleKeySet?: JWTVerifyGetKey, options: AuthOptions = {}) {
  const config = getRuntimeConfig(env);
  return betterAuth({
    appName: "Example SSO",
    baseURL: config.issuer,
    basePath: "/",
    database: env.DB,
    secrets: config.secrets,
    trustedOrigins: [config.issuer],
    advanced: {
      useSecureCookies: false,
      cookies: {
        session_token: {
          name: "__Host-better-auth.session_token",
        },
      },
      defaultCookieAttributes: {
        secure: true,
        httpOnly: true,
        sameSite: "lax",
        path: "/",
      },
      crossSubDomainCookies: {
        enabled: false,
      },
    },
    session: {
      expiresIn: SESSION_TTL_SECONDS,
      updateAge: 0,
      disableSessionRefresh: true,
      storeSessionInDatabase: true,
    },
    account: {
      accountLinking: {
        disableImplicitLinking: true,
      },
    },
    socialProviders: {
      google: {
        clientId: config.googleClientId,
        clientSecret: config.googleClientSecret,
        hd: config.allowedGoogleDomain,
        accessType: "online",
        verifyIdToken: async (token: string, nonce?: string) => {
          await verifyGoogleIdentityToken(token, nonce ?? "", config, googleKeySet);
          return true;
        },
      },
    },
    plugins: [
      jwt({
        jwks: {
          keyPairConfig: { alg: "ES256" },
          rotationInterval: KEY_ROTATION_TTL_SECONDS,
          gracePeriod: KEY_GRACE_TTL_SECONDS,
        },
        jwt: {
          issuer: config.issuer,
          expirationTime: "5 minutes",
          getSubject: ({ user }) => user.id,
        },
        disableSettingJwtHeader: true,
      }),
      oauthProvider({
        clientPrivileges: ({ user }: { user?: User & Record<string, unknown> }) =>
          options.allowOperatorPrivileges === true && user?.email === "operator@example.invalid",
        scopes: [...SCOPES],
        grantTypes: ["authorization_code"],
        codeExpiresIn: AUTHORIZATION_CODE_TTL_SECONDS,
        loginCodeExpiresIn: GOOGLE_LOGIN_TRANSACTION_TTL_SECONDS,
        idTokenExpiresIn: ID_TOKEN_TTL_SECONDS,
        accessTokenExpiresIn: ACCESS_TOKEN_TTL_SECONDS,
        loginPage: "/sign-in",
        consentPage: "/sign-in",
        allowDynamicClientRegistration: false,
        allowUnauthenticatedClientRegistration: false,
        storeTokens: "hashed",
        advertisedMetadata: {
          scopes_supported: [...SCOPES],
          claims_supported: ["iss", "sub", "aud", "exp", "iat", "nonce", "email", "email_verified", "name"],
        },
      }),
    ],
  });
}

export type AuthInstance = ReturnType<typeof createAuth>;
