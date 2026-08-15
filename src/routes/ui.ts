import type { Hono } from "hono";
import { getRuntimeConfig } from "../config";
import { completeGoogleLogin, oauthQueryFromSignIn, startGoogleLogin } from "../google";
import type { AppBindings, AuthResolver } from "../http";

export function registerUiRoutes(app: Hono<AppBindings>, resolveAuth: AuthResolver): void {
  app.get("/", (context) =>
    context.html(
      '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Example SSO</title></head><body><h1>Example SSO</h1><p>Google Workspace sign-in for first-party applications.</p><p><a href="/sign-in">Sign in</a></p></body></html>',
    ),
  );

  app.get("/sign-in", (context) => {
    const query = oauthQueryFromSignIn(context.req.raw);
    const issuer = getRuntimeConfig(context.env).issuer;
    const href = new URL("/sign-in/google", issuer);
    if (query) href.searchParams.set("oauth_query", query);
    const error = context.req.query("error") ? '<p role="alert">Sign-in failed. Try again.</p>' : "";
    return context.html(
      `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Sign in</title></head><body><main><h1>Sign in</h1>${error}<p>Workspace accounts only</p><p><a href="${href.toString()}">Continue with Google</a></p></main></body></html>`,
    );
  });

  app.get("/sign-in/google", async (context) =>
    startGoogleLogin(context.req.raw, getRuntimeConfig(context.env), context.env.DB, {
      rateLimiter: context.env.GOOGLE_LOGIN_RATE_LIMITER,
      requireRateLimiter: true,
    }),
  );
  app.get("/callback/google", async (context) =>
    completeGoogleLogin(context.req.raw, resolveAuth(context.env), getRuntimeConfig(context.env), {
      stateStore: context.env.DB,
      rateLimiter: context.env.GOOGLE_LOGIN_RATE_LIMITER,
      requireRateLimiter: true,
    }),
  );
}
