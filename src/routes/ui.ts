import type { Hono } from "hono";
import { getRuntimeConfig } from "../config";
import { completeGoogleLogin, oauthQueryFromSignIn, startGoogleLogin } from "../google";
import type { AppBindings, AuthResolver } from "../http";
import { createCSRFToken } from "../admin/csrf";
import { getSession, requireSession, uiUser } from "../admin/authz";
import { accountPage, signInPage } from "../ui/pages";
import { appStyles } from "../ui/styles";

export function registerUiRoutes(app: Hono<AppBindings>, resolveAuth: AuthResolver): void {
  app.get("/", async (context) => {
    const session = await getSession(context.req.raw, resolveAuth(context.env));
    if (!session) return context.redirect("/sign-in", 302);
    return context.redirect(session.user.id === context.env.AUTH_ADMIN_USER_ID ? "/admin" : "/account", 302);
  });

  app.get(
    "/assets/app.css",
    () =>
      new Response(appStyles, {
        headers: {
          "Cache-Control": "public, max-age=3600",
          "Content-Type": "text/css; charset=UTF-8",
        },
      }),
  );

  app.get("/sign-in", (context) => {
    const config = getRuntimeConfig(context.env);
    const query = oauthQueryFromSignIn(context.req.raw);
    const href = new URL("/sign-in/google", config.issuer);
    if (query) href.searchParams.set("oauth_query", query);
    return context.html(
      signInPage({
        brand: config.brand,
        googleHref: href.toString(),
        error: context.req.query("error") !== undefined,
      }),
    );
  });

  app.get("/account", async (context) => {
    const result = await requireSession(context.req.raw, resolveAuth(context.env));
    if (result instanceof Response) return result;
    const config = getRuntimeConfig(context.env);
    return context.html(
      accountPage(uiUser(result), config.brand, await createCSRFToken(result.session.id, context.env)),
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
