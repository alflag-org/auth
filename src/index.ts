import { Hono } from "hono";
import { type AuthInstance, createAuth } from "./auth";
import { getRuntimeConfig } from "./config";
import { type AppBindings, registerSecurityMiddleware } from "./http";
import { registerLogoutRoutes } from "./routes/logout";
import { registerProtocolRoutes } from "./routes/protocol";
import { registerUiRoutes } from "./routes/ui";
import { metadataResponse } from "./metadata";
import { cleanupExpiredVerification } from "./cleanup";

export function createApp(): Hono<AppBindings> {
  const app = new Hono<AppBindings>();
  const authByEnvironment = new WeakMap<object, AuthInstance>();
  const resolveAuth = (environment: Env): AuthInstance => {
    const cached = authByEnvironment.get(environment);
    if (cached) return cached;
    const auth = createAuth(environment);
    authByEnvironment.set(environment, auth);
    return auth;
  };

  registerSecurityMiddleware(app);
  registerUiRoutes(app, resolveAuth);
  registerLogoutRoutes(app, resolveAuth);
  app.get("/healthz", (context) => context.json({ status: "ok" }));
  app.get("/.well-known/openid-configuration", (context) => metadataResponse(getRuntimeConfig(context.env).issuer));
  app.get("/.well-known/oauth-authorization-server", (context) =>
    metadataResponse(getRuntimeConfig(context.env).issuer),
  );
  registerProtocolRoutes(app, resolveAuth);
  app.all("*", () => new Response("Not Found", { status: 404 }));
  return app;
}

const app = createApp();

export default {
  fetch: app.fetch,
  scheduled: async (_controller, environment) => {
    await cleanupExpiredVerification(environment.DB, new Date(), 500, 8);
  },
} satisfies ExportedHandler<Env>;
