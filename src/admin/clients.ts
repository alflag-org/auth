import type { OAuthClient } from "@better-auth/oauth-provider";
import type { Context, Hono } from "hono";
import { getRuntimeConfig, SCOPES, type RuntimeConfig } from "../config";
import type { AuthInstance } from "../auth";
import type { AppBindings, AuthResolver } from "../http";
import { logAdminFailure, requireAdmin, requireAdminMutation, serviceUnavailableResponse, uiUser } from "./authz";
import { recordAudit, recentAudits } from "./audit";
import {
  adminOverviewPage,
  clientDetailPage,
  clientFormPage,
  clientListPage,
  clientSecretPage,
  deleteConfirmPage,
  type ClientView,
  type PageBrand,
  rotateSecretConfirmPage,
} from "../ui/pages";

const MAX_CLIENT_NAME_LENGTH = 120;
const MAX_URI_LENGTH = 2048;
const MAX_URI_COUNT = 8;
const AUTHORIZATION_RESPONSE_PARAMETERS = new Set([
  "code",
  "state",
  "iss",
  "error",
  "error_description",
  "error_uri",
  "session_state",
  "response",
]);

type ClientInput = {
  name: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  enableEndSession: boolean;
};

type ParsedInput = { ok: true; value: ClientInput } | { ok: false; message: string };

function headersFor(request: Request): Headers {
  return new Headers(request.headers);
}

function toView(client: OAuthClient): ClientView {
  return {
    client_id: client.client_id,
    client_name: client.client_name,
    scope: client.scope,
    redirect_uris: [...client.redirect_uris],
    post_logout_redirect_uris: client.post_logout_redirect_uris ? [...client.post_logout_redirect_uris] : undefined,
    disabled: client.disabled,
    require_pkce: client.require_pkce,
    enable_end_session: client.enable_end_session,
    token_endpoint_auth_method: client.token_endpoint_auth_method,
    grant_types: client.grant_types ? [...client.grant_types] : undefined,
    response_types: client.response_types ? [...client.response_types] : undefined,
    type: client.type,
    skip_consent: client.skip_consent,
  };
}

function clientInputError(value: string, kind: "redirect" | "logout"): string | null {
  if (value.length === 0 || value.length > MAX_URI_LENGTH)
    return `${kind === "redirect" ? "Redirect" : "Post logout redirect"} URI is too long.`;
  if (value.includes("*") || value.includes("#"))
    return `${kind === "redirect" ? "Redirect" : "Post logout redirect"} URI contains a forbidden character.`;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return `${kind === "redirect" ? "Redirect" : "Post logout redirect"} URI must be an absolute URL.`;
  }
  if (url.protocol !== "https:")
    return `${kind === "redirect" ? "Redirect" : "Post logout redirect"} URI must use HTTPS.`;
  if (url.username || url.password || url.hash)
    return `${kind === "redirect" ? "Redirect" : "Post logout redirect"} URI must not contain credentials or a fragment.`;
  const reserved = kind === "redirect" ? AUTHORIZATION_RESPONSE_PARAMETERS : new Set(["state"]);
  if ([...url.searchParams.keys()].some((name) => reserved.has(name))) {
    return `${kind === "redirect" ? "Redirect" : "Post logout redirect"} URI contains a reserved parameter.`;
  }
  return null;
}

function parseURIs(
  raw: string,
  label: "redirect" | "logout",
  required: boolean,
): { ok: true; value: string[] } | { ok: false; message: string } {
  const values = raw
    .split(/\r?\n/u)
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
  if (required && values.length === 0) return { ok: false, message: "At least one redirect URI is required." };
  if (values.length > MAX_URI_COUNT) return { ok: false, message: "Too many redirect URIs." };
  const unique = [...new Set(values)];
  for (const value of unique) {
    const error = clientInputError(value, label);
    if (error) return { ok: false, message: error };
  }
  return { ok: true, value: unique };
}

function parseClientInput(form: URLSearchParams): ParsedInput {
  const name = form.get("client_name")?.trim() ?? "";
  if (name.length === 0 || name.length > MAX_CLIENT_NAME_LENGTH) return { ok: false, message: "Name is required." };
  const redirectUris = parseURIs(form.get("redirect_uris") ?? "", "redirect", true);
  if (!redirectUris.ok) return redirectUris;
  const postLogoutRedirectUris = parseURIs(form.get("post_logout_redirect_uris") ?? "", "logout", false);
  if (!postLogoutRedirectUris.ok) return postLogoutRedirectUris;
  return {
    ok: true,
    value: {
      name,
      redirectUris: redirectUris.value,
      postLogoutRedirectUris: postLogoutRedirectUris.value,
      enableEndSession: form.has("enable_end_session"),
    },
  };
}

async function listClients(auth: AuthInstance, request: Request): Promise<OAuthClient[]> {
  return (await auth.api.getOAuthClients({ headers: headersFor(request) })) ?? [];
}

async function findClient(auth: AuthInstance, request: Request, clientId: string): Promise<OAuthClient | null> {
  try {
    return await auth.api.getOAuthClient({ headers: headersFor(request), query: { client_id: clientId } });
  } catch {
    return null;
  }
}

function brand(config: RuntimeConfig): PageBrand {
  return config.brand;
}

function clientMutationBody(input: ClientInput) {
  return {
    client_name: input.name,
    redirect_uris: input.redirectUris,
    ...(input.postLogoutRedirectUris.length > 0 ? { post_logout_redirect_uris: input.postLogoutRedirectUris } : {}),
    scope: SCOPES.join(" "),
    token_endpoint_auth_method: "client_secret_basic" as const,
    grant_types: ["authorization_code"] as ("authorization_code" | "client_credentials" | "refresh_token")[],
    response_types: ["code"] as "code"[],
    type: "web" as const,
    client_secret_expires_at: 0,
    skip_consent: true,
    enable_end_session: input.enableEndSession,
    require_pkce: true,
  };
}

function updateBody(input: ClientInput) {
  return {
    redirect_uris: input.redirectUris,
    post_logout_redirect_uris: input.postLogoutRedirectUris,
    scope: SCOPES.join(" "),
    client_name: input.name,
    grant_types: ["authorization_code"] as ("authorization_code" | "client_credentials" | "refresh_token")[],
    response_types: ["code"] as "code"[],
    type: "web" as const,
    skip_consent: true,
    enable_end_session: input.enableEndSession,
  };
}

function genericOperationError(): string {
  return "Unable to complete this operation.";
}

function statusNotice(value: string | undefined): string | undefined {
  if (value === "enabled") return "Client enabled.";
  if (value === "disabled") return "Client disabled. New authorization requests are rejected.";
  if (value === "updated") return "Client updated.";
  return undefined;
}

export function registerAdminRoutes(app: Hono<AppBindings>, resolveAuth: AuthResolver): void {
  app.get("/admin", async (context) => {
    const auth = resolveAuth(context.env);
    const access = await requireAdmin(context.req.raw, context.env, auth);
    if (access instanceof Response) return access;
    try {
      const config = getRuntimeConfig(context.env);
      const [clients, audits] = await Promise.all([listClients(auth, context.req.raw), recentAudits(context.env.DB)]);
      return context.html(
        adminOverviewPage({
          user: uiUser(access.session),
          brand: brand(config),
          csrfToken: access.csrfToken,
          issuer: config.issuer,
          clientCount: clients.length,
          audits,
        }),
      );
    } catch (error) {
      logAdminFailure(context.req.raw, "overview", error);
      return serviceUnavailableResponse();
    }
  });

  app.get("/admin/clients", async (context) => {
    const auth = resolveAuth(context.env);
    const access = await requireAdmin(context.req.raw, context.env, auth);
    if (access instanceof Response) return access;
    try {
      const config = getRuntimeConfig(context.env);
      return context.html(
        clientListPage({
          user: uiUser(access.session),
          brand: brand(config),
          csrfToken: access.csrfToken,
          clients: (await listClients(auth, context.req.raw)).map(toView),
          notice: context.req.query("deleted") === "1" ? "Client deleted." : undefined,
        }),
      );
    } catch (error) {
      logAdminFailure(context.req.raw, "client.list", error);
      return serviceUnavailableResponse();
    }
  });

  app.get("/admin/clients/new", async (context) => {
    const auth = resolveAuth(context.env);
    const access = await requireAdmin(context.req.raw, context.env, auth);
    if (access instanceof Response) return access;
    const config = getRuntimeConfig(context.env);
    return context.html(
      clientFormPage({
        brand: brand(config),
        user: uiUser(access.session),
        csrfToken: access.csrfToken,
        mode: "create",
      }),
    );
  });

  app.post("/admin/clients", async (context) => {
    const auth = resolveAuth(context.env);
    const mutation = await requireAdminMutation(context.req.raw, context.env, auth);
    if (mutation instanceof Response) return mutation;
    const config = getRuntimeConfig(context.env);
    const parsed = parseClientInput(mutation.form);
    if (!parsed.ok)
      return context.html(
        clientFormPage({
          brand: brand(config),
          user: uiUser(mutation.session),
          csrfToken: mutation.csrfToken,
          mode: "create",
          error: parsed.message,
        }),
        400,
      );
    try {
      const created = await auth.api.adminCreateOAuthClient({
        headers: headersFor(context.req.raw),
        body: clientMutationBody(parsed.value),
      });
      if (!created.client_secret) throw new Error("Better Auth did not return a client secret");
      await recordAudit(context.env.DB, {
        actorUserId: mutation.session.user.id,
        action: "client.create",
        targetId: created.client_id,
        targetName: parsed.value.name,
        detail: { redirectCount: parsed.value.redirectUris.length },
      });
      return context.html(
        clientSecretPage({
          brand: brand(config),
          user: uiUser(mutation.session),
          csrfToken: mutation.csrfToken,
          client: toView(created),
          secret: created.client_secret,
          action: "created",
        }),
        201,
      );
    } catch (error) {
      logAdminFailure(context.req.raw, "client.create", error);
      return context.html(
        clientFormPage({
          brand: brand(config),
          user: uiUser(mutation.session),
          csrfToken: mutation.csrfToken,
          mode: "create",
          error: genericOperationError(),
        }),
        400,
      );
    }
  });

  app.get("/admin/clients/:clientId/edit", async (context) => {
    const auth = resolveAuth(context.env);
    const access = await requireAdmin(context.req.raw, context.env, auth);
    if (access instanceof Response) return access;
    const clientId = context.req.param("clientId");
    const client = await findClient(auth, context.req.raw, clientId);
    if (!client) return new Response("Not Found", { status: 404 });
    const config = getRuntimeConfig(context.env);
    return context.html(
      clientFormPage({
        brand: brand(config),
        user: uiUser(access.session),
        csrfToken: access.csrfToken,
        mode: "edit",
        client: toView(client),
      }),
    );
  });

  app.post("/admin/clients/:clientId", async (context) => {
    const auth = resolveAuth(context.env);
    const mutation = await requireAdminMutation(context.req.raw, context.env, auth);
    if (mutation instanceof Response) return mutation;
    const clientId = context.req.param("clientId");
    const current = await findClient(auth, context.req.raw, clientId);
    if (!current) return new Response("Not Found", { status: 404 });
    const config = getRuntimeConfig(context.env);
    const parsed = parseClientInput(mutation.form);
    if (!parsed.ok)
      return context.html(
        clientFormPage({
          brand: brand(config),
          user: uiUser(mutation.session),
          csrfToken: mutation.csrfToken,
          mode: "edit",
          client: toView(current),
          error: parsed.message,
        }),
        400,
      );
    try {
      const updated = await auth.api.adminUpdateOAuthClient({
        headers: headersFor(context.req.raw),
        body: { client_id: clientId, update: updateBody(parsed.value) },
      });
      await recordAudit(context.env.DB, {
        actorUserId: mutation.session.user.id,
        action: "client.update",
        targetId: clientId,
        targetName: parsed.value.name,
        detail: {
          redirectUrisChanged: JSON.stringify(current.redirect_uris) !== JSON.stringify(parsed.value.redirectUris),
          postLogoutRedirectUrisChanged:
            JSON.stringify(current.post_logout_redirect_uris ?? []) !==
            JSON.stringify(parsed.value.postLogoutRedirectUris),
          rpLogoutEnabled: parsed.value.enableEndSession,
        },
      });
      if (!updated.client_id) throw new Error("Better Auth did not return the updated client");
      return context.redirect(`/admin/clients/${encodeURIComponent(clientId)}?status=updated`, 303);
    } catch (error) {
      logAdminFailure(context.req.raw, "client.update", error);
      return context.html(
        clientFormPage({
          brand: brand(config),
          user: uiUser(mutation.session),
          csrfToken: mutation.csrfToken,
          mode: "edit",
          client: {
            ...toView(current),
            client_name: parsed.value.name,
            redirect_uris: parsed.value.redirectUris,
            post_logout_redirect_uris: parsed.value.postLogoutRedirectUris,
          },
          error: genericOperationError(),
        }),
        400,
      );
    }
  });

  app.get("/admin/clients/:clientId/rotate-secret", async (context) => {
    const auth = resolveAuth(context.env);
    const access = await requireAdmin(context.req.raw, context.env, auth);
    if (access instanceof Response) return access;
    const client = await findClient(auth, context.req.raw, context.req.param("clientId"));
    if (!client) return new Response("Not Found", { status: 404 });
    const config = getRuntimeConfig(context.env);
    return context.html(
      rotateSecretConfirmPage({
        brand: brand(config),
        user: uiUser(access.session),
        csrfToken: access.csrfToken,
        client: toView(client),
      }),
    );
  });

  app.post("/admin/clients/:clientId/rotate-secret", async (context) => {
    const auth = resolveAuth(context.env);
    const mutation = await requireAdminMutation(context.req.raw, context.env, auth);
    if (mutation instanceof Response) return mutation;
    const clientId = context.req.param("clientId");
    const current = await findClient(auth, context.req.raw, clientId);
    if (!current) return new Response("Not Found", { status: 404 });
    try {
      const rotated = await auth.api.rotateClientSecret({
        headers: headersFor(context.req.raw),
        body: { client_id: clientId },
      });
      if (!rotated.client_secret) throw new Error("Better Auth did not return a rotated client secret");
      await recordAudit(context.env.DB, {
        actorUserId: mutation.session.user.id,
        action: "client.rotate_secret",
        targetId: clientId,
        targetName: current.client_name ?? "Unnamed client",
      });
      const config = getRuntimeConfig(context.env);
      return context.html(
        clientSecretPage({
          brand: brand(config),
          user: uiUser(mutation.session),
          csrfToken: mutation.csrfToken,
          client: toView(rotated),
          secret: rotated.client_secret,
          action: "rotated",
        }),
        200,
      );
    } catch (error) {
      logAdminFailure(context.req.raw, "client.rotate_secret", error);
      return serviceUnavailableResponse();
    }
  });

  app.post("/admin/clients/:clientId/disable", async (context) => {
    return toggleClient(context, resolveAuth, true);
  });

  app.post("/admin/clients/:clientId/enable", async (context) => {
    return toggleClient(context, resolveAuth, false);
  });

  app.get("/admin/clients/:clientId/delete", async (context) => {
    const auth = resolveAuth(context.env);
    const access = await requireAdmin(context.req.raw, context.env, auth);
    if (access instanceof Response) return access;
    const client = await findClient(auth, context.req.raw, context.req.param("clientId"));
    if (!client) return new Response("Not Found", { status: 404 });
    const config = getRuntimeConfig(context.env);
    return context.html(
      deleteConfirmPage({
        brand: brand(config),
        user: uiUser(access.session),
        csrfToken: access.csrfToken,
        client: toView(client),
      }),
    );
  });

  app.post("/admin/clients/:clientId/delete", async (context) => {
    const auth = resolveAuth(context.env);
    const mutation = await requireAdminMutation(context.req.raw, context.env, auth);
    if (mutation instanceof Response) return mutation;
    const clientId = context.req.param("clientId");
    const client = await findClient(auth, context.req.raw, clientId);
    if (!client) return new Response("Not Found", { status: 404 });
    try {
      await auth.api.deleteOAuthClient({ headers: headersFor(context.req.raw), body: { client_id: clientId } });
      await recordAudit(context.env.DB, {
        actorUserId: mutation.session.user.id,
        action: "client.delete",
        targetId: clientId,
        targetName: client.client_name ?? "Unnamed client",
      });
      return context.redirect("/admin/clients?deleted=1", 303);
    } catch (error) {
      logAdminFailure(context.req.raw, "client.delete", error);
      return serviceUnavailableResponse();
    }
  });

  app.get("/admin/clients/:clientId", async (context) => {
    const auth = resolveAuth(context.env);
    const access = await requireAdmin(context.req.raw, context.env, auth);
    if (access instanceof Response) return access;
    const client = await findClient(auth, context.req.raw, context.req.param("clientId"));
    if (!client) return new Response("Not Found", { status: 404 });
    const config = getRuntimeConfig(context.env);
    return context.html(
      clientDetailPage({
        brand: brand(config),
        user: uiUser(access.session),
        csrfToken: access.csrfToken,
        client: toView(client),
        notice: statusNotice(context.req.query("status")),
      }),
    );
  });
}

async function toggleClient(
  context: Context<AppBindings>,
  resolveAuth: AuthResolver,
  disabled: boolean,
): Promise<Response> {
  const auth = resolveAuth(context.env);
  const mutation = await requireAdminMutation(context.req.raw, context.env, auth);
  if (mutation instanceof Response) return mutation;
  const clientId = context.req.param("clientId") ?? "";
  if (!clientId) return new Response("Not Found", { status: 404 });
  const current = await findClient(auth, context.req.raw, clientId);
  if (!current) return new Response("Not Found", { status: 404 });
  try {
    await auth.api.adminUpdateOAuthClient({
      headers: headersFor(context.req.raw),
      body: { client_id: clientId, update: { disabled } },
    });
    await recordAudit(context.env.DB, {
      actorUserId: mutation.session.user.id,
      action: disabled ? "client.disable" : "client.enable",
      targetId: clientId,
      targetName: current.client_name ?? "Unnamed client",
    });
    return context.redirect(
      `/admin/clients/${encodeURIComponent(clientId)}?status=${disabled ? "disabled" : "enabled"}`,
      303,
    );
  } catch (error) {
    logAdminFailure(context.req.raw, disabled ? "client.disable" : "client.enable", error);
    return serviceUnavailableResponse();
  }
}
