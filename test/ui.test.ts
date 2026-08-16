import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { codeChallenge, dispatch, sessionCookie } from "./support";

const issuer = "https://auth.example.invalid";

async function userCookie(label: string, userId: string): Promise<string> {
  return sessionCookie({
    userId,
    email: `${label}@example.com`,
    token: `ui-token-${label}`,
    sessionId: `ui-session-${label}`,
    name: label === "admin" ? "UI Admin" : "UI User",
  });
}

function csrfToken(html: string): string {
  const token = /name="csrf_token" value="([^"]+)"/u.exec(html)?.[1];
  if (!token) throw new Error("UI page did not contain a CSRF token");
  return token;
}

function formRequest(
  path: string,
  cookie: string,
  values: Record<string, string>,
  origin = issuer,
  fetchSite?: string,
): Request {
  const body = new URLSearchParams(values);
  const headers: Record<string, string> = {
    cookie,
    origin,
    "content-type": "application/x-www-form-urlencoded",
  };
  if (fetchSite) headers["sec-fetch-site"] = fetchSite;
  return new Request(`${issuer}${path}`, {
    method: "POST",
    headers,
    body,
  });
}

async function clientIdAndSecret(html: string): Promise<{ clientId: string; secret: string }> {
  const clientId = /<p><strong>Client ID<\/strong><\/p><code>([^<]+)<\/code>/u.exec(html)?.[1];
  const secret = /class="secret-value">([^<]+)<\/code>/u.exec(html)?.[1];
  if (!clientId || !secret) throw new Error("client creation page did not contain the one-time credentials");
  return { clientId, secret };
}

describe("server-rendered management UI", () => {
  it("protects the console and manages OAuth clients through Better Auth", async () => {
    const signIn = await dispatch(new Request(`${issuer}/sign-in?oauth_query=opaque-signed-value`));
    expect(signIn.status).toBe(200);
    const signInHTML = await signIn.text();
    expect(signInHTML).toContain("Continue with Google");
    expect(signInHTML).toContain("/assets/app.css");
    expect(signIn.headers.get("cache-control")).toBe("no-store");
    expect(signIn.headers.get("content-security-policy")).toBe(
      "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    );
    expect(signIn.headers.get("x-frame-options")).toBe("DENY");

    const unauthenticated = await dispatch(new Request(`${issuer}/admin`));
    expect(unauthenticated.status).toBe(302);
    expect(unauthenticated.headers.get("location")).toBe("/sign-in");

    const nonAdminCookie = await userCookie("member", "ui-non-admin");
    const nonAdmin = await dispatch(new Request(`${issuer}/admin`, { headers: { cookie: nonAdminCookie } }));
    expect(nonAdmin.status).toBe(403);
    const account = await dispatch(new Request(`${issuer}/account`, { headers: { cookie: nonAdminCookie } }));
    expect(account.status).toBe(200);
    expect(await account.text()).toContain("ui-non-admin");

    const adminCookie = await userCookie("admin", "test-admin");
    const root = await dispatch(new Request(`${issuer}/`, { headers: { cookie: adminCookie }, redirect: "manual" }));
    expect(root.status).toBe(302);
    expect(root.headers.get("location")).toBe("/admin");

    const overview = await dispatch(new Request(`${issuer}/admin`, { headers: { cookie: adminCookie } }));
    expect(overview.status).toBe(200);
    expect(await overview.text()).toContain("Operational");

    const newClientPage = await dispatch(
      new Request(`${issuer}/admin/clients/new`, { headers: { cookie: adminCookie } }),
    );
    expect(newClientPage.status).toBe(200);
    const newClientHTML = await newClientPage.text();
    const initialCSRF = csrfToken(newClientHTML);
    const redirectURI = "https://ui.example/callback";
    const postLogoutURI = "https://ui.example/signed-out";

    const wrongOrigin = await dispatch(
      formRequest(
        "/admin/clients",
        adminCookie,
        {
          csrf_token: initialCSRF,
          client_name: "Wrong origin",
          redirect_uris: redirectURI,
          post_logout_redirect_uris: postLogoutURI,
          enable_end_session: "true",
        },
        "https://attacker.example",
      ),
    );
    expect(wrongOrigin.status).toBe(403);

    const nullOriginCrossSite = await dispatch(
      formRequest(
        "/admin/clients",
        adminCookie,
        {
          csrf_token: initialCSRF,
          client_name: "Null origin cross-site",
          redirect_uris: redirectURI,
          post_logout_redirect_uris: postLogoutURI,
        },
        "null",
        "cross-site",
      ),
    );
    expect(nullOriginCrossSite.status).toBe(403);

    const wrongCSRF = await dispatch(
      formRequest("/admin/clients", adminCookie, {
        csrf_token: "invalid",
        client_name: "Wrong CSRF",
        redirect_uris: redirectURI,
        post_logout_redirect_uris: postLogoutURI,
      }),
    );
    expect(wrongCSRF.status).toBe(403);

    const invalidURI = await dispatch(
      formRequest("/admin/clients", adminCookie, {
        csrf_token: initialCSRF,
        client_name: "Invalid URI",
        redirect_uris: "http://ui.example/callback",
        post_logout_redirect_uris: postLogoutURI,
      }),
    );
    expect(invalidURI.status).toBe(400);
    expect(await invalidURI.text()).toContain("must use HTTPS");

    const created = await dispatch(
      formRequest(
        "/admin/clients",
        adminCookie,
        {
          csrf_token: initialCSRF,
          client_name: "UI & Client",
          redirect_uris: redirectURI,
          post_logout_redirect_uris: postLogoutURI,
          enable_end_session: "true",
        },
        "null",
        "same-origin",
      ),
    );
    expect(created.status).toBe(201);
    const createdHTML = await created.text();
    expect(createdHTML).toContain("Client created");
    expect(createdHTML).toContain("Store this value now.");
    const { clientId, secret: firstSecret } = await clientIdAndSecret(createdHTML);

    const detail = await dispatch(
      new Request(`${issuer}/admin/clients/${encodeURIComponent(clientId)}`, { headers: { cookie: adminCookie } }),
    );
    expect(detail.status).toBe(200);
    const detailHTML = await detail.text();
    expect(detailHTML).toContain("UI &amp; Client");
    expect(detailHTML).toContain("Hidden");
    expect(detailHTML).not.toContain(firstSecret);

    const list = await dispatch(new Request(`${issuer}/admin/clients`, { headers: { cookie: adminCookie } }));
    expect(list.status).toBe(200);
    const listHTML = await list.text();
    expect(listHTML).toContain("UI &amp; Client");
    expect(listHTML).not.toContain(firstSecret);

    const editPage = await dispatch(
      new Request(`${issuer}/admin/clients/${encodeURIComponent(clientId)}/edit`, { headers: { cookie: adminCookie } }),
    );
    const editCSRF = csrfToken(await editPage.text());
    const updatedRedirectURI = "https://ui.example/updated-callback";
    const updated = await dispatch(
      formRequest(`/admin/clients/${encodeURIComponent(clientId)}`, adminCookie, {
        csrf_token: editCSRF,
        client_name: "UI Updated Client",
        redirect_uris: `${updatedRedirectURI}\n${updatedRedirectURI}`,
        post_logout_redirect_uris: "",
      }),
    );
    expect(updated.status).toBe(303);
    expect(updated.headers.get("location")).toBe(`/admin/clients/${encodeURIComponent(clientId)}?status=updated`);

    const updatedDetail = await dispatch(
      new Request(`${issuer}/admin/clients/${encodeURIComponent(clientId)}`, { headers: { cookie: adminCookie } }),
    );
    const updatedDetailHTML = await updatedDetail.text();
    expect(updatedDetailHTML).toContain("UI Updated Client");
    expect(updatedDetailHTML).toContain(updatedRedirectURI);
    expect(updatedDetailHTML).not.toContain(postLogoutURI);

    const rotatePage = await dispatch(
      new Request(`${issuer}/admin/clients/${encodeURIComponent(clientId)}/rotate-secret`, {
        headers: { cookie: adminCookie },
      }),
    );
    const rotateCSRF = csrfToken(await rotatePage.text());
    const rotated = await dispatch(
      formRequest(`/admin/clients/${encodeURIComponent(clientId)}/rotate-secret`, adminCookie, {
        csrf_token: rotateCSRF,
      }),
    );
    expect(rotated.status).toBe(200);
    const rotatedCredentials = await clientIdAndSecret(await rotated.text());
    expect(rotatedCredentials.clientId).toBe(clientId);
    expect(rotatedCredentials.secret).not.toBe(firstSecret);

    const rotatedDetail = await dispatch(
      new Request(`${issuer}/admin/clients/${encodeURIComponent(clientId)}`, { headers: { cookie: adminCookie } }),
    );
    expect(await rotatedDetail.text()).not.toContain(rotatedCredentials.secret);

    const oldSecret = await dispatch(
      new Request(`${issuer}/oauth2/token`, {
        method: "POST",
        headers: {
          authorization: `Basic ${btoa(`${clientId}:${firstSecret}`)}`,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: "not-a-real-code",
          redirect_uri: updatedRedirectURI,
          code_verifier: "ui-old-secret-verifier-abcdefghijklmnopqrstuvwxyz-0123456789",
        }),
      }),
    );
    expect(oldSecret.status).toBe(401);
    expect(await oldSecret.text()).not.toContain(firstSecret);

    const detailForDisable = await dispatch(
      new Request(`${issuer}/admin/clients/${encodeURIComponent(clientId)}`, { headers: { cookie: adminCookie } }),
    );
    const disableCSRF = csrfToken(await detailForDisable.text());
    const disabled = await dispatch(
      formRequest(`/admin/clients/${encodeURIComponent(clientId)}/disable`, adminCookie, {
        csrf_token: disableCSRF,
      }),
    );
    expect(disabled.status).toBe(303);

    const verifier = "ui-disabled-verifier-abcdefghijklmnopqrstuvwxyz-0123456789";
    const disabledAuthorizeURL = new URL(`${issuer}/oauth2/authorize`);
    disabledAuthorizeURL.search = new URLSearchParams({
      client_id: clientId,
      response_type: "code",
      redirect_uri: updatedRedirectURI,
      scope: "openid profile email",
      state: "disabled-state",
      nonce: "disabled-nonce",
      code_challenge: await codeChallenge(verifier),
      code_challenge_method: "S256",
    }).toString();
    const disabledAuthorization = await dispatch(new Request(disabledAuthorizeURL));
    expect(disabledAuthorization.status).toBe(400);
    expect(await disabledAuthorization.json()).toEqual({ error: "invalid_client" });

    const detailForEnable = await dispatch(
      new Request(`${issuer}/admin/clients/${encodeURIComponent(clientId)}`, { headers: { cookie: adminCookie } }),
    );
    const enableCSRF = csrfToken(await detailForEnable.text());
    const enabled = await dispatch(
      formRequest(`/admin/clients/${encodeURIComponent(clientId)}/enable`, adminCookie, {
        csrf_token: enableCSRF,
      }),
    );
    expect(enabled.status).toBe(303);

    const deletePage = await dispatch(
      new Request(`${issuer}/admin/clients/${encodeURIComponent(clientId)}/delete`, {
        headers: { cookie: adminCookie },
      }),
    );
    expect(deletePage.status).toBe(200);
    const deleteCSRF = csrfToken(await deletePage.text());
    const deleted = await dispatch(
      formRequest(`/admin/clients/${encodeURIComponent(clientId)}/delete`, adminCookie, {
        csrf_token: deleteCSRF,
      }),
    );
    expect(deleted.status).toBe(303);

    const missing = await dispatch(
      new Request(`${issuer}/admin/clients/${encodeURIComponent(clientId)}`, { headers: { cookie: adminCookie } }),
    );
    expect(missing.status).toBe(404);

    const audits = await env.DB.prepare(
      "SELECT action, detail FROM adminAudit WHERE targetId = ? ORDER BY createdAt ASC, id ASC",
    )
      .bind(clientId)
      .all<{ action: string; detail: string }>();
    expect(audits.results.map((row) => row.action)).toEqual([
      "client.create",
      "client.update",
      "client.rotate_secret",
      "client.disable",
      "client.enable",
      "client.delete",
    ]);
    expect(audits.results.map((row) => row.detail).join(" ")).not.toContain(firstSecret);
    expect(audits.results.map((row) => row.detail).join(" ")).not.toContain(rotatedCredentials.secret);
  });
});
