import { env } from "cloudflare:workers";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { codeChallenge, createTestOAuthClient, dispatch, sessionCookie as createSessionCookie } from "./support";

const issuer = "https://auth.example.invalid";
const redirectURI = "https://matrix.example/callback";

async function sessionCookie(label: string): Promise<string> {
  return createSessionCookie({
    userId: `matrix-user-${label}`,
    email: `${label}@example.com`,
    token: `matrix-session-${label}`,
    sessionId: `matrix-session-row-${label}`,
    name: "Matrix User",
    userAgent: "protocol-matrix",
  });
}

async function createClient(label: string, redirect = redirectURI) {
  return createTestOAuthClient({
    name: `Matrix ${label}`,
    redirectURI: redirect,
    postLogoutRedirectURI: "https://matrix.example/signed-out",
  });
}

function challenge(value = "matrix-verifier-abcdefghijklmnopqrstuvwxyz-0123456789"): string {
  return value === "not-s256"
    ? "matrix-verifier-abcdefghijklmnopqrstuvwxyz-0123456789"
    : "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
}

function authorizationURL(
  clientId: string,
  options: Partial<
    Record<
      | "response_type"
      | "redirect_uri"
      | "scope"
      | "state"
      | "nonce"
      | "code_challenge"
      | "code_challenge_method"
      | "response_mode",
      string
    >
  > = {},
): URL {
  const params = new URLSearchParams({
    client_id: clientId,
    response_type: "code",
    redirect_uri: redirectURI,
    scope: "openid profile email",
    state: "matrix-state",
    nonce: "matrix-nonce",
    code_challenge: challenge(),
    code_challenge_method: "S256",
    ...options,
  });
  return new URL(`${issuer}/oauth2/authorize?${params}`);
}

async function issueCode(clientId: string, label: string): Promise<string> {
  const response = await dispatch(
    new Request(authorizationURL(clientId, { state: `state-${label}`, nonce: `nonce-${label}` }), {
      headers: { cookie: await sessionCookie(label) },
      redirect: "manual",
    }),
  );
  expect(response.status, await response.clone().text()).toBe(302);
  const code = new URL(response.headers.get("location") ?? "https://invalid.example/").searchParams.get("code");
  if (!code) throw new Error("authorization response did not include a code");
  return code;
}

async function issueCodeWithVerifier(clientId: string, label: string): Promise<{ code: string; verifier: string }> {
  const verifier = `matrix-resource-${label}-abcdefghijklmnopqrstuvwxyz-0123456789`;
  const response = await dispatch(
    new Request(
      authorizationURL(clientId, {
        state: `state-${label}`,
        nonce: `nonce-${label}`,
        code_challenge: await codeChallenge(verifier),
      }),
      { headers: { cookie: await sessionCookie(label) }, redirect: "manual" },
    ),
  );
  expect(response.status, await response.clone().text()).toBe(302);
  const code = new URL(response.headers.get("location") ?? "https://invalid.example/").searchParams.get("code");
  if (!code) throw new Error("authorization response did not include a code");
  return { code, verifier };
}

async function assertJSON(response: Response, status: number, body: Record<string, string>): Promise<void> {
  const text = await response.clone().text();
  if (status === 400 && response.status === 302) {
    const location = new URL(response.headers.get("location") ?? "https://invalid.example/");
    expect(location.searchParams.get("error")).toBe(body.error);
    return;
  }
  expect(response.status, text).toBe(status);
  if (response.status === 400 && text === "Bad request") {
    expect(body.error).toBe("invalid_request");
    return;
  }
  expect(JSON.parse(text)).toEqual(body);
}

describe("authorization protocol controls", () => {
  let sharedClient: Awaited<ReturnType<typeof createClient>>;
  beforeAll(async () => {
    sharedClient = await createClient("shared");
  });

  it("rejects missing state, nonce, PKCE, non-S256 PKCE, and unsupported response types precisely", async () => {
    const client = sharedClient;
    const cases = [
      ["missing state", { state: "" }, { error: "invalid_request" }],
      ["missing nonce", { nonce: "" }, { error: "invalid_request" }],
      ["missing PKCE", { code_challenge: "", code_challenge_method: "" }, { error: "invalid_request" }],
      ["non-S256 PKCE", { code_challenge_method: "plain" }, { error: "invalid_request" }],
      ["response type", { response_type: "token" }, { error: "unsupported_response_type" }],
    ] as const;
    for (const [name, options, body] of cases) {
      const response = await dispatch(new Request(authorizationURL(client.client_id, options)));
      await assertJSON(response, 400, body);
      if (name === "response type") {
        const location = new URL(response.headers.get("location") ?? "https://invalid.example/");
        expect(location.searchParams.get("error")).toBe("unsupported_response_type");
        expect(location.searchParams.get("state")).toBe("matrix-state");
        expect(location.searchParams.get("iss")).toBe(issuer);
      }
      expect(name).toBeTypeOf("string");
    }
  });

  it("rejects an unregistered, modified, and structurally unsafe redirect URI", async () => {
    const client = sharedClient;
    for (const redirect of ["https://matrix.example/other", "https://matrix.example/callback?changed=1"]) {
      const response = await dispatch(new Request(authorizationURL(client.client_id, { redirect_uri: redirect })));
      await assertJSON(response, 400, { error: "invalid_request" });
    }
    const unsafe = await dispatch(
      new Request(authorizationURL(client.client_id, { redirect_uri: "https://matrix.example/callback/" })),
    );
    await assertJSON(unsafe, 400, { error: "invalid_request" });
    const polluted = authorizationURL(client.client_id);
    polluted.searchParams.append("redirect_uri", "https://attacker.example/callback");
    await assertJSON(await dispatch(new Request(polluted)), 400, { error: "invalid_request" });
  });

  it("rejects disabled clients before authorization and does not redirect an error", async () => {
    const client = sharedClient;
    await env.DB.prepare("UPDATE oauthClient SET disabled = 1 WHERE clientId = ?").bind(client.client_id).run();
    const response = await dispatch(new Request(authorizationURL(client.client_id)));
    await assertJSON(response, 400, { error: "invalid_client" });
    await env.DB.prepare("UPDATE oauthClient SET disabled = 0 WHERE clientId = ?").bind(client.client_id).run();
  });

  it("rejects unsupported scopes and all public registration or management routes", async () => {
    const client = sharedClient;
    const offline = await dispatch(new Request(authorizationURL(client.client_id, { scope: "openid offline_access" })));
    await assertJSON(offline, 400, { error: "invalid_scope" });
    const paths = [
      "/oauth2/register",
      "/oauth2/create-client",
      "/oauth2/update-client",
      "/oauth2/delete-client",
      "/oauth2/client/rotate-secret",
      "/oauth2/get-clients",
      "/oauth2/get-client",
      "/oauth2/public-client",
      "/oauth2/public-client-prelogin",
      "/oauth2/get-consent",
      "/oauth2/get-consents",
      "/oauth2/update-consent",
      "/oauth2/delete-consent",
      "/admin/oauth2/create-client",
      "/admin/oauth2/update-client",
      "/admin/oauth2/delete-client",
      "/admin/oauth2/get-client",
      "/admin/oauth2/get-clients",
      "/admin/oauth2/rotate-secret",
      "/sign-up/email",
      "/sign-in/email",
      "/forget-password",
      "/reset-password",
      "/change-password",
      "/set-password",
      "/delete-user",
      "/update-user",
      "/get-session",
      "/list-sessions",
      "/revoke-session",
      "/unknown-route",
    ];
    for (const path of paths) {
      const response = await dispatch(new Request(`${issuer}${path}`, { method: "POST" }));
      expect(response.status, path).toBe(404);
      expect(await response.text(), path).toBe("Not Found");
    }
  });

  it("accepts query response mode, rejects request objects, and advertises callback issuer", async () => {
    const client = sharedClient;
    const session = await sessionCookie("response-mode");
    const queryResponse = await dispatch(
      new Request(authorizationURL(client.client_id, { response_mode: "query" }), {
        headers: { cookie: session },
        redirect: "manual",
      }),
    );
    expect(queryResponse.status).toBe(302);
    const callback = new URL(queryResponse.headers.get("location") ?? "https://invalid.example/");
    expect(callback.searchParams.get("iss")).toBe(issuer);
    const queryRedirect = "https://matrix.example/callback?tenant=a";
    const queryClient = await createClient("query-redirect", queryRedirect);
    const queryRedirectResponse = await dispatch(
      new Request(authorizationURL(queryClient.client_id, { redirect_uri: queryRedirect }), {
        headers: { cookie: session },
        redirect: "manual",
      }),
    );
    expect(queryRedirectResponse.status).toBe(302);
    const queryCallback = new URL(queryRedirectResponse.headers.get("location") ?? "https://invalid.example/");
    expect(queryCallback.origin + queryCallback.pathname).toBe("https://matrix.example/callback");
    expect(queryCallback.searchParams.get("tenant")).toBe("a");
    expect(queryCallback.searchParams.get("state")).toBe("matrix-state");
    expect(queryCallback.searchParams.get("code")).toBeTruthy();
    expect(queryCallback.searchParams.get("iss")).toBe(issuer);
    const maliciousQueryClient = await createClient("reserved-query", "https://matrix.example/callback?code=attacker");
    await assertJSON(
      await dispatch(
        new Request(
          authorizationURL(maliciousQueryClient.client_id, {
            redirect_uri: "https://matrix.example/callback?code=attacker",
          }),
        ),
      ),
      400,
      { error: "invalid_request" },
    );
    const fragmentResponse = await dispatch(
      new Request(authorizationURL(client.client_id, { response_mode: "fragment" }), {
        headers: { cookie: session },
      }),
    );
    await assertJSON(fragmentResponse, 400, { error: "unsupported_response_mode" });
    for (const parameter of ["request", "request_uri"]) {
      const requestURL = authorizationURL(client.client_id);
      requestURL.searchParams.set(parameter, "signed-request");
      await assertJSON(await dispatch(new Request(requestURL)), 400, { error: "invalid_request" });
    }
  });

  it("rejects resource indicators before Better Auth without consuming the authorization code", async () => {
    const client = sharedClient;
    if (!client.client_secret) throw new Error("client secret was not returned");
    const authorizationWithResource = authorizationURL(client.client_id);
    authorizationWithResource.search += "&%72esource=https%3A%2F%2Fresource.example%2Fapi";
    await assertJSON(await dispatch(new Request(authorizationWithResource)), 400, { error: "invalid_request" });

    const flow = await issueCodeWithVerifier(client.client_id, "resource-indicator");
    const basic = `Basic ${btoa(`${client.client_id}:${client.client_secret}`)}`;
    const rejectedQueryResource = await dispatch(
      new Request(`${issuer}/oauth2/token?%72esource=${encodeURIComponent("https://resource.example/api")}`, {
        method: "POST",
        headers: { authorization: basic, "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: flow.code,
          redirect_uri: redirectURI,
          code_verifier: flow.verifier,
        }),
      }),
    );
    await assertJSON(rejectedQueryResource, 400, { error: "invalid_request" });

    const rejectedResource = await dispatch(
      new Request(`${issuer}/oauth2/token`, {
        method: "POST",
        headers: { authorization: basic, "content-type": "application/x-www-form-urlencoded" },
        body: `grant_type=authorization_code&code=${encodeURIComponent(flow.code)}&redirect_uri=${encodeURIComponent(redirectURI)}&code_verifier=${encodeURIComponent(flow.verifier)}&%72esource=https%3A%2F%2Fresource.example%2Fapi`,
      }),
    );
    await assertJSON(rejectedResource, 400, { error: "invalid_request" });

    const duplicateResource = await dispatch(
      new Request(`${issuer}/oauth2/token`, {
        method: "POST",
        headers: { authorization: basic, "content-type": "application/x-www-form-urlencoded" },
        body: `grant_type=authorization_code&code=${encodeURIComponent(flow.code)}&redirect_uri=${encodeURIComponent(redirectURI)}&code_verifier=${encodeURIComponent(flow.verifier)}&resource=https%3A%2F%2Fresource.example%2Fapi&resource=https%3A%2F%2Fresource.example%2Fother`,
      }),
    );
    await assertJSON(duplicateResource, 400, { error: "invalid_request" });

    const normalToken = await dispatch(
      new Request(`${issuer}/oauth2/token`, {
        method: "POST",
        headers: { authorization: basic, "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: flow.code,
          redirect_uri: redirectURI,
          code_verifier: flow.verifier,
        }),
      }),
    );
    expect(normalToken.status, await normalToken.clone().text()).toBe(200);
    const tokens = (await normalToken.json()) as { access_token: string };
    expect(tokens.access_token).not.toContain(".");
  });

  it("rejects missing and wrong client authentication and client_secret_post", async () => {
    const client = sharedClient;
    if (!client.client_secret) throw new Error("client secret was not returned");
    const missing = await dispatch(
      new Request(`${issuer}/oauth2/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "authorization_code", code: "unused", redirect_uri: redirectURI }),
      }),
    );
    await assertJSON(missing, 401, { error: "invalid_client" });
    const malformedScheme = await dispatch(
      new Request(`${issuer}/oauth2/token`, {
        method: "POST",
        headers: {
          authorization: `Basicx ${btoa(`${client.client_id}:unused`)}`,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({ grant_type: "authorization_code" }),
      }),
    );
    await assertJSON(malformedScheme, 401, { error: "invalid_client" });
    const wrongSecretCode = await issueCode(client.client_id, "wrong-secret");
    const wrong = await dispatch(
      new Request(`${issuer}/oauth2/token`, {
        method: "POST",
        headers: {
          authorization: `Basic ${btoa(`${client.client_id}:wrong-secret`)}`,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: wrongSecretCode,
          redirect_uri: redirectURI,
        }),
      }),
    );
    await assertJSON(wrong, 401, { error: "invalid_client", error_description: "invalid client" });
    const post = await dispatch(
      new Request(`${issuer}/oauth2/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: client.client_id,
          client_secret: client.client_secret,
          code: "unused",
          redirect_uri: redirectURI,
        }),
      }),
    );
    await assertJSON(post, 401, { error: "invalid_client" });
    const duplicateGrant = await dispatch(
      new Request(`${issuer}/oauth2/token`, {
        method: "POST",
        headers: {
          authorization: `Basic ${btoa(`${client.client_id}:${client.client_secret}`)}`,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: "grant_type=authorization_code&grant_type=client_credentials",
      }),
    );
    await assertJSON(duplicateGrant, 400, { error: "invalid_request" });
    const duplicateCode = await dispatch(
      new Request(`${issuer}/oauth2/token`, {
        method: "POST",
        headers: {
          authorization: `Basic ${btoa(`${client.client_id}:${client.client_secret}`)}`,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: "grant_type=authorization_code&code=one&code=two",
      }),
    );
    await assertJSON(duplicateCode, 400, { error: "invalid_request" });
  });

  it("rejects refresh, password, client_credentials, and offline attempts with the protocol error", async () => {
    const client = sharedClient;
    if (!client.client_secret) throw new Error("client secret was not returned");
    const basic = `Basic ${btoa(`${client.client_id}:${client.client_secret}`)}`;
    for (const grantType of ["refresh_token", "password", "client_credentials"]) {
      const response = await dispatch(
        new Request(`${issuer}/oauth2/token`, {
          method: "POST",
          headers: { authorization: basic, "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ grant_type: grantType, scope: "openid offline_access" }),
        }),
      );
      await assertJSON(response, 400, { error: "unsupported_grant_type" });
    }
  });

  it("redacts codes, bearer tokens, session cookies, and client secrets from protocol errors", async () => {
    const markers = [
      "marker-authorization-code",
      "marker-access-token",
      "marker-session-cookie",
      "marker-client-secret",
      "marker-better-auth-secret",
      "marker-signing-private-key",
    ];
    const markerCode = markers[0];
    const markerVerifier = markers[1];
    const markerClientSecret = markers[3];
    if (!markerCode || !markerVerifier || !markerClientSecret) throw new Error("test markers were incomplete");
    const logs: string[] = [];
    const spies = [
      vi.spyOn(console, "debug").mockImplementation((...values) => logs.push(values.join(" "))),
      vi.spyOn(console, "info").mockImplementation((...values) => logs.push(values.join(" "))),
      vi.spyOn(console, "warn").mockImplementation((...values) => logs.push(values.join(" "))),
      vi.spyOn(console, "error").mockImplementation((...values) => logs.push(values.join(" "))),
    ];
    const tokenError = await dispatch(
      new Request(`${issuer}/oauth2/token`, {
        method: "POST",
        headers: {
          authorization: `Basic ${btoa(`${sharedClient.client_id}:${markers[3]}`)}`,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: markerCode,
          redirect_uri: redirectURI,
          code_verifier: markerVerifier,
          client_secret: markerClientSecret,
          client_id: sharedClient.client_id,
        }),
      }),
    );
    const tokenErrorBody = await tokenError.text();
    const sessionError = await dispatch(
      new Request(`${issuer}/get-session`, { headers: { cookie: `__Host-better-auth.session_token=${markers[2]}` } }),
    );
    const sessionErrorBody = await sessionError.text();
    for (const marker of markers) {
      expect(tokenErrorBody).not.toContain(marker);
      expect(sessionErrorBody).not.toContain(marker);
      expect(logs.join("\n")).not.toContain(marker);
    }
    for (const spy of spies) spy.mockRestore();
  });

  it("rejects an oversized chunked token request without buffering it in full", async () => {
    const client = sharedClient;
    if (!client.client_secret) throw new Error("client secret was not returned");
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("grant_type=authorization_code&"));
        controller.enqueue(new Uint8Array(20_000));
        controller.close();
      },
    });
    const response = await dispatch(
      new Request(`${issuer}/oauth2/token`, {
        method: "POST",
        headers: {
          authorization: `Basic ${btoa(`${client.client_id}:${client.client_secret}`)}`,
          "content-type": "application/x-www-form-urlencoded",
        },
        body,
      }),
    );
    await assertJSON(response, 400, { error: "invalid_request" });
  });
});
