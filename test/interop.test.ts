import { env } from "cloudflare:workers";
import { symmetricDecrypt } from "better-auth/crypto";
import { decodeJwt, importJWK, SignJWT } from "jose";
import { sha256Base64Url } from "../src/crypto";
import {
  authorizationCodeGrant,
  buildAuthorizationUrl,
  buildEndSessionUrl,
  ClientSecretBasic,
  type CustomFetchOptions,
  calculatePKCECodeChallenge,
  customFetch,
  discovery,
  enableNonRepudiationChecks,
  fetchUserInfo,
  randomNonce,
  randomPKCECodeVerifier,
  randomState,
} from "openid-client";
import { describe, expect, it } from "vitest";
import { dispatch } from "./support";
import { createTestOAuthClient, sessionCookie } from "./support";

const issuer = "https://auth.example.invalid";
const redirectURI = "https://app.example/callback";
const postLogoutRedirectURI = "https://app.example/signed-out";

async function signedSessionCookie(): Promise<string> {
  return sessionCookie({
    userId: "workspace-user",
    email: "user@example.com",
    token: "session-workspace-user",
    sessionId: "session-row-workspace-user",
    name: "Workspace user",
  });
}

async function createInteropClient() {
  return createTestOAuthClient({
    name: "Interop Client",
    redirectURI,
    postLogoutRedirectURI,
  });
}

function workerFetch(): (url: string, options: CustomFetchOptions) => Promise<Response> {
  return async (url, options) => {
    const requestInit: RequestInit = {
      method: options.method,
      headers: options.headers,
      redirect: options.redirect,
    };
    if (options.body !== undefined) requestInit.body = options.body as BodyInit | null;
    if (options.signal !== undefined) requestInit.signal = options.signal;
    const request = new Request(url, requestInit);
    const response = await dispatch(request);
    return new Response(await response.arrayBuffer(), { status: response.status, headers: response.headers });
  };
}

async function authorizationCallback(
  configuration: Awaited<ReturnType<typeof discovery>>,
  cookie: string,
  label: string,
) {
  const codeVerifier = randomPKCECodeVerifier();
  const state = `${label}-${randomState()}`;
  const nonce = `${label}-${randomNonce()}`;
  const codeChallenge = await calculatePKCECodeChallenge(codeVerifier);
  const authorizationURL = buildAuthorizationUrl(configuration, {
    redirect_uri: redirectURI,
    scope: "openid profile email",
    state,
    nonce,
    prompt: "none",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });
  const authorization = await dispatch(new Request(authorizationURL, { headers: { cookie }, redirect: "manual" }));
  expect(authorization.status, await authorization.clone().text()).toBe(302);
  const callback = new URL(authorization.headers.get("location") ?? "https://invalid.example/");
  const code = callback.searchParams.get("code");
  if (!code) throw new Error("authorization response did not include a code");
  return { callback, codeVerifier, state, nonce, code };
}

describe("openid-client interoperability", () => {
  it("discovers, completes authorization code + PKCE, validates the ID token and UserInfo, then performs RP logout", async () => {
    const client = await createInteropClient();
    if (!client.client_secret) throw new Error("operator client creation did not return a secret");
    const cookie = await signedSessionCookie();
    const configuration = await discovery(
      new URL(issuer),
      client.client_id,
      { client_secret: client.client_secret },
      ClientSecretBasic(client.client_secret),
      { [customFetch]: workerFetch() },
    );
    enableNonRepudiationChecks(configuration);
    expect(configuration.serverMetadata().issuer).toBe(issuer);
    expect(configuration.serverMetadata().jwks_uri).toBe(`${issuer}/jwks`);

    const codeVerifier = randomPKCECodeVerifier();
    const state = randomState();
    const nonce = randomNonce();
    const codeChallenge = await calculatePKCECodeChallenge(codeVerifier);
    const authorizationURL = buildAuthorizationUrl(configuration, {
      redirect_uri: redirectURI,
      scope: "openid profile email",
      state,
      nonce,
      prompt: "none",
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    });
    expect(authorizationURL.searchParams.get("client_id")).toBe(client.client_id);
    expect(authorizationURL.searchParams.get("response_type")).toBe("code");
    const authorization = await dispatch(new Request(authorizationURL, { headers: { cookie }, redirect: "manual" }));
    expect(authorization.status, await authorization.clone().text()).toBe(302);
    const callback = new URL(authorization.headers.get("location") ?? "https://invalid.example/");
    expect(callback.origin + callback.pathname).toBe(redirectURI);
    expect(callback.searchParams.get("state")).toBe(state);
    expect(callback.searchParams.get("code")).toBeTruthy();

    const tokens = await authorizationCodeGrant(configuration, callback, {
      pkceCodeVerifier: codeVerifier,
      expectedState: state,
      expectedNonce: nonce,
    });
    expect(tokens.token_type?.toLowerCase()).toBe("bearer");
    expect(tokens.expires_in).toBe(600);
    expect(tokens.refresh_token).toBeUndefined();
    const claims = tokens.claims();
    expect(claims?.sub).toBe("workspace-user");
    expect(claims?.iss).toBe(issuer);
    expect(claims?.aud).toBe(client.client_id);
    expect(claims?.nonce).toBe(nonce);
    expect(claims?.email).toBe("user@example.com");
    expect(claims?.email_verified).toBe(true);
    expect(tokens.id_token).toBeTypeOf("string");
    if (!tokens.access_token || !tokens.id_token)
      throw new Error("authorization code grant returned incomplete tokens");

    const userInfo = await fetchUserInfo(configuration, tokens.access_token, claims?.sub ?? "");
    expect(userInfo.sub).toBe("workspace-user");
    expect(userInfo.email).toBe("user@example.com");
    expect(userInfo.email_verified).toBe(true);
    const userInfoPost = await dispatch(
      new Request(`${issuer}/oauth2/userinfo`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${tokens.access_token}`,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: "",
      }),
    );
    expect(userInfoPost.status).toBe(200);
    const userInfoPostBody = (await userInfoPost.json()) as { sub?: string };
    expect(userInfoPostBody.sub).toBe("workspace-user");
    expect(userInfoPostBody).toEqual(userInfo);

    const expectInvalidToken = async (response: Response) => {
      expect(response.status).toBe(401);
      expect(response.headers.get("www-authenticate")).toBe('Bearer error="invalid_token"');
      const body = await response.text();
      expect(body).toBe(JSON.stringify({ error: "invalid_token" }));
      expect(body).not.toContain(tokens.access_token);
    };
    await expectInvalidToken(await dispatch(new Request(`${issuer}/oauth2/userinfo`)));
    await expectInvalidToken(
      await dispatch(
        new Request(`${issuer}/oauth2/userinfo`, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: "",
        }),
      ),
    );
    await expectInvalidToken(
      await dispatch(new Request(`${issuer}/oauth2/userinfo`, { headers: { authorization: "Basic not-a-bearer" } })),
    );
    await expectInvalidToken(
      await dispatch(new Request(`${issuer}/oauth2/userinfo`, { headers: { authorization: "Bearer" } })),
    );
    await expectInvalidToken(
      await dispatch(new Request(`${issuer}/oauth2/userinfo`, { headers: { authorization: "Bearer unknown-token" } })),
    );
    for (const query of [
      `access_token=${encodeURIComponent(tokens.access_token)}`,
      "access_token=unknown-token",
      "foo=bar",
    ]) {
      const queryTokenResponse = await dispatch(
        new Request(`${issuer}/oauth2/userinfo?${query}`, {
          headers: { authorization: `Bearer ${tokens.access_token}` },
        }),
      );
      expect(queryTokenResponse.status).toBe(400);
      expect(await queryTokenResponse.json()).toEqual({ error: "invalid_request" });
    }
    const nonemptyPost = await dispatch(
      new Request(`${issuer}/oauth2/userinfo`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${tokens.access_token}`,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: "scope=openid",
      }),
    );
    expect(nonemptyPost.status).toBe(400);
    expect(await nonemptyPost.json()).toEqual({ error: "invalid_request" });
    const duplicatePost = await dispatch(
      new Request(`${issuer}/oauth2/userinfo`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${tokens.access_token}`,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: "scope=openid&scope=profile",
      }),
    );
    expect(duplicatePost.status).toBe(400);
    expect(await duplicatePost.json()).toEqual({ error: "invalid_request" });
    const oversizedPost = await dispatch(
      new Request(`${issuer}/oauth2/userinfo`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${tokens.access_token}`,
          "content-type": "application/x-www-form-urlencoded",
          "content-length": "16385",
        },
        body: "",
      }),
    );
    expect(oversizedPost.status).toBe(400);
    expect(await oversizedPost.json()).toEqual({ error: "invalid_request" });

    const accessTokenHash = await sha256Base64Url(tokens.access_token);
    const originalAccessToken = await env.DB.prepare("SELECT scopes, expiresAt FROM oauthAccessToken WHERE token = ?")
      .bind(accessTokenHash)
      .first<{ scopes: string; expiresAt: string }>();
    if (!originalAccessToken) throw new Error("access token row was not created");
    await env.DB.prepare("UPDATE oauthAccessToken SET scopes = ? WHERE token = ?")
      .bind("not-json", accessTokenHash)
      .run();
    await expectInvalidToken(
      await dispatch(
        new Request(`${issuer}/oauth2/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } }),
      ),
    );
    await env.DB.prepare("UPDATE oauthAccessToken SET scopes = ? WHERE token = ?")
      .bind(originalAccessToken.scopes, accessTokenHash)
      .run();
    const restoredUserInfo = await dispatch(
      new Request(`${issuer}/oauth2/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } }),
    );
    expect(restoredUserInfo.status).toBe(200);
    expect(await restoredUserInfo.json()).toEqual(userInfo);
    await env.DB.prepare("UPDATE oauthAccessToken SET expiresAt = ? WHERE token = ?")
      .bind("not-a-date", accessTokenHash)
      .run();
    await expectInvalidToken(
      await dispatch(
        new Request(`${issuer}/oauth2/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } }),
      ),
    );
    await env.DB.prepare("UPDATE oauthAccessToken SET expiresAt = ? WHERE token = ?")
      .bind(originalAccessToken.expiresAt, accessTokenHash)
      .run();
    const restoredAfterExpiry = await dispatch(
      new Request(`${issuer}/oauth2/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } }),
    );
    expect(restoredAfterExpiry.status).toBe(200);
    expect(await restoredAfterExpiry.json()).toEqual(userInfo);

    const postAuthorization = new URL(`${issuer}/oauth2/authorize`);
    const postAuthorizationForm = new URLSearchParams({
      client_id: client.client_id,
      response_type: "code",
      redirect_uri: redirectURI,
      scope: "openid profile email",
      state: "post-state",
      nonce: "post-nonce",
      code_challenge: await calculatePKCECodeChallenge(randomPKCECodeVerifier()),
      code_challenge_method: "S256",
    });
    const postAuthorizationResponse = await dispatch(
      new Request(postAuthorization, {
        method: "POST",
        headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
        body: postAuthorizationForm,
        redirect: "manual",
      }),
    );
    expect(postAuthorizationResponse.status).toBe(302);
    expect(new URL(postAuthorizationResponse.headers.get("location") ?? "https://invalid.example/").origin).toBe(
      new URL(redirectURI).origin,
    );

    const knownClientError = new URL(`${issuer}/oauth2/authorize`);
    knownClientError.search = new URLSearchParams({
      client_id: client.client_id,
      response_type: "code",
      redirect_uri: redirectURI,
      scope: "openid",
      state: "known-error-state",
      nonce: "known-error-nonce",
      code_challenge: await calculatePKCECodeChallenge(randomPKCECodeVerifier()),
      code_challenge_method: "S256",
      prompt: "create",
    }).toString();
    const knownErrorResponse = await dispatch(new Request(knownClientError, { redirect: "manual" }));
    expect(knownErrorResponse.status).toBe(302);
    const knownErrorLocation = new URL(knownErrorResponse.headers.get("location") ?? "https://invalid.example/");
    expect(knownErrorLocation.origin + knownErrorLocation.pathname).toBe(redirectURI);
    expect(knownErrorLocation.searchParams.get("error")).toBe("invalid_request");
    expect(knownErrorLocation.searchParams.get("state")).toBe("known-error-state");
    expect(knownErrorLocation.searchParams.get("iss")).toBe(issuer);

    const unknownClientError = new URL(`${issuer}/oauth2/authorize`);
    unknownClientError.search = new URLSearchParams({
      client_id: "unknown-client",
      response_type: "code",
      redirect_uri: redirectURI,
      scope: "openid",
      state: "unknown-error-state",
      nonce: "unknown-error-nonce",
      code_challenge: await calculatePKCECodeChallenge(randomPKCECodeVerifier()),
      code_challenge_method: "S256",
      prompt: "create",
    }).toString();
    const unknownErrorResponse = await dispatch(new Request(unknownClientError, { redirect: "manual" }));
    expect(unknownErrorResponse.status).toBe(400);

    const wrongAlgorithm = await new SignJWT({
      aud: client.client_id,
      sid: "session-row-workspace-user",
    })
      .setProtectedHeader({ alg: "HS256" })
      .sign(new TextEncoder().encode("wrong-algorithm-secret"));
    const wrongAlgorithmURL = new URL(`${issuer}/oauth2/end-session`);
    wrongAlgorithmURL.search = new URLSearchParams({
      id_token_hint: wrongAlgorithm,
      client_id: client.client_id,
    }).toString();
    const wrongAlgorithmResponse = await dispatch(new Request(wrongAlgorithmURL, { redirect: "manual" }));
    expect(wrongAlgorithmResponse.status).toBe(400);

    const oversizedStateURL = new URL(`${issuer}/oauth2/end-session`);
    oversizedStateURL.search = new URLSearchParams({
      id_token_hint: tokens.id_token,
      client_id: client.client_id,
      post_logout_redirect_uri: postLogoutRedirectURI,
      state: "x".repeat(257),
    }).toString();
    const oversizedStateResponse = await dispatch(new Request(oversizedStateURL, { redirect: "manual" }));
    expect(oversizedStateResponse.status).toBe(400);

    const logoutURL = buildEndSessionUrl(configuration, {
      id_token_hint: tokens.id_token,
      post_logout_redirect_uri: postLogoutRedirectURI,
      state: "logout-state",
    });
    const logout = await dispatch(new Request(logoutURL, { headers: { cookie }, redirect: "manual" }));
    expect(logout.status, await logout.clone().text()).toBe(302);
    expect(logout.headers.get("location")).toBe(`${postLogoutRedirectURI}?state=logout-state`);
    const session = await env.DB.prepare("SELECT id FROM session WHERE id = ?")
      .bind("session-row-workspace-user")
      .first();
    expect(session).toBeNull();
  });

  it("rejects tampered and wrongly issued ID tokens at the openid-client validation boundary", async () => {
    const client = await createInteropClient();
    if (!client.client_secret) throw new Error("operator client creation did not return a secret");
    const cookie = await signedSessionCookie();
    await dispatch(new Request(`${issuer}/jwks`));
    const jwksRow = await env.DB.prepare("SELECT id, privateKey FROM jwks ORDER BY createdAt DESC LIMIT 1").first<{
      id: string;
      privateKey: string;
    }>();
    if (!jwksRow) throw new Error("local signing key was not generated");
    const secret = env.BETTER_AUTH_SECRETS.split(":", 2)[1];
    if (!secret) throw new Error("test secret was not configured");
    const privateKeyJSON = await symmetricDecrypt({
      key: { keys: new Map([[1, secret]]), currentVersion: 1 },
      data: JSON.parse(jwksRow.privateKey),
    });
    const privateKey = await importJWK(JSON.parse(privateKeyJSON), "ES256");
    let mutation: "tamper" | "issuer" | "audience" | "nonce" | "expiry" = "tamper";
    let tokenMutations = 0;
    const configuration = await discovery(
      new URL(issuer),
      client.client_id,
      { client_secret: client.client_secret },
      ClientSecretBasic(client.client_secret),
      {
        [customFetch]: async (url, options) => {
          const response = await workerFetch()(url, options);
          if (new URL(url).pathname !== "/oauth2/token") return response;
          const body = (await response.json()) as { id_token?: string; [key: string]: unknown };
          if (!body.id_token) throw new Error("token endpoint did not return an ID token");
          tokenMutations += 1;
          if (mutation === "tamper") {
            const parts = body.id_token.split(".");
            parts[2] = `${parts[2]?.startsWith("a") ? "b" : "a"}${parts[2]?.slice(1) ?? ""}`;
            body.id_token = parts.join(".");
          } else {
            const claims = decodeJwt(body.id_token);
            const altered = {
              ...claims,
              ...(mutation === "issuer" ? { iss: "https://wrong.example.invalid" } : {}),
              ...(mutation === "audience" ? { aud: "wrong-client" } : {}),
              ...(mutation === "nonce" ? { nonce: "wrong-nonce" } : {}),
              ...(mutation === "expiry" ? { exp: Math.floor(Date.now() / 1000) - 60 } : {}),
            };
            body.id_token = await new SignJWT(altered)
              .setProtectedHeader({ alg: "ES256", kid: jwksRow.id })
              .sign(privateKey);
          }
          return Response.json(body, { headers: { "content-type": "application/json" } });
        },
      },
    );
    enableNonRepudiationChecks(configuration);
    for (const check of ["tamper", "issuer", "audience", "nonce", "expiry"] as const) {
      mutation = check;
      const flow = await authorizationCallback(configuration, cookie, `id-token-${check}`);
      await expect(
        authorizationCodeGrant(configuration, flow.callback, {
          pkceCodeVerifier: flow.codeVerifier,
          expectedState: flow.state,
          expectedNonce: flow.nonce,
        }),
      ).rejects.toThrow();
    }
    expect(tokenMutations).toBe(5);
  });
});
