# Workers-native SSO

This repository contains a Cloudflare Worker that signs users in through Google Workspace and provides an OpenID Connect (OIDC) provider for first-party confidential web applications. Applications keep their own sessions. The Worker keeps one central SSO session and issues short-lived OIDC tokens.

Google Workspace is the only upstream identity provider. This service is not Cloudflare Access. It does not store Google passwords or MFA credentials, and it never authenticates a user from an email suffix alone.

## Local development

Use [mise](https://mise.jdx.dev/) for the pinned Node.js and pnpm toolchain. `mise.toml` declares Node.js `24.19.0` and pnpm `11.21.0`; the committed `mise.lock` records the resolved toolchain and download checksums.

From the repository root, run:

```sh
mise trust
mise install --locked node@24.19.0 npm:pnpm@11.21.0
mise run bootstrap
mise run migrate-local
mise run dev
```

`mise run bootstrap` installs the frozen dependency set and creates `.dev.vars` from `.dev.vars.example` when the file does not exist. It never overwrites an existing `.dev.vars`. Set `AUTH_ISSUER`, `BETTER_AUTH_SECRETS`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `ALLOWED_GOOGLE_DOMAIN` there for local development. `.dev.vars` is ignored and must not be committed; the example values are fictional.

The local Worker uses D1 and listens on Wrangler’s default development address. Local Google integration tests use a fake upstream and do not contact Google. Use `mise run check` for the standard lint, format, type, and test checks, and `mise run build` for both dry-run Worker bundles.

Keep machine-specific mise overrides in the ignored `mise.local.toml` file.

## Trust boundary

The Google callback accepts an identity only after checking the Google issuer, RS256 signature, audience, expiration, nonce, `email_verified`, `sub`, and exact `hd` claim. A missing or different `hd` fails closed. The public OIDC `sub` is the local user ID, not Google’s `sub`. Email is not an identity key, and implicit email account linking is disabled.

The central session cookie is `__Host-better-auth.session_token`. It is `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, and has no `Domain` attribute. Sessions last eight hours and do not slide. Local application sessions are separate.

## OIDC and OAuth contract

Applications use OIDC discovery. They should not hard-code implementation-specific paths.

```text
https://<issuer>/.well-known/openid-configuration
https://<issuer>/.well-known/oauth-authorization-server
```

The provider exposes authorization, token, UserInfo, JWKS, and RP-initiated logout endpoints through the discovery document. The issuer is an HTTPS origin with no path, credentials, query, or fragment.

The supported flow is Authorization Code with PKCE `S256` for registered first-party confidential web clients only:

- Authorization accepts `GET` and form-encoded `POST`.
- Requests require `state`, `nonce`, an exact registered `redirect_uri`, `response_type=code`, and PKCE `S256`.
- The token request’s `code_verifier` must be 43–128 characters from the unreserved set `A-Z a-z 0-9 - . _ ~`.
- The token endpoint uses `client_secret_basic`.
- UserInfo accepts Bearer-only `GET`, or Bearer-only `POST` with an empty `application/x-www-form-urlencoded` body.
- Application logout is local to the relying party. `/sign-out` performs central logout, and `/oauth2/end-session` supports RP-initiated logout for enabled clients.

Authorization codes expire after 60 seconds and are single-use. ID tokens expire after five minutes. Access tokens expire after ten minutes. The central session is non-sliding and lasts eight hours. Google login continuation state lasts five minutes.

Supported scopes are `openid`, `profile`, and `email`. Standard OAuth errors include `invalid_client`, `invalid_grant`, and `invalid_token` with their normal status and authentication headers. Resource indicators are rejected before the OAuth provider. Refresh tokens, dynamic client registration, password login, signup, client credentials, implicit flow, public clients, and `offline_access` are not supported.

The local `sub` issued with `openid` is the only application identity key. `name`, `email`, and `email_verified` are returned according to the requested scopes; Google’s `sub`, Google tokens, roles, and groups are not exposed.

The provider signs ID tokens with ES256. Signing keys rotate every 90 days, and an old public key remains available for a 30-day grace period.

## Database migrations

The repository has one `0001_initial.sql` migration. It contains the Better Auth schema, authorization-admission capacity tracking, JWK revocation state, Google continuation linkage, and the required expiry and admission indexes. `mise run generate-migration` rebuilds it from Better Auth's generated schema and the project schema composer; `mise run migration-check` rejects drift or additional SQL migration files. Review the initial schema before applying it to shared D1. After it has been applied, keep it immutable and add a new migration for later schema changes.

## Client registration

Client registration is an operator action. The route is available only on the local or remote operator Worker; it is not on the production router.

Before any command, supply `BETTER_AUTH_SECRETS`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `ALLOWED_GOOGLE_DOMAIN`, and `AUTH_ISSUER` from the shell or a secret manager through the process environment. Remote operation also requires Wrangler authentication for the intended Cloudflare account, such as `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`, plus the explicit account and D1 database IDs shown below. The operator checks that the main and operator Wrangler configurations have matching D1 bindings and includes that target in both confirmations.

For local D1:

```sh
mise run client-create -- \
  --name "Example App" \
  --redirect-uri "https://app.example.invalid/callback" \
  --post-logout-redirect-uri "https://app.example.invalid/signed-out"
```

For remote D1, replace the non-secret target placeholders and include the exact target in both confirmations:

```sh
ACCOUNT_ID="<cloudflare-account-id>"
D1_DATABASE_ID="<d1-database-id>"
mise run client-create -- \
  --remote \
  --account-id "$ACCOUNT_ID" \
  --d1-database-id "$D1_DATABASE_ID" \
  --confirm-remote="CREATE-OAUTH-CLIENT-REMOTE:$ACCOUNT_ID:$D1_DATABASE_ID" \
  --confirm-remote-again="CREATE-OAUTH-CLIENT-REMOTE:$ACCOUNT_ID:$D1_DATABASE_ID" \
  --name "Example App" \
  --redirect-uri "https://app.example.invalid/callback" \
  --post-logout-redirect-uri "https://app.example.invalid/signed-out"
```

The command applies the operator migration, starts the operator Worker on loopback, waits for readiness from that spawned process, and prints the generated client secret once. Store it in the relying party’s secret store. The client is a trusted `type=web` client with `authorization_code`, `client_secret_basic`, PKCE, skipped consent, and RP-initiated logout enabled. Redirect and post-logout URIs must be exact HTTPS URLs without credentials, fragments, wildcards, or reserved response parameters.

The command writes a temporary env file with mode `0600`, passes only an allowlisted environment to the child Worker, and removes the child process group and temporary env on normal completion, failure, or interruption. Operator nonces and Worker secret values are not put in argv or child logs. The generated client secret is delivered once on the command’s output; do not copy it into source, D1, or logs.

## Cloudflare operator boundary

The repository does not create Cloudflare resources, D1 databases, Rate Limiting namespaces, DNS records, secrets, or deployments. Before production work, replace the placeholder D1 ID and namespace IDs for all five rate-limit bindings in the Wrangler configuration, set the required secrets, and set the real HTTPS issuer:

- `BETTER_AUTH_SECRETS`
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `ALLOWED_GOOGLE_DOMAIN`

The rate-limit bindings are `GOOGLE_LOGIN_RATE_LIMITER` at 30 requests/60 seconds, `OAUTH_AUTHORIZE_RATE_LIMITER` at 60/60, `OAUTH_TOKEN_RATE_LIMITER` at 30/60, `OAUTH_USERINFO_RATE_LIMITER` at 60/60, and `OAUTH_END_SESSION_RATE_LIMITER` at 30/60. They key on `cf-connecting-ip`; a missing binding, missing or oversized source IP, or limiter failure fails closed on the protected route. Pending Google login state has a total cap of 500, with separate 100-state standalone sign-in and 400-state relying-party authorization pools. The source cap is 25; relying-party states also have a 50-per-client cap and a 10-per-source/client cap. OAuth authorization admissions are persisted in D1 with caps of 1,000 globally and 20 per source/client pair, and expire with the five-minute Google continuation. Purge, count, and conditional insert run in the same D1 batch transaction. The continuation is bound to its admission; each Google transaction and authorization code is single-use. These persistent limits contain capacity and modest abuse, but do not completely prevent a sufficiently distributed set of senders from consuming one side of the split budget.

The Worker runs cleanup every 15 minutes. Each invocation performs at most eight rounds of 500-row batches for expired verification rows, access tokens, authorization admissions, sessions, and retired revoked or expired JWKs. Google login and authorization admission paths also purge bounded batches of expired state before admitting new work.

Observability is enabled, but `invocation_logs` is disabled. This avoids storing callback codes and `id_token_hint` values in platform invocation URL logs. Deploy preflight rejects placeholder or missing production configuration before a deployment command proceeds.

## Secret and JWK rotation

`BETTER_AUTH_SECRETS` is a newest-first versioned list. Put the new value before the old value and deploy while both are valid:

```text
2:<new-secret>,1:<old-secret>
```

For remote commands below, use the same non-secret `ACCOUNT_ID` and `D1_DATABASE_ID` target variables as in client registration.

Run the operator command locally:

```sh
mise run jwk-rotate -- --confirm=ROTATE-JWK
```

Run it against remote D1 only with an explicit target and both target-aware confirmations:

```sh
mise run jwk-rotate -- \
  --remote \
  --account-id "$ACCOUNT_ID" \
  --d1-database-id "$D1_DATABASE_ID" \
  --confirm="ROTATE-JWK:$ACCOUNT_ID:$D1_DATABASE_ID" \
  --confirm-again="ROTATE-JWK:$ACCOUNT_ID:$D1_DATABASE_ID"
```

Check the returned `key_id`, the published JWKS, and a real signed token. Keep v1 until values signed with it, including state and session values, have expired. Then deploy v2-only. The previous public JWK remains valid for the 30-day grace period. Never put secret values in source, D1, or logs.

For an emergency, revoke a retired key. The current signing key cannot be revoked. Local revoke requires the key ID in its confirmation:

```sh
mise run jwk-revoke -- \
  --key-id "$KEY_ID" \
  --confirm="REVOKE-JWK:$KEY_ID"
```

Remote revoke requires the explicit target and both target-aware confirmations:

```sh
mise run jwk-revoke -- \
  --remote \
  --account-id "$ACCOUNT_ID" \
  --d1-database-id "$D1_DATABASE_ID" \
  --key-id "$KEY_ID" \
  --confirm="REVOKE-JWK:$KEY_ID:$ACCOUNT_ID:$D1_DATABASE_ID" \
  --confirm-again="REVOKE-JWK:$KEY_ID:$ACCOUNT_ID:$D1_DATABASE_ID"
```

Revocation removes the retired key from JWKS and RP-initiated logout validation immediately. Normal rotation keeps a non-revoked retired public key available for the 30-day grace period.

## Deployment

Remote migration is an explicit operator action against the intended D1 database. Review the migration first, then run:

```sh
mise exec -- pnpm exec wrangler d1 migrations apply DB --remote --config wrangler.jsonc
mise run deploy-preflight
mise run build
```

`mise run build` runs `wrangler deploy --dry-run` for the main Worker and the operator Worker. A real deployment is a separate explicit action:

```sh
mise run deploy
```

Do not treat a dry-run as a deployment. The repository does not apply remote migrations or deploy automatically.

## Verification

Run the pinned install and the checks relevant to the change:

```sh
mise run bootstrap
mise run audit-prod
mise run audit-signatures
mise run supply-chain-check
mise run migrate-local
mise run db-check-local
mise run check
mise run migration-check
mise run types-check
mise run build
mise run deploy-preflight-negative
mise run operator-check
mise run oss-check
```

`mise run check` includes code and Markdown linting, formatting checks, type checking, and tests. The tests run with isolated local D1 migrations and fake Google responses.

## Supply-chain note

`@better-auth/oauth-provider` is pinned to the stable version `1.6.28`. `GHSA-p2fr-6hmx-4528` is the only explicit `pnpm audit` allowlist entry. The application rejects query, form-body, encoded, and duplicate `resource` parameters before the dependency handles authorization or token requests, making the advisory path unreachable here. When an upstream stable release contains the fix, update the exact `@better-auth/oauth-provider` pin to the first stable fixed release, then remove only the `pnpm audit` allowlist entry. This exception is intentional and must not become a silent ignore.
