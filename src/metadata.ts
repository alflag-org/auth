import { SCOPES } from "./config";

export function oidcMetadata(issuer: string) {
  return {
    issuer,
    authorization_endpoint: `${issuer}/oauth2/authorize`,
    token_endpoint: `${issuer}/oauth2/token`,
    userinfo_endpoint: `${issuer}/oauth2/userinfo`,
    jwks_uri: `${issuer}/jwks`,
    end_session_endpoint: `${issuer}/oauth2/end-session`,
    scopes_supported: [...SCOPES],
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code"],
    token_endpoint_auth_methods_supported: ["client_secret_basic"],
    code_challenge_methods_supported: ["S256"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["ES256"],
    claims_supported: ["iss", "sub", "aud", "exp", "iat", "nonce", "email", "email_verified", "name"],
    authorization_response_iss_parameter_supported: true,
    request_parameter_supported: false,
    request_uri_parameter_supported: false,
  } as const;
}

export function metadataResponse(issuer: string): Response {
  return Response.json(oidcMetadata(issuer), {
    headers: { "Cache-Control": "public, max-age=300", "Content-Type": "application/json" },
  });
}
