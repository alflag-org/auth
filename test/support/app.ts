import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { createApp } from "../../src/index";

export const testApp = createApp();
const testRateLimiter: RateLimit = { limit: async () => ({ success: true }) };
const testEnvironment = {
  ...env,
  OAUTH_AUTHORIZE_RATE_LIMITER: testRateLimiter,
  OAUTH_TOKEN_RATE_LIMITER: testRateLimiter,
  OAUTH_USERINFO_RATE_LIMITER: testRateLimiter,
  OAUTH_END_SESSION_RATE_LIMITER: testRateLimiter,
} as Env;

export async function dispatch(request: Request): Promise<Response> {
  const executionContext = createExecutionContext();
  const headers = new Headers(request.headers);
  headers.set("cf-connecting-ip", headers.get("cf-connecting-ip") ?? "198.51.100.1");
  const response = await testApp.fetch(new Request(request, { headers }), testEnvironment, executionContext);
  await waitOnExecutionContext(executionContext);
  return response;
}

export async function dispatchWithEnvironment(request: Request, environment: Env): Promise<Response> {
  const executionContext = createExecutionContext();
  const headers = new Headers(request.headers);
  headers.set("cf-connecting-ip", headers.get("cf-connecting-ip") ?? "198.51.100.1");
  const response = await testApp.fetch(new Request(request, { headers }), environment, executionContext);
  await waitOnExecutionContext(executionContext);
  return response;
}
