import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";

process.env.BETTER_AUTH_SECRETS ??= "1:test-schema-secret-1234567890abcdef1234567890abcdef";
process.env.GOOGLE_CLIENT_ID ??= "test-google-client";
process.env.GOOGLE_CLIENT_SECRET ??= "test-google-secret";
process.env.ALLOWED_GOOGLE_DOMAIN ??= "example.com";
process.env.AUTH_ISSUER ??= "https://auth.example.invalid";

export default defineConfig({
  plugins: [
    cloudflareTest(async () => ({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        compatibilityDate: "2026-08-11",
        bindings: {
          BETTER_AUTH_SECRETS: "1:test-schema-secret-1234567890abcdef1234567890abcdef",
          GOOGLE_CLIENT_ID: "test-google-client",
          GOOGLE_CLIENT_SECRET: "test-google-secret",
          ALLOWED_GOOGLE_DOMAIN: "example.com",
          AUTH_ISSUER: "https://auth.example.invalid",
          TEST_MIGRATIONS: await readD1Migrations(fileURLToPath(new URL("./migrations", import.meta.url))),
        },
      },
    })),
  ],
  test: {
    setupFiles: ["./test/setup.ts"],
    include: ["test/**/*.test.ts"],
    testTimeout: 30_000,
    fileParallelism: false,
  },
});
