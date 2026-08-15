import { applyD1Migrations, type D1Migration } from "cloudflare:test";
import { env } from "cloudflare:workers";

const testEnvironment = env as Env & { TEST_MIGRATIONS: D1Migration[] };
await applyD1Migrations(testEnvironment.DB, testEnvironment.TEST_MIGRATIONS);
