import { readFile, readdir } from "node:fs/promises";
import { getMigrations } from "better-auth/db/migration";
import { createAuth, type AuthEnvironment } from "../src/auth";
import { buildInitialMigration } from "./initial-migration";

const migrationPath = "migrations/0001_initial.sql";
const adminAuditMigrationPath = "migrations/0002_admin_audit.sql";
const expectedAdminAuditMigration = [
  'create table "adminAudit" (',
  '  "id" text not null primary key,',
  '  "actorUserId" text not null,',
  '  "action" text not null,',
  '  "targetType" text not null,',
  '  "targetId" text not null,',
  '  "targetName" text not null,',
  '  "detail" text not null,',
  '  "createdAt" date not null',
  ");",
  "",
  'create index "adminAudit_createdAt_idx" on "adminAudit" ("createdAt");',
  "",
].join("\n");
const fakePreparedStatement: D1PreparedStatement = {
  bind: (..._values: unknown[]) => fakePreparedStatement,
  first: async (_column?: string) => {
    throw new Error("migration check must not query D1");
  },
  run: async () => {
    throw new Error("migration check must not query D1");
  },
  all: async <T = Record<string, unknown>>(): Promise<D1Result<T>> => ({
    success: true,
    meta: { duration: 0, size_after: 0, rows_read: 0, rows_written: 0, last_row_id: 0, changed_db: false, changes: 0 },
    results: [],
  }),
  raw: async (_options?: { columnNames?: boolean }) => {
    throw new Error("migration check must not query D1");
  },
};
const fakeD1: D1Database = {
  prepare: (_query: string) => fakePreparedStatement,
  batch: async (_statements: D1PreparedStatement[]) => {
    throw new Error("migration check must not query D1");
  },
  exec: async (_query: string) => {
    throw new Error("migration check must not query D1");
  },
  withSession: () => {
    throw new Error("migration check must not query D1");
  },
  dump: async () => {
    throw new Error("migration check must not query D1");
  },
};
const env: AuthEnvironment = {
  DB: fakeD1,
  AUTH_ISSUER: "https://auth.example.invalid",
  BETTER_AUTH_SECRETS: "1:migration-check-secret-1234567890abcdef1234567890abcdef",
  GOOGLE_CLIENT_ID: "migration-check-client",
  GOOGLE_CLIENT_SECRET: "migration-check-secret-1234567890abcdef1234567890abcdef",
  ALLOWED_GOOGLE_DOMAIN: "example.com",
};

const migrationFiles = (await readdir("migrations")).filter((name) => name.endsWith(".sql")).sort();
if (migrationFiles[0] !== "0001_initial.sql" || migrationFiles[1] !== "0002_admin_audit.sql")
  throw new Error(
    `expected migrations/0001_initial.sql and migrations/0002_admin_audit.sql first, found: ${migrationFiles.join(", ")}`,
  );

const adminAuditMigration = await readFile(adminAuditMigrationPath, "utf8");
if (adminAuditMigration !== expectedAdminAuditMigration)
  throw new Error(`${adminAuditMigrationPath} is stale or malformed`);

const migrations = await getMigrations(createAuth(env).options);
const expected = buildInitialMigration(await migrations.compileMigrations());
const actual = await readFile(migrationPath, "utf8");
if (expected !== actual)
  throw new Error(`${migrationPath} is stale; run pnpm generate:migration and review the generated diff`);
console.log("Baseline migrations are up to date");
