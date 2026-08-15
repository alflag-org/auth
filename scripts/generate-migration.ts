import { writeFile } from "node:fs/promises";
import { getMigrations } from "better-auth/db/migration";
import { createAuth, type AuthEnvironment } from "../src/auth";
import { buildInitialMigration } from "./initial-migration";

const fakePreparedStatement: D1PreparedStatement = {
  bind: (..._values: unknown[]) => fakePreparedStatement,
  first: async (_column?: string) => {
    throw new Error("schema generation must not query D1");
  },
  run: async () => {
    throw new Error("schema generation must not query D1");
  },
  all: async <T = Record<string, unknown>>(): Promise<D1Result<T>> => ({
    success: true,
    meta: {
      duration: 0,
      size_after: 0,
      rows_read: 0,
      rows_written: 0,
      last_row_id: 0,
      changed_db: false,
      changes: 0,
    },
    results: [],
  }),
  raw: async (_options?: { columnNames?: boolean }) => {
    throw new Error("schema generation must not query D1");
  },
};

const fakeD1: D1Database = {
  prepare: (_query: string) => fakePreparedStatement,
  batch: async (_statements: D1PreparedStatement[]) => {
    throw new Error("schema generation must not query D1");
  },
  exec: async (_query: string) => {
    throw new Error("schema generation must not query D1");
  },
  withSession: () => {
    throw new Error("schema generation must not query D1");
  },
  dump: async () => {
    throw new Error("schema generation must not query D1");
  },
};

const env = {
  DB: fakeD1,
  BETTER_AUTH_SECRETS: "1:schema-generation-only-marker-1234567890abcdef",
  GOOGLE_CLIENT_ID: "schema-generation-client",
  GOOGLE_CLIENT_SECRET: "schema-generation-secret-00000000000000000000000000000000",
  ALLOWED_GOOGLE_DOMAIN: "example.com",
  AUTH_ISSUER: "https://auth.example.invalid",
} satisfies AuthEnvironment;

const auth = createAuth(env);
const migrations = await getMigrations(auth.options);
await writeFile("migrations/0001_initial.sql", buildInitialMigration(await migrations.compileMigrations()), "utf8");
