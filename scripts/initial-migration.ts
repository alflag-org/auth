const PROJECT_TABLE =
  'create table "oauthAuthorizationAdmission" ("id" text not null primary key, "sourceKey" text not null, "clientId" text not null, "expiresAt" date not null, "createdAt" date not null, "continuationDigest" text, "continuationStateId" text, "consumedAt" date);';

const PROJECT_INDEXES = [
  'create index "verification_expiresAt_idx" on "verification" ("expiresAt");',
  'create index "verification_identifier_expiresAt_idx" on "verification" ("identifier", "expiresAt");',
  'create index "verification_google_state_source_idx" on "verification" ("identifier", "googleSourceKey");',
  'create index "verification_google_state_client_idx" on "verification" ("identifier", "googleClientId");',
  'create index "oauthAuthorizationAdmission_expiresAt_idx" on "oauthAuthorizationAdmission" ("expiresAt");',
  'create index "oauthAuthorizationAdmission_sourceKey_expiresAt_idx" on "oauthAuthorizationAdmission" ("sourceKey", "expiresAt");',
  'create index "oauthAuthorizationAdmission_clientId_expiresAt_idx" on "oauthAuthorizationAdmission" ("clientId", "expiresAt");',
  'create index "oauthAuthorizationAdmission_continuation_idx" on "oauthAuthorizationAdmission" ("continuationDigest", "clientId", "continuationStateId", "expiresAt");',
  'create index "oauthAccessToken_expiresAt_idx" on "oauthAccessToken" ("expiresAt");',
  'create index "session_expiresAt_idx" on "session" ("expiresAt");',
  'create index "jwks_expiresAt_idx" on "jwks" ("expiresAt");',
].join("\n\n");

function addColumns(sql: string, table: string, columns: readonly string[]): string {
  const prefix = `create table "${table}" (`;
  const start = sql.indexOf(prefix);
  if (start < 0) throw new Error(`Better Auth migration is missing the ${table} table`);
  const end = sql.indexOf(");", start);
  if (end < 0) throw new Error(`Better Auth migration has an incomplete ${table} table`);
  const statement = sql.slice(start, end);
  for (const column of columns) {
    const name = column.slice(0, column.indexOf(" "));
    if (statement.includes(name)) throw new Error(`Better Auth migration already defines ${table}.${name}`);
  }
  return `${sql.slice(0, end)}, ${columns.join(", ")}${sql.slice(end)}`;
}

export function buildInitialMigration(betterAuthMigration: string): string {
  let sql = betterAuthMigration.trim();
  sql = addColumns(sql, "verification", [
    '"googleSourceKey" text',
    '"googleClientId" text',
    '"googleAdmissionId" text',
  ]);
  sql = addColumns(sql, "jwks", ['"revokedAt" date']);
  if (sql.includes('create table "oauthAuthorizationAdmission"'))
    throw new Error("Better Auth migration already defines oauthAuthorizationAdmission");

  const firstIndex = sql.indexOf('\ncreate index "');
  if (firstIndex < 0) throw new Error("Better Auth migration has no index boundary");
  sql = `${sql.slice(0, firstIndex).trimEnd()}\n\n${PROJECT_TABLE}\n\n${sql.slice(firstIndex).trimStart()}`;
  return `${sql}\n\n${PROJECT_INDEXES}\n`;
}
