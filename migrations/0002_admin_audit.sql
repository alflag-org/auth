create table "adminAudit" (
  "id" text not null primary key,
  "actorUserId" text not null,
  "action" text not null,
  "targetType" text not null,
  "targetId" text not null,
  "targetName" text not null,
  "detail" text not null,
  "createdAt" date not null
);

create index "adminAudit_createdAt_idx" on "adminAudit" ("createdAt");
