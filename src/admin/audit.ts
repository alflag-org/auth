export type AdminAuditAction =
  | "client.create"
  | "client.update"
  | "client.disable"
  | "client.enable"
  | "client.rotate_secret"
  | "client.delete";

export type AdminAudit = {
  action: AdminAuditAction;
  targetName: string;
  detail: string;
  createdAt: string;
};

const auditActions = new Set<AdminAuditAction>([
  "client.create",
  "client.update",
  "client.disable",
  "client.enable",
  "client.rotate_secret",
  "client.delete",
]);

export async function recordAudit(
  database: D1Database,
  entry: {
    actorUserId: string;
    action: AdminAuditAction;
    targetId: string;
    targetName: string;
    detail?: Record<string, boolean | number | string>;
  },
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO adminAudit
       (id, actorUserId, action, targetType, targetId, targetName, detail, createdAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      crypto.randomUUID(),
      entry.actorUserId,
      entry.action,
      "oauth_client",
      entry.targetId,
      entry.targetName,
      JSON.stringify(entry.detail ?? {}),
      new Date().toISOString(),
    )
    .run();
}

export async function recentAudits(database: D1Database, limit = 10): Promise<AdminAudit[]> {
  const rows = await database
    .prepare("SELECT action, targetName, detail, createdAt FROM adminAudit ORDER BY createdAt DESC, id DESC LIMIT ?")
    .bind(limit)
    .all<{ action: string; targetName: string; detail: string; createdAt: string }>();
  return rows.results.map((row) => {
    let detail = "";
    try {
      const parsed: unknown = JSON.parse(row.detail);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        detail = Object.entries(parsed as Record<string, unknown>)
          .filter(([, value]) => typeof value === "string" || typeof value === "number" || typeof value === "boolean")
          .map(([key, value]) => `${key}: ${String(value)}`)
          .join(", ");
      }
    } catch {
      detail = "";
    }
    const action = auditActions.has(row.action as AdminAuditAction)
      ? (row.action as AdminAuditAction)
      : "client.update";
    return { action, targetName: row.targetName, detail, createdAt: row.createdAt };
  });
}
