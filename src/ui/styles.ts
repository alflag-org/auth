export const appStyles = `
:root {
  --bg: #f5f6f7;
  --surface: #ffffff;
  --border: #d9dde2;
  --text: #1e2329;
  --muted: #68717c;
  --accent: #2457a6;
  --accent-contrast: #ffffff;
  --danger: #a43c3c;
  --danger-surface: #fff5f5;
  --success: #246b4b;
  --code: #eef1f4;
}

* { box-sizing: border-box; }

html { background: var(--bg); }

body {
  margin: 0;
  color: var(--text);
  background: var(--bg);
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  line-height: 1.5;
}

a { color: var(--accent); }

button, input, textarea { font: inherit; }

button, a { -webkit-tap-highlight-color: transparent; }

.site-header {
  border-bottom: 1px solid var(--border);
  background: var(--surface);
}

.header-inner {
  display: flex;
  align-items: center;
  gap: 1.5rem;
  max-width: 960px;
  min-height: 4rem;
  margin: 0 auto;
  padding: 0 1.25rem;
}

.brand {
  color: var(--text);
  font-weight: 700;
  text-decoration: none;
  white-space: nowrap;
}

.nav { display: flex; gap: 1rem; }

.nav a { text-decoration: none; }

.header-user {
  display: flex;
  align-items: center;
  gap: 0.8rem;
  margin-left: auto;
  font-size: 0.9rem;
}

.page {
  width: min(100% - 2.5rem, 960px);
  margin: 0 auto;
  padding: 3rem 0 5rem;
}

.page-narrow { width: min(100% - 2.5rem, 420px); }

.stack { display: flex; flex-direction: column; gap: 1rem; }

.stack-tight { gap: 0.5rem; }

.card {
  padding: 1.5rem;
  border: 1px solid var(--border);
  border-radius: 0.5rem;
  background: var(--surface);
  box-shadow: 0 1px 2px rgb(30 35 41 / 4%);
}

.card h1, .card h2, .card h3, .page > h1, .page > h2 { margin-top: 0; }

.login-card { margin-top: 4rem; text-align: center; }

.login-card .stack { align-items: stretch; }

.muted { color: var(--muted); }

.small { font-size: 0.875rem; }

.code, code {
  padding: 0.15rem 0.35rem;
  border-radius: 0.25rem;
  background: var(--code);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.9em;
  overflow-wrap: anywhere;
}

.button, .button-danger, .button-secondary {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 2.5rem;
  padding: 0.55rem 0.9rem;
  border: 1px solid var(--accent);
  border-radius: 0.35rem;
  background: var(--accent);
  color: var(--accent-contrast);
  font-weight: 600;
  text-decoration: none;
  cursor: pointer;
}

.button:hover, .button-danger:hover, .button-secondary:hover { filter: brightness(0.96); }

.button-secondary { border-color: var(--border); background: var(--surface); color: var(--text); }

.button-danger { border-color: var(--danger); background: var(--danger); }

.button-link {
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--accent);
  text-decoration: underline;
  cursor: pointer;
}

.actions { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: center; }

.inline-form { display: inline; }

.field { display: flex; flex-direction: column; gap: 0.35rem; }

.field label, .field legend { font-weight: 600; }

.field input[type="text"], .field textarea {
  width: 100%;
  padding: 0.65rem 0.7rem;
  border: 1px solid var(--border);
  border-radius: 0.35rem;
  background: var(--surface);
  color: var(--text);
}

.field textarea { min-height: 7rem; resize: vertical; }

.field input:focus, .field textarea:focus, button:focus-visible, a:focus-visible {
  outline: 3px solid rgb(36 87 166 / 25%);
  outline-offset: 2px;
}

.checkbox { display: flex; gap: 0.6rem; align-items: flex-start; }

.checkbox input { margin-top: 0.3rem; }

.notice { padding: 0.8rem 1rem; border: 1px solid var(--border); border-radius: 0.35rem; background: var(--surface); }

.notice-error { border-color: #e1a5a5; background: var(--danger-surface); color: #7c2929; }

.notice-success { border-color: #9cc7b0; background: #f2fbf5; color: var(--success); }

.definition-list { display: grid; grid-template-columns: minmax(8rem, 0.35fr) 1fr; gap: 0.7rem 1rem; margin: 0; }

.definition-list dt { color: var(--muted); }

.definition-list dd { margin: 0; overflow-wrap: anywhere; }

.uri-list { margin: 0; padding-left: 1.25rem; }

.uri-list li + li { margin-top: 0.4rem; }

.section-heading { display: flex; justify-content: space-between; gap: 1rem; align-items: baseline; }

.section-heading h1, .section-heading h2 { margin: 0; }

.client-list { display: grid; gap: 0.75rem; }

.client-item { display: block; padding: 1.1rem 1.25rem; border: 1px solid var(--border); border-radius: 0.45rem; background: var(--surface); color: var(--text); text-decoration: none; }

.client-item:hover { border-color: var(--accent); }

.client-item-header { display: flex; justify-content: space-between; gap: 1rem; }

.client-name { font-weight: 700; }

.status { font-size: 0.85rem; font-weight: 600; }

.status-active { color: var(--success); }

.status-disabled { color: var(--danger); }

.meta-row { display: flex; flex-wrap: wrap; gap: 0.75rem 1.25rem; margin-top: 0.35rem; font-size: 0.9rem; }

.audit-list { margin: 0; padding: 0; list-style: none; }

.audit-list li { display: flex; justify-content: space-between; gap: 1rem; padding: 0.75rem 0; border-top: 1px solid var(--border); }

.audit-list li:first-child { border-top: 0; }

.audit-action { font-weight: 600; }

.danger-zone { border-color: #e1a5a5; }

.danger-zone h2 { color: var(--danger); }

.secret-box { padding: 1rem; border: 1px solid #9cc7b0; border-radius: 0.35rem; background: #f2fbf5; }

.secret-value { display: block; margin-top: 0.4rem; padding: 0.75rem; background: var(--surface); font-size: 1rem; user-select: all; }

@media (max-width: 640px) {
  .header-inner { flex-wrap: wrap; padding-top: 0.8rem; padding-bottom: 0.8rem; }
  .header-user { width: 100%; margin-left: 0; }
  .page { padding-top: 1.5rem; }
  .section-heading, .client-item-header, .audit-list li { align-items: flex-start; flex-direction: column; }
  .definition-list { grid-template-columns: 1fr; gap: 0.2rem; }
  .definition-list dd { margin-bottom: 0.7rem; }
}
`;
