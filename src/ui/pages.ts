import { escapeHTML, layout, type UIUser } from "./layout";

export type ClientView = {
  client_id: string;
  client_name?: string | undefined;
  scope?: string | undefined;
  redirect_uris: string[];
  post_logout_redirect_uris?: string[] | undefined;
  disabled?: boolean | undefined;
  require_pkce?: boolean | undefined;
  enable_end_session?: boolean | undefined;
  token_endpoint_auth_method?: string | undefined;
  grant_types?: string[] | undefined;
  response_types?: string[] | undefined;
  type?: string | undefined;
  skip_consent?: boolean | undefined;
};

export type AuditView = {
  action: string;
  targetName: string;
  detail: string;
  createdAt: string;
};

export type PageBrand = {
  name: string;
  workspaceLabel: string;
};

function csrfInput(csrfToken: string): string {
  return `<input type="hidden" name="csrf_token" value="${escapeHTML(csrfToken)}">`;
}

function clientName(client: ClientView): string {
  return client.client_name?.trim() || "Unnamed client";
}

function clientPath(clientId: string, suffix = ""): string {
  return `/admin/clients/${encodeURIComponent(clientId)}${suffix}`;
}

function uriList(values: string[] | undefined): string {
  if (!values || values.length === 0) return `<span class="muted">—</span>`;
  return `<ul class="uri-list">${values.map((value) => `<li><code>${escapeHTML(value)}</code></li>`).join("")}</ul>`;
}

function formValue(values: string[] | undefined): string {
  return escapeHTML(values?.join("\n") ?? "");
}

export function signInPage(options: { brand: PageBrand; googleHref: string; error: boolean }): string {
  const error = options.error
    ? `<div class="notice notice-error" role="alert"><strong>Authentication failed</strong><br>Unable to complete the authentication request.</div>`
    : "";
  return layout({
    title: "Sign in",
    brand: options.brand.name,
    narrow: true,
    content: `<section class="card login-card"><div class="stack"><p class="muted">${escapeHTML(options.brand.name)}</p><h1>Sign in to continue</h1>${error}<a class="button" href="${escapeHTML(options.googleHref)}">Continue with Google</a><p class="muted small">${escapeHTML(options.brand.workspaceLabel)}</p></div></section>`,
  });
}

export function accountPage(user: UIUser, brand: PageBrand, csrfToken: string): string {
  return layout({
    title: "Account",
    brand: brand.name,
    user,
    csrfToken,
    content: `<div class="stack"><div class="section-heading"><h1>Account</h1></div><section class="card"><dl class="definition-list"><dt>Name</dt><dd>${escapeHTML(user.name)}</dd><dt>Email</dt><dd>${escapeHTML(user.email)}</dd><dt>User ID</dt><dd><code>${escapeHTML(user.id)}</code></dd><dt>Provider</dt><dd>Google Workspace</dd></dl></section><div class="actions"><form method="post" action="/sign-out">${csrfInput(csrfToken)}<button class="button" type="submit">Sign out</button></form></div></div>`,
  });
}

export function signOutPage(options: { brand: PageBrand; csrfToken?: string | undefined }): string {
  const token = options.csrfToken ? csrfInput(options.csrfToken) : "";
  return layout({
    title: "Sign out",
    brand: options.brand.name,
    narrow: true,
    content: `<section class="card stack"><h1>Sign out</h1><form method="post" action="/sign-out" class="stack">${token}<button class="button" type="submit">Sign out</button></form></section>`,
  });
}

export function adminOverviewPage(options: {
  user: UIUser;
  brand: PageBrand;
  csrfToken: string;
  issuer: string;
  clientCount: number;
  audits: AuditView[];
}): string {
  const audits =
    options.audits.length === 0
      ? `<p class="muted">No changes recorded.</p>`
      : `<ul class="audit-list">${options.audits
          .map(
            (audit) =>
              `<li><span><span class="audit-action">${escapeHTML(audit.action)}</span><br><span class="muted">${escapeHTML(audit.targetName)}${audit.detail ? ` · ${escapeHTML(audit.detail)}` : ""}</span></span><time class="muted small">${escapeHTML(audit.createdAt)}</time></li>`,
          )
          .join("")}</ul>`;
  return layout({
    title: "Overview",
    brand: options.brand.name,
    user: options.user,
    navigation: true,
    csrfToken: options.csrfToken,
    content: `<div class="stack"><div class="section-heading"><h1>Overview</h1></div><section class="card stack"><div><h2>OIDC Provider</h2><p><code>${escapeHTML(options.issuer)}</code></p><p class="status status-active">Operational</p></div><div><h2>Clients</h2><p>${escapeHTML(options.clientCount)} registered</p></div><div><h2>Signed in as</h2><p>${escapeHTML(options.user.email)}</p></div></section><section class="card"><h2>Recent changes</h2>${audits}</section></div>`,
  });
}

export function clientListPage(options: {
  user: UIUser;
  brand: PageBrand;
  csrfToken: string;
  clients: ClientView[];
  notice?: string | undefined;
}): string {
  const clients =
    options.clients.length === 0
      ? `<section class="card"><p class="muted">No clients registered.</p></section>`
      : `<div class="client-list">${options.clients
          .map(
            (client) =>
              `<a class="client-item" href="${escapeHTML(clientPath(client.client_id))}"><span class="client-item-header"><span class="client-name">${escapeHTML(clientName(client))}</span><span class="status ${client.disabled ? "status-disabled" : "status-active"}">${client.disabled ? "Disabled" : "Active"}</span></span><span class="meta-row"><span>client_id: <code>${escapeHTML(client.client_id)}</code></span><span>${escapeHTML(client.scope ?? "")}</span></span><span class="muted small">${escapeHTML(client.redirect_uris[0] ?? "No redirect URI")}</span></a>`,
          )
          .join("")}</div>`;
  const notice = options.notice ? `<div class="notice notice-success">${escapeHTML(options.notice)}</div>` : "";
  return layout({
    title: "Clients",
    brand: options.brand.name,
    user: options.user,
    navigation: true,
    csrfToken: options.csrfToken,
    content: `<div class="stack"><div class="section-heading"><h1>Clients</h1><a class="button" href="/admin/clients/new">New client</a></div>${notice}${clients}</div>`,
  });
}

export function clientFormPage(options: {
  brand: PageBrand;
  user: UIUser;
  csrfToken: string;
  mode: "create" | "edit";
  client?: ClientView;
  error?: string;
}): string {
  const client = options.client;
  const edit = options.mode === "edit";
  const action = edit ? clientPath(client?.client_id ?? "", "") : "/admin/clients";
  const title = edit ? "Edit client" : "New client";
  const error = options.error ? `<div class="notice notice-error" role="alert">${escapeHTML(options.error)}</div>` : "";
  const logoutChecked = client?.enable_end_session !== false;
  return layout({
    title,
    brand: options.brand.name,
    user: options.user,
    navigation: true,
    csrfToken: options.csrfToken,
    content: `<div class="stack"><div class="section-heading"><h1>${title}</h1><a href="${edit ? escapeHTML(clientPath(client?.client_id ?? "")) : "/admin/clients"}">Cancel</a></div><section class="card"><form method="post" action="${escapeHTML(action)}" class="stack">${csrfInput(options.csrfToken)}${error}<div class="field"><label for="client-name">Name</label><input id="client-name" name="client_name" type="text" maxlength="120" required value="${escapeHTML(client?.client_name ?? "")}"></div><div class="field"><label for="redirect-uris">Redirect URIs</label><span class="muted small">One URI per line. HTTPS URLs only.</span><textarea id="redirect-uris" name="redirect_uris" required>${formValue(client?.redirect_uris)}</textarea></div><div class="field"><label for="post-logout-redirect-uris">Post logout redirect URIs</label><span class="muted small">One URI per line. Leave empty when the client does not use RP-initiated logout.</span><textarea id="post-logout-redirect-uris" name="post_logout_redirect_uris">${formValue(client?.post_logout_redirect_uris)}</textarea></div><label class="checkbox"><input type="checkbox" name="require_pkce" checked disabled><span><strong>Require PKCE</strong><br><span class="muted small">Authorization Code clients use S256 PKCE.</span></span></label><label class="checkbox"><input type="checkbox" name="enable_end_session" value="true"${logoutChecked ? " checked" : ""}><span><strong>Allow RP-initiated logout</strong></span></label><div class="actions"><button class="button" type="submit">${edit ? "Save changes" : "Create client"}</button></div></form></section></div>`,
  });
}

export function clientDetailPage(options: {
  brand: PageBrand;
  user: UIUser;
  csrfToken: string;
  client: ClientView;
  notice?: string | undefined;
}): string {
  const client = options.client;
  const disabled = client.disabled === true;
  const notice = options.notice ? `<div class="notice notice-success">${escapeHTML(options.notice)}</div>` : "";
  const toggleAction = clientPath(client.client_id, disabled ? "/enable" : "/disable");
  const toggleLabel = disabled ? "Enable client" : "Disable client";
  return layout({
    title: clientName(client),
    brand: options.brand.name,
    user: options.user,
    navigation: true,
    csrfToken: options.csrfToken,
    content: `<div class="stack"><div class="section-heading"><h1>${escapeHTML(clientName(client))}</h1><a href="/admin/clients">All clients</a></div>${notice}<section class="card stack"><div class="status ${disabled ? "status-disabled" : "status-active"}">${disabled ? "Disabled" : "Active"}</div><dl class="definition-list"><dt>Client ID</dt><dd><code>${escapeHTML(client.client_id)}</code></dd><dt>Client Secret</dt><dd><span class="muted">Hidden</span> · <a href="${escapeHTML(clientPath(client.client_id, "/rotate-secret"))}">Rotate secret</a></dd><dt>Redirect URIs</dt><dd>${uriList(client.redirect_uris)}</dd><dt>Post logout URIs</dt><dd>${uriList(client.post_logout_redirect_uris)}</dd><dt>Protocol</dt><dd>Authorization Code · PKCE required · ${escapeHTML(client.scope ?? "openid profile email")} · Consent skipped · RP logout ${client.enable_end_session === false ? "disabled" : "enabled"}</dd></dl><div class="actions"><a class="button-secondary" href="${escapeHTML(clientPath(client.client_id, "/edit"))}">Edit</a><form method="post" action="${escapeHTML(toggleAction)}">${csrfInput(options.csrfToken)}<button class="button" type="submit">${toggleLabel}</button></form></div></section><section class="card danger-zone stack"><h2>Danger zone</h2><p class="muted">Delete is permanent. Disable is reversible and rejects new authorization requests.</p><div class="actions"><a class="button-danger" href="${escapeHTML(clientPath(client.client_id, "/delete"))}">Delete client</a></div></section></div>`,
  });
}

export function rotateSecretConfirmPage(options: {
  brand: PageBrand;
  user: UIUser;
  csrfToken: string;
  client: ClientView;
}): string {
  return layout({
    title: "Rotate client secret",
    brand: options.brand.name,
    user: options.user,
    navigation: true,
    csrfToken: options.csrfToken,
    content: `<div class="stack"><h1>Rotate client secret?</h1><section class="card stack"><p>${escapeHTML(clientName(options.client))}</p><p>The existing client secret will become invalid immediately.</p><div class="actions"><a class="button-secondary" href="${escapeHTML(clientPath(options.client.client_id))}">Cancel</a><form method="post" action="${escapeHTML(clientPath(options.client.client_id, "/rotate-secret"))}">${csrfInput(options.csrfToken)}<button class="button-danger" type="submit">Rotate secret</button></form></div></section></div>`,
  });
}

export function deleteConfirmPage(options: {
  brand: PageBrand;
  user: UIUser;
  csrfToken: string;
  client: ClientView;
}): string {
  return layout({
    title: "Delete client",
    brand: options.brand.name,
    user: options.user,
    navigation: true,
    csrfToken: options.csrfToken,
    content: `<div class="stack"><h1>Delete “${escapeHTML(clientName(options.client))}”?</h1><section class="card stack"><p>This operation cannot be undone.</p><p>Client ID: <code>${escapeHTML(options.client.client_id)}</code></p><div class="actions"><a class="button-secondary" href="${escapeHTML(clientPath(options.client.client_id))}">Cancel</a><form method="post" action="${escapeHTML(clientPath(options.client.client_id, "/delete"))}">${csrfInput(options.csrfToken)}<button class="button-danger" type="submit">Delete permanently</button></form></div></section></div>`,
  });
}

export function clientSecretPage(options: {
  brand: PageBrand;
  user: UIUser;
  csrfToken: string;
  client: ClientView;
  secret: string;
  action: "created" | "rotated";
}): string {
  const heading = options.action === "created" ? "Client created" : "Client secret rotated";
  return layout({
    title: heading,
    brand: options.brand.name,
    user: options.user,
    navigation: true,
    csrfToken: options.csrfToken,
    content: `<div class="stack"><h1>${heading}</h1><section class="secret-box stack"><p><strong>Client ID</strong></p><code>${escapeHTML(options.client.client_id)}</code><p><strong>Client Secret</strong></p><code class="secret-value">${escapeHTML(options.secret)}</code><p><strong>Store this value now.</strong><br>It will not be shown again.</p></section><div class="actions"><a class="button" href="${escapeHTML(clientPath(options.client.client_id))}">Continue to client</a></div></div>`,
  });
}
