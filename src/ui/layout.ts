export type UIUser = {
  id: string;
  name: string;
  email: string;
};

export type LayoutOptions = {
  title: string;
  content: string;
  brand?: string;
  user?: UIUser;
  navigation?: boolean;
  csrfToken?: string;
  narrow?: boolean;
};

export function escapeHTML(value: string | number | boolean | null | undefined): string {
  return String(value ?? "").replace(/[&<>"']/gu, (character) => {
    switch (character) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      default:
        return "&#39;";
    }
  });
}

function signOutForm(csrfToken: string | undefined): string {
  const token = csrfToken ? `<input type="hidden" name="csrf_token" value="${escapeHTML(csrfToken)}">` : "";
  return `<form method="post" action="/sign-out" class="inline-form">${token}<button class="button-link" type="submit">Sign out</button></form>`;
}

function header(options: LayoutOptions, brand: string): string {
  const navigation = options.navigation
    ? `<nav class="nav" aria-label="Primary"><a href="/admin">Overview</a><a href="/admin/clients">Clients</a></nav>`
    : "";
  const signedIn = options.user
    ? `<div class="header-user"><span class="muted">${escapeHTML(options.user.email)}</span>${signOutForm(options.csrfToken)}</div>`
    : "";
  return `<header class="site-header"><div class="header-inner"><a class="brand" href="/">${escapeHTML(brand)}</a>${navigation}${signedIn}</div></header>`;
}

export function layout(options: LayoutOptions): string {
  const brand = options.brand ?? "Auth";
  const pageClass = options.narrow ? "page page-narrow" : "page";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer"><title>${escapeHTML(options.title)} · ${escapeHTML(brand)}</title><link rel="stylesheet" href="/assets/app.css"></head><body>${header(options, brand)}<main class="${pageClass}">${options.content}</main></body></html>`;
}
