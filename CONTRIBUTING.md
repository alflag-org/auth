# Contributing

Use Node.js `24.19.0` and pnpm `11.21.0`.

Install with the lockfile:

```sh
pnpm install --frozen-lockfile
```

Before opening a pull request, run the smallest relevant checks. The minimum release-oriented verification is:

```sh
pnpm audit:prod
pnpm audit:signatures
pnpm supply-chain:check
pnpm check
pnpm db:check:local
pnpm migration:check
pnpm types:check
pnpm build
pnpm deploy:preflight:negative
pnpm operator:check
pnpm oss:check
```

Use Conventional Commits. Keep changes focused and describe their user or operator impact. Do not commit secrets, `.dev.vars`, local D1 state, coverage, build output, or generated machine-local state.

For security issues, follow [SECURITY.md](SECURITY.md). Do not open a public issue.
