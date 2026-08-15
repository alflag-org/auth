# Contributing

Use [mise](https://mise.jdx.dev/) for Node.js `24.19.0` and pnpm `11.21.0`.

Set up a checkout with the committed toolchain lockfile:

```sh
mise trust
mise install --locked node@24.19.0 npm:pnpm@11.21.0
mise run bootstrap
mise run migrate-local
```

Before opening a pull request, run the smallest relevant checks. The minimum release-oriented verification is:

```sh
mise run audit-prod
mise run audit-signatures
mise run supply-chain-check
mise run check
mise run db-check-local
mise run migration-check
mise run types-check
mise run build
mise run deploy-preflight-negative
mise run operator-check
mise run oss-check
```

For a package script without a mise task, run it through the pinned environment with `mise exec -- pnpm <script>`.

Use Conventional Commits. Keep changes focused and describe their user or operator impact. Do not commit secrets, `.dev.vars`, local D1 state, coverage, build output, or generated machine-local state.

For security issues, follow [SECURITY.md](SECURITY.md). Do not open a public issue.
