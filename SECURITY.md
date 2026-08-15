# Security policy

Security fixes target the current default branch; older snapshots are unsupported.

If this private repository is made public, immediately enable GitHub Private Vulnerability Reporting after public visibility and before announcing or distributing the repository. Once enabled, use GitHub’s “Report a vulnerability” flow. Do not disclose vulnerabilities in public issues. Do not include secrets, production credentials, or live-service probing in a report.

## Dependency advisory exception

The only explicit audit exception is `GHSA-p2fr-6hmx-4528` for the pinned stable `@better-auth/oauth-provider` `1.6.28`. The application rejects query, form-body, encoded, and duplicate `resource` parameters before the dependency handles authorization or token requests, so the affected path is unreachable in this application.

When an upstream stable release fixes the advisory, update the exact `@better-auth/oauth-provider` pin to the first stable fixed release, then remove only the `pnpm audit` allowlist entry. The exception is not a general audit ignore.
