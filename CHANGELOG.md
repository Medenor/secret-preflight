# Changelog

## 1.0.0 — 2026-11-20

First release.

- `scripts/scan.py`: masking scanner with `staged`, `push` and `tree` modes, provider and generic secret patterns, credential files, checksum-validated PII, test/docs downgrading, a pushed-history check (CRITICAL), an inline allowlist marker (`secret-preflight:ignore`), grouping of LOW findings, and a JSON report with NO-GO exit code.
- `scripts/selftest.py`: throwaway-repo test suite with runtime-generated fake secrets.
- `SKILL.md`: go/no-go workflow and verdict-first report.
- `references/remediation.md`: rotation, commit cleanup and history rewrite.
- Distribution: Claude Code plugin marketplace (`/plugin install secret-preflight@secret-preflight`), with only the plugin folder installed; skill-only ZIP attached to each release by CI.
