---
name: secret-preflight
description: Go/no-go check for leaked secrets, private keys, credential files and PII before a commit, push or PR. Use for 'is it safe to push', 'check for secrets', 'security check', or repo audits.
---

# Secret Preflight

A go/no-go check before code leaves the machine. It answers one question — **can this be committed or pushed as is?** — and, when the answer is no, says exactly what to do first.

Detection is done by `scripts/scan.py` (Python 3.8+, standard library only). The script masks every value before printing, so raw secrets never enter the conversation. You handle scope, triage, the report and the fixes.

## Ground rules

1. **Detection goes through the script only.** Never grep, cat or Read files to look for secrets: that would pull raw values into the conversation. If the script cannot run, report the error and stop.
2. **Never print, echo or reconstruct a secret.** Quote only the script's `masked` and `masked_line` fields.
3. **Look, don't touch.** No edits to files, `.gitignore`, the index or history until the user approves a specific fix.
4. **No live testing.** Never call a provider API to check whether a key works. Never install tools without asking.

## 1 · Choose the check

| The user says… | Mode | Scope |
|---|---|---|
| "before I commit" | `staged` | lines added in the index |
| "before I push", "before a PR" | `push` | lines added by every commit not yet on the remote, including secrets added and later deleted |
| "scan the repo", "security check", "audit" | `tree` (default) | tracked + untracked-not-ignored files, including files committed despite `.gitignore` |

Full-history audits are out of scope for the script: recommend gitleaks or trufflehog for those.

## 2 · Run it

```bash
python3 <skill-dir>/scripts/scan.py --mode <mode> --root <repo>
```

JSON on stdout. Exit `1` = NO-GO, `0` = GO or HOLD, `2` = error (relay the `error` field).

If `scanners_available` lists gitleaks, trufflehog or detect-secrets, offer to run it as a second opinion, always in redacted mode, and merge by file:line.

## 3 · Triage

Already done by the script — do not redo it:
- placeholders, env/variable references, field-name keys and plain identifiers are dropped;
- PII is kept only when its checksum validates (Luhn, IBAN mod-97, Chinese ID, Belgian national number);
- test, fixture, example and docs paths are downgraded one level (`downgraded`);
- secrets also present in remote-tracking history become CRITICAL (`pushed_in`, `exposure: "pushed"`);
- lines carrying `secret-preflight:ignore` are skipped and listed in `allowlisted_lines`.

Your part — assess every MEDIUM generic finding (`Possible secret (generic assignment)`) from `key`, `masked_line` and `value_profile`, and label it:
- **Likely real** — random-looking (`looks_random`), mixed character classes with digits, or a credential-style key (`*_SECRET`, `*_TOKEN`, `PASSWORD`) in config, CI or deploy files.
- **Likely benign** — documentation sample, doctest, throwaway CI service password, value that reads as a word.

Never drop a finding. A benign label stays in the report with its one-line reason.

## 4 · Report

Lead with the verdict. Use Markdown tables; omit any empty section.

```markdown
## 🛫 Secret preflight — NO-GO
`push` · `my-repo` · 3 commits ahead of `origin/main` · 412 files

**1 blocker must be fixed before pushing.** 1 item to review · 37 notices.

### ⛔ Blockers
| ID | Where | What | Exposure | First action |
|---|---|---|---|---|
| C1 | `deploy.sh:2` | GitHub token `ghp_****… (40 chars)` | pushed in `a1b2c3d` | Revoke the token now |
| H1 | `keys/server.pem` | Private key file | untracked, not ignored | Add to `.gitignore` |

### 🔍 To review
| ID | Where | What | Assessment |
|---|---|---|---|
| M1 | `config.json:15` | `apiKey` = `**** (32 chars)` | Likely real: 32 random chars |

### ℹ️ Notices
- 31 email addresses in `data/users.csv`, 6 in `docs/`: confirm they may be public.

### Coverage
- Skipped: 12 binary, 3 lockfiles · Allowlisted: 1 line (`tests/fixtures.py:8`)
- Pushed check based on local remote refs; run `git fetch` for an exact answer.
- History before the push range was not audited.

**Next step:** revoke the GitHub token in C1, then I'll walk you through the rest.
```

Rules for the report:
- **Verdict line**: `GO` ✅ / `HOLD` ⚠️ / `NO-GO` ⛔, taken from the script's `verdict`. If you judge every MEDIUM benign, keep the script's verdict and add one line saying so.
- **Blockers** = CRITICAL + HIGH. **To review** = MEDIUM. **Notices** = LOW, summarised in one bullet per type (use `low_findings_grouped` when present and offer a line-level rerun with `--root <sub-folder>`).
- **Exposure** comes from the `exposure` field: `pushed` (with `pushed_in`), `local-commit`, `staged`, `tracked`, `tracked-but-ignored`, `untracked-not-ignored`. Say plainly when a file is tracked despite `.gitignore`.
- **Coverage** is mandatory: skipped files, allowlisted lines, the script's `notes`, a missing `.gitignore`, and what this mode does not cover. It tells the user what GO does *not* guarantee.
- **Next step** is one sentence: the single most urgent action.
- A clean result is four lines: verdict heading, scope line, `No secrets, sensitive files or PII found.`, and Coverage.

## 5 · Fix (only after approval)

Order of operations:
1. **Pushed (CRITICAL)** → revoke or rotate the credential. Rewriting history does not un-leak it.
2. **In a local commit** → remove it and rewrite the commit that introduced it (amend or interactive rebase). A follow-up "remove secret" commit still pushes the secret.
3. **Hardcoded in a file** → environment variable or secrets manager; add the empty key to `.env.example`.
4. **Sensitive file** → tracked: `git rm --cached <file>` + `.gitignore`; untracked: `.gitignore`.
5. **PII** → ask whether the data is meant to be public; suggest anonymised fixtures.

Read `references/remediation.md` for rotation locations and history-rewrite commands, only when a fix is needed. After the fixes, run the same mode again and show the new verdict.

## Maintenance

After any change to a pattern or filter, run `python3 <skill-dir>/scripts/selftest.py`. It builds a throwaway repo with runtime-generated fake secrets and checks every mode, the masking and the false-positive filters.
