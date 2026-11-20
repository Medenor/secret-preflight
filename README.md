# secret-preflight

**A go/no-go check for leaked secrets before you commit or push.** An agent skill for [Claude Code](https://docs.claude.com/en/docs/claude-code) and Claude.

Ask *"is it safe to push?"* and Claude runs a deterministic scanner over exactly what is about to leave your machine, then answers **GO**, **HOLD** or **NO-GO**, with the one action to take first.

```markdown
## 🛫 Secret preflight — NO-GO
`push` · `my-repo` · 3 commits ahead of `origin/main` · 412 files

**1 blocker must be fixed before pushing.** 1 item to review · 37 notices.

### ⛔ Blockers
| ID | Where | What | Exposure | First action |
|---|---|---|---|---|
| C1 | `deploy.sh:2` | GitHub token `ghp_****… (40 chars)` | pushed in `a1b2c3d` | Revoke the token now |
| H1 | `keys/server.pem` | Private key file | untracked, not ignored | Add to `.gitignore` |
...
```

## Why another secret scanner?

Most agent-based scanners ask the model to grep for patterns. That has three problems this skill is built to avoid.

| Problem | What secret-preflight does |
|---|---|
| **Grep puts the raw secret into the conversation** (and into logs and transcripts) | Detection runs in `scripts/scan.py`, which masks every value before printing. The agent only sees `ghp_****… (40 chars)`. |
| **The wrong scope.** Scanning the working tree misses what actually gets pushed. | Three modes: `staged` (pre-commit), `push` (every unpushed commit, including a secret added and then deleted) and `tree` (including files committed despite `.gitignore`). |
| **"Delete the line" is the wrong fix once a secret is pushed** | The script checks remote-tracking history. Pushed secrets become **CRITICAL**, and the first action is *rotate*, not *edit*. |

Other differences:

- **Fewer false positives.** Placeholders, `${ENV}` references, variable names and field-name keys (`password_field_name`) are filtered out. PII is reported only when its checksum validates (Luhn, IBAN mod-97, Chinese ID, Belgian national number). Test, fixture and docs paths are downgraded, not hidden.
- **Honest coverage.** Every report says what was skipped, what was allowlisted, and what a GO does *not* guarantee.
- **Read-only by default.** Fixes are proposed and applied only after you approve them.
- **Tested.** `scripts/selftest.py` builds a throwaway repo with runtime-generated fake secrets and checks every mode, the masking and the false-positive filters. No literal token appears anywhere in this repo, so it passes GitHub push protection.

On Django (7,100 files) a full `tree` scan takes about 8 s and returns HOLD with 4 items to review.

## What it detects

| Category | Examples | Default severity |
|---|---|---|
| Provider tokens | AWS, GitHub, GitLab, Anthropic, OpenAI, Stripe, Slack (token and webhook), Google, Square, npm, Hugging Face, JWT | HIGH |
| Key material | `-----BEGIN … PRIVATE KEY-----` blocks, GCP service-account keys, `.pem`, `.key`, `.p12`, `.pfx`, `.jks`, `id_rsa`, … | HIGH |
| Credentials in URLs | `postgres://user:pass@host` and similar | HIGH |
| Credential files | `.env*`, `credentials.json`, `service-account*.json`, `.npmrc`, `.pypirc`, `.netrc`, `.aws/credentials`, `.docker/config.json`, `*.tfstate` | HIGH with values, LOW without |
| Generic assignments | `api_key = "…"`, `PASSWORD: …`, `client_secret => …` | MEDIUM (the agent assesses each one) |
| PII | email addresses, payment cards, IBANs, Chinese ID and mobile numbers, Belgian national numbers | LOW |

Severity is raised to **CRITICAL** when the value is found in remote-tracking history.

## Install

Requirements: Python 3.8+ and git. No dependencies.

### Claude Code: plugin (recommended)

In a Claude Code session:
```
/plugin marketplace add Medenor/secret-preflight
/plugin install secret-preflight@secret-preflight
```
On Claude Code 2.1.275 or later, one step is enough: `/plugin install secret-preflight --marketplace Medenor/secret-preflight`.

Claude Code installs only the plugin folder (manifest + skill) into its plugin cache, so nothing from this repo lands in your skills directory. The skill triggers on its own ("is it safe to push?"), or you can run it explicitly with `/secret-preflight:secret-preflight`.

### Claude Code: standalone skill

Each release carries a ZIP that holds only the skill folder:
```bash
curl -fsSL -o /tmp/secret-preflight-skill.zip \
  https://github.com/Medenor/secret-preflight/releases/latest/download/secret-preflight-skill.zip
unzip -q /tmp/secret-preflight-skill.zip -d ~/.claude/skills/ && rm /tmp/secret-preflight-skill.zip
```
To share it with a team through a project, unzip into `<project>/.claude/skills/` instead.

### Claude apps

Download `secret-preflight-skill.zip` from the [latest release](https://github.com/Medenor/secret-preflight/releases/latest) and upload it in Claude's skills settings. The `staged` and `push` modes need a git repository in Claude's environment.

## Repository layout

```
.claude-plugin/marketplace.json            marketplace catalog (this repo)
plugins/secret-preflight/                  the plugin: the only part that gets installed
├── .claude-plugin/plugin.json
└── skills/secret-preflight/
    ├── SKILL.md
    ├── scripts/scan.py                    masking scanner (JSON out)
    ├── scripts/selftest.py                self-test suite
    └── references/remediation.md          rotation and history-rewrite guide
.github/workflows/                         CI self-test + release ZIP
README.md, LICENSE, ACKNOWLEDGMENTS.md, CHANGELOG.md
```

## Use

Ask in plain language:

- "Is it safe to push?" → `push` mode
- "Check for secrets before I commit" → `staged` mode
- "Run a security check on this repo" → `tree` mode

Or run the scanner directly. It prints JSON, and its exit code fits CI and git hooks (`1` = NO-GO):
```bash
python3 <skill-dir>/scripts/scan.py --mode push --root .
```

To silence a known false positive, add `secret-preflight:ignore` to the line. Allowlisted lines are always listed in the report's Coverage section.

## Limits

- It is not a full-history auditor. For that, use [gitleaks](https://github.com/gitleaks/gitleaks) or [trufflehog](https://github.com/trufflesecurity/trufflehog). If one is installed, the skill offers to run it as a second opinion.
- The pushed check relies on your local remote-tracking refs. Run `git fetch` first for an exact answer.
- Pattern-based detection misses secrets with no recognisable shape or key name. A GO lowers the risk; it does not prove there is none.
- PII patterns cover a few locales. Add your own in `scripts/scan.py` (pattern + checksum), then run the self-test.

## Development

```bash
S=plugins/secret-preflight/skills/secret-preflight/scripts
python3 $S/selftest.py            # must print "OK"
python3 $S/scan.py --root .       # the repo must scan GO
claude plugin validate .          # marketplace + plugin manifests
```

To release, bump `version` in `plugins/secret-preflight/.claude-plugin/plugin.json`, then publish a GitHub release tagged `v<version>`. The release workflow checks that the tag matches the version, runs the self-test and attaches `secret-preflight-skill.zip`.

Pull requests are welcome. Every new pattern needs a positive and a look-alike case in `selftest.py`, built at runtime (never commit a literal token).

## Credits

Inspired by [mercury0993/secret-scanner](https://github.com/mercury0993/secret-scanner). See [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md).

## License

[MIT](LICENSE)
