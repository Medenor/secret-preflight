# Remediation reference

Read this only when a preflight finding needs fixing. Propose a step, wait for approval, then act.

## 1. Rotate first, always

When a secret has been pushed, treat it as compromised, even if the repo is private and even if history is rewritten afterwards. Clones, forks, CI logs and caches may already hold it.

Where to revoke or rotate (menus change, so confirm in the provider's UI):

| Provider | Where |
|---|---|
| GitHub token | Settings → Developer settings → Personal access tokens (or the GitHub App / OAuth app settings) |
| GitLab token | User settings → Access tokens (or project/group access tokens) |
| AWS access key | IAM console → user → Security credentials → deactivate, then delete; review CloudTrail for use |
| Anthropic API key | Anthropic Console → API keys |
| OpenAI API key | OpenAI platform → API keys |
| Google API key / service account | Google Cloud console → APIs & Services → Credentials; IAM → Service accounts → Keys |
| Stripe live key | Dashboard → Developers → API keys → roll key |
| Slack token / webhook | App configuration → OAuth & Permissions (rotate) / Incoming Webhooks (remove and recreate) |
| npm token | npmjs.com → Access Tokens |
| Hugging Face token | Settings → Access Tokens |
| Database password in a URL | change the password on the database server, then update every consumer |
| Private key | generate a new key pair, replace the public key wherever it is trusted, revoke certificates issued for the old key |

Then check the provider's access logs for use between the leak and the rotation.

## 2. Remove from commits that are not pushed yet

The secret is in the last commit:
```bash
# edit the file to remove the value, then
git add <file>
git commit --amend --no-edit
```

The secret is in an older unpushed commit:
```bash
git rebase -i <commit-before-the-leak>
# mark the commit as "edit", fix the file, then:
git add <file> && git commit --amend --no-edit && git rebase --continue
```

A sensitive file was committed by mistake:
```bash
git rm --cached <file>
echo "<file>" >> .gitignore
git add .gitignore
git commit --amend --no-edit   # or fix it in the commit that added it, via rebase -i
```

Run the preflight again in `push` mode: the finding must disappear from every unpushed commit.

## 3. Rewrite pushed history (optional, after rotation)

Rewriting history only cleans the repository. It does not make a leaked credential safe again. Before you rewrite, coordinate with everyone who has a clone, because it needs a force push and they will all have to re-clone or reset.

With [git-filter-repo](https://github.com/newren/git-filter-repo) (works on a fresh mirror clone):
```bash
git clone --mirror <url> repo.git && cd repo.git
# remove a file from all history
git filter-repo --invert-paths --path <file>
# or replace a value everywhere (one literal per line in expressions.txt; the value never goes on the command line)
git filter-repo --replace-text expressions.txt
git push --force --mirror
rm expressions.txt   # it contains the secret
```

On GitHub, cached views, forks and pull-request refs may still show the old commits. Contact GitHub Support to purge them if needed.

## 4. Prevent recurrence

- Keep secrets in environment variables or a secrets manager. Commit a `.env.example` that lists the key names with empty values.
- Add `.env*` (with `!.env.example`), `*.pem`, `*.key` and `*.tfstate` to `.gitignore`.
- Enable your host's secret scanning and push protection where available.
- Run the preflight in `staged` mode before commits and in `push` mode before pushes.
