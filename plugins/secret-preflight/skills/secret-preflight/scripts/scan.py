#!/usr/bin/env python3
"""
secret-preflight / scan.py

Scan the content a git repository is about to commit or push for secrets,
sensitive files and PII, and print a JSON report on stdout.

Raw secret values are NEVER printed. Every value is masked inside this script,
so the caller only ever sees public prefixes, lengths and masked lines.

Usage:
  scan.py [--mode tree|staged|push] [--root PATH] [--no-pushed-check]

Modes:
  tree    (default) tracked + untracked-not-ignored files in the working tree
  staged  lines added in the index (pre-commit)
  push    lines added by every commit not yet on the remote (pre-push)

Exit codes: 0 = GO or HOLD, 1 = NO-GO, 2 = usage or runtime error.
Standard library only, Python 3.8+.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import math
import os
import re
import shutil
import subprocess
import sys
from collections import Counter

MAX_BYTES = 1_000_000
MAX_PER_FILE_TYPE = 20
MAX_PICKAXE = 25
MASKED_LINE_MAX = 200
LOW_DETAIL_MAX = 50   # above this, LOW findings are grouped per file/type

SKIP_DIRS = {"node_modules", ".git", "dist", "build", "vendor", ".venv", "venv",
             "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".next", "target"}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
              "Cargo.lock", "composer.lock", "Gemfile.lock", "go.sum", "uv.lock"}
SKIP_SUFFIXES = (".min.js", ".min.css", ".lock", ".map")

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
DOCS_PATH = re.compile(r"(?i)(^|/)docs?/")
DOWNGRADE = {"HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW", "CRITICAL": "CRITICAL"}

TEST_PATH = re.compile(
    r"(?i)(^|[/._-])(tests?|specs?|__tests__|testdata|fixtures?|mocks?|examples?|samples?)([/._-]|$)")

# ---------------------------------------------------------------- patterns --

def _p(name, rx, prefix=None, pickaxe=True):
    return (name, re.compile(rx), re.compile(prefix) if prefix else None, pickaxe)

# Order matters: on overlapping matches the first pattern wins.
PROVIDERS = [
    _p("GCP service-account key", r'"private_key"\s*:\s*"-----BEGIN', pickaxe=False),
    _p("Private key block", r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----", pickaxe=False),
    _p("AWS access key ID", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", r"AKIA|ASIA"),
    _p("GitHub fine-grained PAT", r"\bgithub_pat_[A-Za-z0-9_]{82}", r"github_pat_"),
    _p("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}", r"gh[pousr]_"),
    _p("GitLab PAT", r"\bglpat-[A-Za-z0-9_-]{20,}", r"glpat-"),
    _p("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{32,}", r"sk-ant-"),
    _p("OpenAI API key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}",
       r"sk-(?:proj-|svcacct-|admin-)?"),
    _p("Stripe live key", r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}", r"(?:sk|rk)_live_"),
    _p("Slack webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+",
       r"https://hooks\.slack\.com/services/"),
    _p("Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}", r"xox[abposr]-"),
    _p("Google API key", r"\bAIza[0-9A-Za-z_-]{35}", r"AIza"),
    _p("Square access token", r"\bsq0atp-[0-9A-Za-z_-]{22}", r"sq0atp-"),
    _p("npm token", r"\bnpm_[A-Za-z0-9]{36}\b", r"npm_"),
    _p("Hugging Face token", r"\bhf_[A-Za-z0-9]{34,}", r"hf_"),
    _p("JWT", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", r"eyJ"),
]

URL_CRED = re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.-]*)://([^\s:/@'\"]+):([^\s@/'\"]{3,})@([^\s'\"/:]+)")

GENERIC = re.compile(
    r"(?i)([a-z0-9_.-]*(?:api[_-]?key|secret|token|password|passwd|pwd|credential|"
    r"private[_-]?key|access[_-]?key|auth(?!or))[a-z0-9_.-]*)[\"']?\s*(?::=|=>|:|=(?!=))\s*[\"']?"
    r"([^\s\"'#,;<>`]{8,})")

CRED_KEY = re.compile(
    r"(?i)[\"']?([^\s=:\"'#]*(?:secret|token|password|passwd|pwd|credential|auth(?!or)|"
    r"api[_-]?key|private[_-]?key|access[_-]?key)[^\s=:\"'#]*)[\"']?\s*[=:]\s*[\"']?([^\"'\s#][^\"'#]*)")
NETRC_PW = re.compile(r"\bpassword\s+(\S+)")

PLACEHOLDER = re.compile(
    r"(?i)(example|changeme|change_me|placeholder|dummy|sample|your[_-]|replace|redacted|"
    r"xxx|<[^>]*>|\*{3,}|todo|fixme|insert|notreal|not_real)")
COMMON_WORDS = {"password", "secret", "null", "none", "nil", "undefined", "true", "false",
                "required", "optional", "string", "notset", "empty", "token", "pass",
                "postgres", "root", "admin", "mysql", "guest", "default"}
# Key names that hold a *name* or *setting* about a secret, not the secret itself.
KEY_META = re.compile(r"(?i)(name|field|label|_id|url|uri|type|prefix|suffix|header|param|attr|"
                      r"path|file|length|len|count|policy|pattern|regex|format|mode|hint|"
                      r"validators?|class|endpoint|__)$")
LOWER_IDENT = re.compile(r"^_?[a-z][a-z_/-]*[_/-][a-z_/-]*$")   # words: go/no-go, set-password
INDIRECT = re.compile(r"(^\$|\$\{|process\.env|os\.environ|getenv|ENV\[|secrets\.|vault:|"
                      r"[()\[\]{}]|%\()")
DOTTED = re.compile(r"^[A-Za-z_]\w*(\.[A-Za-z_]\w*)+$")
IDENT = re.compile(r"^[A-Za-z_]\w*$")
ENV_NAME = re.compile(r"^[A-Z][A-Z0-9]*_[A-Z0-9_]+$")
CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".java", ".kt",
            ".rb", ".php", ".cs", ".rs", ".swift", ".scala", ".c", ".cc", ".cpp", ".h",
            ".hpp", ".m", ".dart", ".lua", ".r", ".vue", ".svelte"}

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")
CNID = re.compile(r"\b\d{17}[\dXx]\b")
BENN = re.compile(r"\b\d{2}\.?\d{2}\.?\d{2}-?\d{3}\.?\d{2}\b")
CARD = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")
CNMOB = re.compile(r"\b1[3-9]\d{9}\b")

EMAIL_SKIP_EXT = (".po", ".pot")   # translator credits
EMAIL_SKIP_FILES = {"package.json", "LICENSE", "LICENSE.md", "LICENSE.txt", "CODEOWNERS",
                    "AUTHORS", "AUTHORS.md", ".mailmap", "CONTRIBUTORS", "pyproject.toml",
                    "setup.py", "setup.cfg", "Cargo.toml", "composer.json"}
EMAIL_SKIP_LOCAL = {"noreply", "no-reply", "donotreply", "do-not-reply", "git"}
EMAIL_SKIP_TLD = {"png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "css", "js", "ts",
                  "local", "localhost", "test", "invalid", "example"}

ALLOW_MARKER = "secret-preflight" + ":ignore"
# Cheap pre-filters: skip a regex family when the line cannot possibly match.
PROVIDER_HINTS = ("AKIA", "ASIA", "_pat_", "gh", "glpat", "sk-", "_live_", "hooks.slack",
                  "xox", "AIza", "sq0atp", "npm_", "hf_", "eyJ", "PRIVATE KEY", "private_key")
GENERIC_HINT = re.compile(r"(?i)api[_-]?key|secret|token|passw|pwd|credential|private[_-]?key|"
                          r"access[_-]?key|auth")
DIGIT_DEL = str.maketrans("", "", "0123456789")

DIGIT_RUN = re.compile(r"\d(?:[ .-]?\d){8,}")
TOKENISH = re.compile(r"[A-Za-z0-9+/=_.\-]{16,}")

# --------------------------------------------------------------- validators --

def luhn(d: str) -> bool:
    total = 0
    for i, c in enumerate(reversed(d)):
        n = int(c)
        if i % 2:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def card_ok(s: str) -> bool:
    d = re.sub(r"\D", "", s)
    if not 13 <= len(d) <= 19 or len(set(d)) == 1:
        return False
    two = int(d[:2])
    if not (d[0] in "3456" or 22 <= two <= 27):
        return False
    return luhn(d)


def iban_ok(s: str) -> bool:
    t = s.replace(" ", "").upper()
    if not 15 <= len(t) <= 34:
        return False
    num = "".join(str(int(c, 36)) for c in t[4:] + t[:4])
    return int(num) % 97 == 1


def cnid_ok(s: str) -> bool:
    s = s.upper()
    y, m, d = int(s[6:10]), int(s[10:12]), int(s[12:14])
    if not (1900 <= y <= 2099 and 1 <= m <= 12 and 1 <= d <= 31):
        return False
    w = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    total = sum(int(s[i]) * w[i] for i in range(17))
    return "10X98765432"[total % 11] == s[17]


def benn_ok(s: str) -> bool:
    d = re.sub(r"\D", "", s)
    if len(d) != 11:
        return False
    mm, dd = int(d[2:4]), int(d[4:6])
    if not (mm <= 12 or 20 <= mm <= 32 or 40 <= mm <= 52) or dd > 31:
        return False
    chk = int(d[9:])
    return chk == 97 - int(d[:9]) % 97 or chk == 97 - int("2" + d[:9]) % 97

# ------------------------------------------------------------------ helpers --

def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def is_placeholder(v: str) -> bool:
    lv = v.lower().strip("\"'")
    if lv in COMMON_WORDS or len(set(lv)) <= 2:
        return True
    return bool(PLACEHOLDER.search(v))


def is_indirection(v: str, path: str, quoted: bool) -> bool:
    if (INDIRECT.search(v) or DOTTED.match(v) or ENV_NAME.match(v) or v.isdigit()
            or v.startswith("\\") or LOWER_IDENT.match(v) or re.match(r"(?i)https?://", v)):
        return True
    ext = os.path.splitext(path)[1].lower()
    return (not quoted) and ext in CODE_EXT and bool(IDENT.match(v))


def profile(v: str) -> dict:
    classes = [n for n, f in (("lower", str.islower), ("upper", str.isupper),
                              ("digit", str.isdigit)) if any(f(c) for c in v)]
    if any(not c.isalnum() for c in v):
        classes.append("symbol")
    e = entropy(v)
    return {"length": len(v), "classes": classes, "entropy": round(e, 2),
            "looks_random": e >= 3.5 and len(v) >= 16}


def mask_prefixed(val: str, pre) -> str:
    m = pre.match(val) if pre else None
    p = m.group(0) if m else ""
    return f"{p}****… ({len(val)} chars)"


def scrub(line: str) -> str:
    def rep(m):
        t = m.group(0)
        if "****" in t:
            return t
        if any(c.isdigit() for c in t) and any(c.isalpha() for c in t) and entropy(t) >= 3.0:
            return f"****({len(t)})"
        return t
    line = TOKENISH.sub(rep, line)
    return DIGIT_RUN.sub(lambda m: "#" * len(re.sub(r"\D", "", m.group(0))), line)


def overlaps(spans, s, e):
    return any(s < b and a < e for a, b, _ in spans)


def git(args, cwd, timeout=120):
    try:
        r = subprocess.run(["git", "-c", "core.quotepath=off", *args], cwd=cwd,
                           capture_output=True, text=True, errors="replace", timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 else None


def read_bytes(path):
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return "LARGE"
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def is_binary(data: bytes) -> bool:
    return b"\0" in data[:8192]


def excluded(path: str) -> bool:
    parts = path.replace(os.sep, "/").split("/")
    b = parts[-1]
    return any(p in SKIP_DIRS for p in parts[:-1]) or b in SKIP_FILES or b.endswith(SKIP_SUFFIXES)

# ------------------------------------------------------------ line scanning --

def scan_line(path, ln, text, commit):
    spans, out = [], []

    def add(sev, cat, typ, s, e, masked, value=None, **extra):
        spans.append((s, e, masked))
        f = {"severity": sev, "category": cat, "type": typ, "file": path, "line": ln,
             "masked": masked}
        if commit:
            f["commit"] = commit
        f.update(extra)
        if value is not None:
            f["_value"] = value
        out.append(f)

    ndigits = len(text) - len(text.translate(DIGIT_DEL))
    providers = PROVIDERS if any(h in text for h in PROVIDER_HINTS) else ()
    for name, rx, pre, pick in providers:
        for m in rx.finditer(text):
            s, e = m.span()
            if overlaps(spans, s, e):
                continue
            val = m.group(0)
            if name == "Private key block":
                add("HIGH", "secret", name, s, e, val)
                continue
            if name == "GCP service-account key":
                add("HIGH", "secret", name, s, e, '"private_key": "' + "-" * 5 + 'BEGIN ****')
                continue
            body = val[pre.match(val).end():] if pre and pre.match(val) else val
            if is_placeholder(body):
                continue
            add("HIGH", "secret", name, s, e, mask_prefixed(val, pre),
                value=val if pick else None, length=len(val))

    for m in (URL_CRED.finditer(text) if "://" in text and "@" in text else ()):
        s, e = m.span()
        pw = m.group(3)
        if overlaps(spans, s, e) or is_placeholder(pw) or INDIRECT.search(pw):
            continue
        add("HIGH", "secret", "Credentials in URL", s, e,
            f"{m.group(1)}://****:****@****", value=pw, length=len(pw))

    for m in (GENERIC.finditer(text) if GENERIC_HINT.search(text) else ()):
        s, e = m.span(2)
        val = m.group(2)
        quoted = s > 0 and text[s - 1] in "\"'"
        if (overlaps(spans, s, e) or KEY_META.search(m.group(1)) or is_placeholder(val)
                or is_indirection(val, path, quoted)):
            continue
        add("MEDIUM", "secret", "Possible secret (generic assignment)", s, e,
            f"**** ({len(val)} chars)", value=val, key=m.group(1), value_profile=profile(val))

    base = os.path.basename(path)
    pii = [
        ("IBAN", IBAN, iban_ok, lambda v: v.replace(" ", "")[:2] + "****" + v.replace(" ", "")[-4:]),
        ("Chinese ID number", CNID, cnid_ok, lambda v: f"**** ({len(v)} digits)"),
        ("Belgian national number", BENN, benn_ok, lambda v: "**.**.**-***.**"),
        ("Payment card", CARD, card_ok, lambda v: "**** " + re.sub(r"\D", "", v)[-4:]),
        ("Chinese mobile number", CNMOB, None, lambda v: v[:3] + "****" + v[-4:]),
    ]
    for name, rx, ok, msk in (pii if ndigits >= 11 else ()):
        for m in rx.finditer(text):
            s, e = m.span()
            v = m.group(0)
            if overlaps(spans, s, e) or (ok and not ok(v)):
                continue
            if (s > 0 and text[s - 1] == ".") or re.match(r"\.\d", text[e:e + 2]):
                continue  # part of a decimal number (coordinates, measurements)
            add("LOW", "pii", name, s, e, msk(v), validated=ok is not None)

    if "@" in text and base not in EMAIL_SKIP_FILES and not base.endswith(EMAIL_SKIP_EXT):
        for m in EMAIL.finditer(text):
            s, e = m.span()
            v = m.group(0)
            local, _, domain = v.partition("@")
            tld = domain.rsplit(".", 1)[-1].lower()
            if (overlaps(spans, s, e) or local.lower() in EMAIL_SKIP_LOCAL
                    or tld in EMAIL_SKIP_TLD
                    or re.search(r"(^|\.)example\.(com|org|net)$", domain.lower())):
                continue
            add("LOW", "pii", "Email address", s, e, f"{local[0]}***@{domain}")

    if out:
        masked = text
        for a, b, mk in sorted(spans, key=lambda x: -x[0]):
            masked = masked[:a] + mk + masked[b:]
        masked = scrub(masked).strip()
        if len(masked) > MASKED_LINE_MAX:
            masked = masked[:MASKED_LINE_MAX] + "…"
        for f in out:
            f["masked_line"] = masked
    return out

# ------------------------------------------------------ sensitive file kinds --

KEYMAT_EXT = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk")
SSH_KEYS = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
SSH_PUBLIC = {"known_hosts", "authorized_keys", "config"}
CONFIG_NAMES = {".npmrc", ".pypirc", ".netrc", "credentials.json", "credentials.xml"}
TEMPLATE_SUFFIX = (".example", ".sample", ".template", ".dist", ".defaults")


def sensitive_kind(path: str):
    p = "/" + path.replace(os.sep, "/")
    b = p.rsplit("/", 1)[-1]
    if "/.ssh/" in p:
        return None if b.endswith(".pub") or b in SSH_PUBLIC else "keymaterial"
    if b in SSH_KEYS or b.lower().endswith(KEYMAT_EXT):
        return "keymaterial"
    if b == ".env" or (b.startswith(".env.") and not b.endswith(TEMPLATE_SUFFIX)):
        return "config"
    if (b in CONFIG_NAMES or fnmatch.fnmatch(b, "service-account*.json")
            or p.endswith("/.aws/credentials") or p.endswith("/.docker/config.json")):
        return "config"
    if b.endswith((".tfstate", ".tfstate.backup")):
        return "tfstate"
    return None


def cred_keys(text: str):
    keys = []
    for line in text.splitlines():
        for m in CRED_KEY.finditer(line):
            v = m.group(2).strip()
            if v and not is_placeholder(v) and not INDIRECT.search(v):
                keys.append(m.group(1))
        m = NETRC_PW.search(line)
        if m and not is_placeholder(m.group(1)):
            keys.append("password (netrc)")
    return sorted(set(keys))


def file_finding(path, kind, status, root):
    data = read_bytes(os.path.join(root, path))
    f = {"category": "file", "file": path, "status": status}
    if kind == "keymaterial":
        if data is None or data == "LARGE":
            f.update(severity="HIGH", type="Key-material file",
                     note="content not readable in working tree")
        elif b"PRIVATE KEY" in data:
            f.update(severity="HIGH", type="Private key file")
        elif is_binary(data):
            f.update(severity="HIGH", type="Binary key store",
                     note="if this is a Keynote/.key document, not a secret")
        elif b"CERTIFICATE" in data or b"PUBLIC KEY" in data:
            f.update(severity="LOW", type="Public certificate or key", note="not secret by itself")
        else:
            f.update(severity="MEDIUM", type="Key-material file type")
        return f
    text = "" if data in (None, "LARGE") or is_binary(data) else data.decode("utf-8", "replace")
    keys = cred_keys(text)
    f["credential_keys"] = keys
    if kind == "tfstate":
        f.update(severity="HIGH", type="Terraform state", note="state files store secrets in plain text")
    elif keys:
        f.update(severity="HIGH", type="Credential/config file with values")
    else:
        f.update(severity="LOW", type="Sensitive config file type",
                 note="no credential keys with values detected")
    return f

# --------------------------------------------------------------- diff parse --

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def parse_patch(out: str):
    """Yield (path, line_no, text, commit) for every added line of a patch."""
    commit = path = None
    ln = 0
    in_hunk = False
    for raw in out.splitlines():
        if not in_hunk or raw[:1] not in ("+", "-", " ", "\\"):
            if raw.startswith("COMMIT "):
                commit, path, in_hunk = raw[7:].strip(), None, False
                continue
            if raw.startswith("diff --git"):
                path, in_hunk = None, False
                continue
            if raw.startswith("+++ ") and not in_hunk:
                p = raw[4:].strip().strip('"')
                path = None if p == "/dev/null" else (p[2:] if p.startswith("b/") else p)
                continue
            if raw.startswith("--- ") and not in_hunk:
                continue
            m = HUNK.match(raw)
            if m:
                ln, in_hunk = int(m.group(1)), True
                continue
        if in_hunk and path:
            if raw.startswith("+"):
                yield path, ln, raw[1:], commit
                ln += 1
            elif raw.startswith(" "):
                ln += 1

# --------------------------------------------------------------------- main --

def collect(mode, root, is_git, notes):
    """Return (scope_info, paths, units, status_of) where units maps path -> [(ln, text, commit)]."""
    units, status_of = {}, {}
    info = {"mode": mode, "root": root, "git": is_git}
    if not is_git:
        paths = []
        for d, dirs, files in os.walk(root):
            dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
            for fn in files:
                paths.append(os.path.relpath(os.path.join(d, fn), root))
        for p in paths:
            status_of[p] = "no-git"
        return info, sorted(paths), None, status_of

    def z(args):
        out = git(args, root) or ""
        return [p for p in out.split("\0") if p]

    if mode == "tree":
        paths = z(["ls-files", "-co", "--exclude-standard", "-z"])
        tracked = set(z(["ls-files", "-z"]))
        ti = set(z(["ls-files", "-ci", "--exclude-standard", "-z"]))
        info["tracked_but_ignored"] = sorted(ti)
        for p in paths:
            status_of[p] = ("tracked-but-ignored" if p in ti else
                            "tracked" if p in tracked else "untracked-not-ignored")
        return info, sorted(set(paths)), None, status_of

    if mode == "staged":
        paths = z(["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"])
        patch = git(["diff", "--cached", "-U0", "--no-color", "--no-ext-diff",
                     "--diff-filter=ACMR"], root) or ""
        for p in paths:
            status_of[p] = "staged"
    else:  # push
        upstream = git(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"], root)
        rng = ["@{u}..HEAD"] if upstream else ["HEAD", "--not", "--remotes"]
        info["range"] = f"{upstream.strip()}..HEAD" if upstream else "HEAD --not --remotes"
        if not upstream:
            notes.append("No upstream branch: scanning commits on HEAD not present on any remote.")
        names = git(["log", "--name-only", "--format=", "--diff-filter=ACMR", *rng], root) or ""
        paths = sorted({p for p in names.splitlines() if p})
        patch = git(["log", "-p", "-U0", "--no-color", "--no-ext-diff", "--format=COMMIT %h",
                     "--diff-filter=ACMR", *rng], root) or ""
        for p in paths:
            status_of[p] = "in-unpushed-commit"
    for path, ln, text, commit in parse_patch(patch):
        units.setdefault(path, []).append((ln, text, commit))
    return info, sorted(set(paths)), units, status_of


def main(argv=None):
    ap = argparse.ArgumentParser(description="Scan a repo for secrets, sensitive files and PII.")
    ap.add_argument("--mode", choices=["tree", "staged", "push"], default="tree")
    ap.add_argument("--root", default=".")
    ap.add_argument("--no-pushed-check", action="store_true",
                    help="skip searching remote-tracking history for each secret")
    args = ap.parse_args(argv)

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(json.dumps({"error": f"not a directory: {root}"}))
        return 2
    notes = []
    top = git(["rev-parse", "--show-toplevel"], root) if shutil.which("git") else None
    is_git = top is not None
    if is_git:
        root = top.strip()
    elif args.mode != "tree":
        print(json.dumps({"error": f"--mode {args.mode} requires a git repository"}))
        return 2
    else:
        notes.append("Not a git repository: scanned every file; cannot tell what would be committed.")

    info, paths, units, status_of = collect(args.mode, root, is_git, notes)
    remote_refs = bool(is_git and (git(["for-each-ref", "--count=1", "refs/remotes"], root) or "").strip())
    info["remote_refs"] = remote_refs

    findings, skipped = [], Counter()
    per_cap, suppressed = Counter(), Counter()
    flagged_files = set()
    allowlisted = []
    scanned = 0

    # file-level findings
    for p in paths:
        if any(part in SKIP_DIRS for part in p.replace(os.sep, "/").split("/")[:-1]):
            continue
        kind = sensitive_kind(p)
        if kind:
            findings.append(file_finding(p, kind, status_of.get(p, "unknown"), root))
            flagged_files.add(p)

    # content findings
    for p in paths:
        if excluded(p):
            skipped["excluded"] += 1
            continue
        if units is None:
            data = read_bytes(os.path.join(root, p))
            if data is None:
                continue
            if data == "LARGE":
                skipped["large"] += 1
                continue
            if is_binary(data):
                skipped["binary"] += 1
                continue
            lines = [(i, t, None) for i, t in
                     enumerate(data.decode("utf-8", "replace").splitlines(), 1)]
        else:
            lines = units.get(p, [])
            if sum(len(t) for _, t, _ in lines) > MAX_BYTES:
                skipped["large"] += 1
                continue
        scanned += 1
        for ln, text, commit in lines:
            if ALLOW_MARKER in text and "`" + ALLOW_MARKER not in text:  # `marker` = doc mention
                allowlisted.append(f"{p}:{ln}")
                continue
            for f in scan_line(p, ln, text, commit):
                if p in flagged_files and f["severity"] == "MEDIUM" and f["category"] == "secret":
                    continue  # already covered by the file-level finding
                key = (p, f["type"])
                per_cap[key] += 1
                if per_cap[key] > MAX_PER_FILE_TYPE:
                    suppressed[key] += 1
                    continue
                findings.append(f)

    # downgrade findings in test / fixture / example / docs paths
    for f in findings:
        why = ("test/fixture/example path" if TEST_PATH.search(f["file"]) else
               "documentation path" if DOCS_PATH.search(f["file"]) else None)
        if why:
            new = DOWNGRADE[f["severity"]]
            if new != f["severity"]:
                f["severity"], f["downgraded"] = new, why

    # pushed-history check
    if remote_refs and not args.no_pushed_check:
        cache, budget, capped = {}, MAX_PICKAXE, False
        for f in findings:
            if f["severity"] not in ("HIGH", "MEDIUM"):
                continue
            hit = None
            if f["category"] == "file":
                out = git(["log", "--remotes", "-1", "--format=%h", "--", f["file"]], root)
                hit = (out or "").strip() or None
            elif "_value" in f:
                v = f["_value"]
                if v not in cache:
                    if budget <= 0:
                        capped = True
                        continue
                    budget -= 1
                    out = git(["log", "--remotes", "--reverse", "--format=%h", "-S" + v], root,
                              timeout=60)
                    cache[v] = ((out or "").split() or [None])[0]
                hit = cache[v]
            if hit:
                f["pushed_in"] = hit
                if f["severity"] == "HIGH":
                    f["severity"] = "CRITICAL"
        if capped:
            notes.append(f"Pushed-history check capped at {MAX_PICKAXE} distinct values; "
                         "the rest were not checked.")
        notes.append("Pushed check uses local remote-tracking refs; run `git fetch` first for accuracy.")
    elif is_git and not remote_refs:
        notes.append("No remote-tracking refs: cannot tell whether anything was already pushed.")

    for f in findings:
        f.pop("_value", None)
        if f.get("pushed_in"):
            f["exposure"] = "pushed"
        elif f.get("commit"):
            f["exposure"] = "local-commit"
        else:
            f["exposure"] = status_of.get(f["file"], "unknown")

    findings.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["file"], f.get("line", 0)))
    seq = Counter()
    for f in findings:
        seq[f["severity"]] += 1
        f["id"] = f"{f['severity'][0]}{seq[f['severity']]}"

    summary = {s: seq.get(s, 0) for s in SEVERITIES}
    low_groups = []
    if summary["LOW"] > LOW_DETAIL_MAX:
        grp = Counter((f["file"], f["type"]) for f in findings if f["severity"] == "LOW")
        low_groups = [{"file": k[0], "type": k[1], "count": v} for k, v in grp.most_common()]
        findings = [f for f in findings if f["severity"] != "LOW"]
        notes.append(f"{summary['LOW']} LOW findings grouped per file/type in low_findings_grouped; "
                     "re-run on a sub-folder (--root) for line-level detail.")
    verdict = ("NO-GO" if summary["CRITICAL"] or summary["HIGH"] else
               "HOLD" if summary["MEDIUM"] else "GO")
    report = {
        "scope": info,
        "files_scanned": scanned,
        "files_skipped": dict(skipped),
        "gitignore_present": os.path.exists(os.path.join(root, ".gitignore")),
        "scanners_available": [n for n in ("gitleaks", "trufflehog", "detect-secrets")
                               if shutil.which(n)],
        "summary": summary,
        "verdict": verdict,
        "findings": findings,
        "low_findings_grouped": low_groups,
        "allowlisted_lines": allowlisted,
        "suppressed": [{"file": k[0], "type": k[1], "count": v} for k, v in suppressed.items()],
        "notes": notes,
    }
    json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 1 if verdict == "NO-GO" else 0


if __name__ == "__main__":
    sys.exit(main())
