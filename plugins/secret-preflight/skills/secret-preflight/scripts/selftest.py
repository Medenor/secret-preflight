#!/usr/bin/env python3
"""
secret-preflight / selftest.py

Builds a throwaway git repo (with a bare "remote") full of FAKE secrets and
look-alikes, runs scan.py in every mode and checks the results.

Fake tokens are assembled at runtime from split fragments, so this file never
contains a literal token: pushing the skill to GitHub will not trip push
protection or other scanners.

Usage: selftest.py            (exit 0 = all checks passed)
"""
import json
import os
import random
import re
import string
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCAN = os.path.join(HERE, "scan.py")
ALNUM = string.ascii_letters + string.digits
rng = random.Random(1234)


def rnd(n, alphabet=ALNUM):
    return "".join(rng.choice(alphabet) for _ in range(n))


def luhn_digit(body):
    total = 0
    for i, c in enumerate(reversed(body)):
        n = int(c)
        if i % 2 == 0:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return str((10 - total % 10) % 10)


def fake_card():
    body = "4" + rnd(14, string.digits)
    d = body + luhn_digit(body)
    return " ".join(d[i:i + 4] for i in range(0, 16, 4))


def fake_iban_be():
    bban = rnd(12, string.digits)
    check = 98 - int(bban + "1114" + "00") % 97
    s = f"BE{check:02d}{bban}"
    return " ".join(s[i:i + 4] for i in range(0, 16, 4))


def fake_be_nn():
    base = "850730033"
    chk = 97 - int(base) % 97
    return f"85.07.30-033.{chk:02d}"


def fake_cn_id():
    body = "110105" + "19850730" + "123"
    w = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    return body + "10X98765432"[sum(int(body[i]) * w[i] for i in range(17)) % 11]


# fake tokens, assembled from fragments
GH1 = "gh" + "p_" + rnd(36)
GH2 = "gh" + "p_" + rnd(36)
GH_FIX = "gh" + "p_" + rnd(36)
GH_ALLOW = "gh" + "p_" + rnd(36)
AWS1 = "AK" + "IA" + rnd(16, string.ascii_uppercase + string.digits)
AWS2 = "AK" + "IA" + rnd(16, string.ascii_uppercase + string.digits)
ANT = "sk-" + "ant-" + "api03-" + rnd(40)
HF = "h" + "f_" + rnd(36)
STRIPE = "sk" + "_live_" + rnd(28)
JWT = "ey" + "J" + rnd(20) + ".ey" + "J" + rnd(24) + "." + rnd(30)
DB_PW = rnd(18)
GENERIC = rnd(32)
PK_HEAD = "-----BEGIN " + "RSA PRIVATE" + " KEY-----"
PK_FOOT = "-----END " + "RSA PRIVATE" + " KEY-----"
CARD, IBAN, BENN, CNID = fake_card(), fake_iban_be(), fake_be_nn(), fake_cn_id()
ALL_SECRETS = [GH_ALLOW, GH1, GH2, GH_FIX, AWS1, AWS2, ANT, HF, STRIPE, JWT, DB_PW, GENERIC]


def sh(*args, cwd):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True)


def write(root, path, content):
    full = os.path.join(root, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as f:
        f.write(content)


def build(tmp):
    remote, repo = os.path.join(tmp, "remote.git"), os.path.join(tmp, "repo")
    os.makedirs(repo)
    sh("git", "init", "--bare", "-q", remote, cwd=tmp)
    sh("git", "init", "-q", cwd=repo)
    sh("git", "checkout", "-q", "-b", "main", cwd=repo)
    for k, v in (("user.email", "selftest@localhost"), ("user.name", "selftest"),
                 ("commit.gpgsign", "false")):
        sh("git", "config", k, v, cwd=repo)
    sh("git", "remote", "add", "origin", remote, cwd=repo)

    # commit 1 (pushed): a token in deploy.sh and a committed .env.production
    write(repo, "deploy.sh", f"#!/bin/sh\nGITHUB_TOKEN={GH2}\n")
    write(repo, ".env.production", f"STRIPE_SECRET_KEY={STRIPE}\nDEBUG=false\n")
    write(repo, "README.md", "# demo\n")
    sh("git", "add", "-A", cwd=repo)
    sh("git", "commit", "-q", "-m", "init", cwd=repo)
    sh("git", "push", "-q", "-u", "origin", "main", cwd=repo)

    # commit 2 (not pushed): the main test surface
    write(repo, ".gitignore", ".env*\n!.env.example\n")
    write(repo, "app.py", "\n".join([
        "import os",
        f'GH = "{GH1}"',
        f'AWS_KEY = "{AWS1}"',
        f'api_key = "{GENERIC}"',
        f'session = "{JWT}"',
        'api_key_doc = "YOUR_API_KEY_HERE"',            # placeholder
        'password = os.environ["DB_PASSWORD"]',         # indirection
        "token = get_token()",                          # function call
        "password = user_password",                     # variable in code
        'icon = "logo@2x.png"',                         # not an email
        "timestamp = 123456789012345",                  # 15 digits, not PII
        "bad_card = '4111 1111 1111 1112'",             # fails Luhn
        'contact = "noreply@example.com"',              # skipped email
        "doc_key = 'AKIAIOSFODNN7EXAMPLE'",             # AWS doc example key
        f'legacy = "{GH_ALLOW}"  # secret-preflight' + ':ignore',   # allowlisted
        "",
    ]))
    write(repo, "config.yaml",
          f"db:\n  url: postgres://admin:{DB_PW}@db.internal:5432/app\n"
          "  replica: postgres://admin:${DB_PASS}@replica:5432/app\n"
          "  password: ${DB_PASS}\n")
    write(repo, "data/customers.csv",
          "name,email,card,iban,nn,cnid\n"
          f"Jane,jane.doe@acme-corp.be,{CARD},{IBAN},{BENN},{CNID}\n")  # secret-preflight:ignore
    write(repo, "keys/server.pem",
          PK_HEAD + "\n" + "\n".join(rnd(64, ALNUM + "+/") for _ in range(5)) + "\n" + PK_FOOT + "\n")
    write(repo, "keys/public.pem", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
    write(repo, "tests/fixtures/sample.py", f'TOKEN = "{GH_FIX}"\n')
    write(repo, ".env.example", "API_KEY=\nDB_PASSWORD=\n")
    sh("git", "add", "-A", cwd=repo)
    sh("git", "commit", "-q", "-m", "app", cwd=repo)

    # commits 3 + 4 (not pushed): secret added then deleted
    write(repo, "tmp.txt", f"aws={AWS2}\n")
    sh("git", "add", "-A", cwd=repo)
    sh("git", "commit", "-q", "-m", "tmp", cwd=repo)
    sh("git", "rm", "-q", "tmp.txt", cwd=repo)
    sh("git", "commit", "-q", "-m", "rm tmp", cwd=repo)

    # ignored + untracked: must never be reported
    write(repo, ".env", f"ANTHROPIC_API_KEY={ANT}\n")
    # staged, not committed
    write(repo, "staged.py", f'HF = "{HF}"\n')
    sh("git", "add", "staged.py", cwd=repo)
    return repo


def run(repo, mode):
    r = subprocess.run([sys.executable, SCAN, "--mode", mode, "--root", repo],
                       capture_output=True, text=True)
    return r.returncode, r.stdout, json.loads(r.stdout)


failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def has(report, typ, file, severity=None):
    for f in report["findings"]:
        if f["type"] == typ and f["file"] == file and (severity is None or f["severity"] == severity):
            return True
    return False


def main():
    with tempfile.TemporaryDirectory() as tmp:
        repo = build(tmp)

        for mode in ("tree", "staged", "push"):
            _, out, _ = run(repo, mode)
            for s in ALL_SECRETS:
                check(s not in out, f"[{mode}] raw secret value leaked in output")
            for s in (re.sub(r"\D", "", CARD), CNID):
                check(s not in out, f"[{mode}] raw PII value leaked in output")

        code, _, t = run(repo, "tree")
        check(code == 1 and t["verdict"] == "NO-GO", "[tree] verdict should be NO-GO, exit 1")
        check(has(t, "GitHub token", "app.py", "HIGH"), "[tree] GitHub token in app.py")
        check(has(t, "AWS access key ID", "app.py", "HIGH"), "[tree] AWS key in app.py")
        check(has(t, "JWT", "app.py", "HIGH"), "[tree] JWT in app.py")
        check(has(t, "Possible secret (generic assignment)", "app.py", "MEDIUM"), "[tree] generic api_key")
        check(has(t, "Credentials in URL", "config.yaml", "HIGH"), "[tree] DB URL credentials")
        check(has(t, "Private key block", "keys/server.pem"), "[tree] private key block")
        check(has(t, "Private key file", "keys/server.pem", "HIGH"), "[tree] private key file")
        check(has(t, "Public certificate or key", "keys/public.pem", "LOW"), "[tree] public cert LOW")
        check(has(t, "GitHub token", "deploy.sh", "CRITICAL"), "[tree] pushed token -> CRITICAL")
        check(has(t, "Credential/config file with values", ".env.production", "CRITICAL"),
              "[tree] pushed tracked-but-ignored .env.production -> CRITICAL")
        check(all(f["exposure"] == "pushed" for f in t["findings"] if f["severity"] == "CRITICAL"),
              "[tree] CRITICAL findings have exposure=pushed")
        check(".env.production" in t["scope"].get("tracked_but_ignored", []),
              "[tree] tracked_but_ignored list")
        check(has(t, "GitHub token", "tests/fixtures/sample.py", "MEDIUM"), "[tree] fixture downgraded")
        for typ in ("Email address", "Payment card", "IBAN", "Belgian national number",
                    "Chinese ID number"):
            check(has(t, typ, "data/customers.csv", "LOW"), f"[tree] PII {typ}")
        check(not any(f["file"] in (".env", "tmp.txt") for f in t["findings"]),
              "[tree] ignored .env / deleted tmp.txt must not appear")
        app = [f for f in t["findings"] if f["file"] == "app.py"]
        check(len([f for f in app if f["type"] == "Possible secret (generic assignment)"]) == 1,
              "[tree] look-alikes in app.py must not produce generic findings")
        check(not any(f["type"] in ("Email address", "Payment card") for f in app),
              "[tree] logo@2x.png / noreply / bad card must not be PII")
        check(not any(f["type"] == "AWS access key ID" and f.get("line") == 14 for f in app),
              "[tree] AWS documentation example key must be ignored")
        check(len([f for f in t["findings"] if f["file"] == "config.yaml"]) == 1,
              "[tree] only the real DB URL in config.yaml")

        check(t["allowlisted_lines"] == ["app.py:15"], "[tree] allowlisted line listed, not reported")

        code, _, s = run(repo, "staged")
        check({f["file"] for f in s["findings"]} == {"staged.py"}, "[staged] only staged.py")
        check(has(s, "Hugging Face token", "staged.py", "HIGH"), "[staged] HF token")

        code, _, p = run(repo, "push")
        check(has(p, "AWS access key ID", "tmp.txt"), "[push] secret in deleted-but-unpushed file")
        check(all(f["exposure"] == "local-commit" for f in p["findings"] if f["file"] == "tmp.txt"),
              "[push] exposure=local-commit")
        check(all(f["exposure"] == "staged" for f in s["findings"]), "[staged] exposure=staged")
        check(not any(f["file"] == "deploy.sh" for f in p["findings"]),
              "[push] already-pushed commit must be outside push range")
        check(has(p, "GitHub token", "app.py"), "[push] app.py token in unpushed commit")

    if failures:
        print("FAIL")
        for f in failures:
            print("  -", f)
        return 1
    print("OK — all self-test checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
