#!/usr/bin/env python3
"""Contract for the security-scan job.

Fails while the workflow still calls gitleaks/gitleaks-action (the step that
exits on organization repos before PII and RO-Crate run). Passes when the job
scans full git history with the checksum-pinned gitleaks CLI and the later
steps are unchanged.
"""

import hashlib
import os
import secrets
import shutil
import string
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "security-scan.yml"
SCRIPT = ROOT / "scripts" / "run_gitleaks.sh"
CHECKOUT_SHA = "11d5960a326750d5838078e36cf38b85af677262"
GITLEAKS_VERSION = "8.30.1"
SHA_LINUX_X64 = "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
SHA_LINUX_ARM64 = "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"
# Bodies of the two steps that must stay byte-for-byte. The hashes cover the
# denylist and the RO-Crate diff check without copying those literals here.
PII_RUN_SHA256 = "de5621d4cc0a0a4393c6a63f06fc4a34f3f368fa14d3e234caef2b1d02e563a7"
ROCRATE_RUN_SHA256 = "1564ebd7b83cf1d908857da53f4a7dc0ec9de4d6ef0f080c14c43812c9989155"
SCAN_LINE = '"$bin" git "$TARGET" --redact --verbose --exit-code 1 --no-banner'


def fail(message):
    raise SystemExit(message)


def extract_run_block(text, step_name):
    marker = f"- name: {step_name}\n"
    start = text.find(marker)
    if start < 0:
        fail(f"missing step {step_name}")
    lines = text[start + len(marker):].splitlines(keepends=True)
    body = []
    seen_run = False
    for line in lines:
        if not seen_run:
            if line.strip() == "run: |":
                seen_run = True
            continue
        if line.startswith("          ") or line == "\n":
            body.append(line)
            continue
        break
    if not seen_run or not body:
        fail(f"missing run block for {step_name}")
    return "".join(body)


def assert_workflow(text):
    for line in text.splitlines():
        code = line.split("#", 1)[0]
        if "gitleaks-action" in code:
            fail("security-scan still uses gitleaks-action; that action requires a paid org license and skips later steps")
        if "GITLEAKS_LICENSE" in code:
            fail("security-scan must not depend on a paid GITLEAKS_LICENSE")
    if "continue-on-error" in text:
        fail("security-scan must not continue past a failed scan step")
    if "fetch-depth: 0" not in text:
        fail("checkout must fetch full history (fetch-depth: 0)")
    if f"actions/checkout@{CHECKOUT_SHA}" not in text:
        fail(f"actions/checkout must be pinned to {CHECKOUT_SHA}")
    if "bash scripts/run_gitleaks.sh" not in text:
        fail("gitleaks step must run scripts/run_gitleaks.sh")
    if "contents: read" not in text:
        fail("security-scan must keep contents: read")
    for name, expected in (
        ("PII scan (personal identifiers)", PII_RUN_SHA256),
        ("RO-Crate manifest freshness (diff-verified)", ROCRATE_RUN_SHA256),
    ):
        body = extract_run_block(text, name)
        digest = hashlib.sha256(body.encode()).hexdigest()
        if digest != expected:
            fail(f"{name} changed (sha256 {digest}); do not loosen or remove this step")


def assert_script(text):
    if not text.startswith("#!/usr/bin/env bash\n"):
        fail("run_gitleaks.sh must be a bash script")
    for needle in (
        f'VERSION="{GITLEAKS_VERSION}"',
        f'SHA_LINUX_X64="{SHA_LINUX_X64}"',
        f'SHA_LINUX_ARM64="{SHA_LINUX_ARM64}"',
        "sha256sum -c -",
        "curl --proto =https --proto-redir =https",
        "unset GITLEAKS_CONFIG GITLEAKS_CONFIG_TOML",
        SCAN_LINE,
    ):
        if needle not in text:
            fail(f"run_gitleaks.sh is missing {needle}")
    if "--config" in text:
        fail("run_gitleaks.sh must not pass --config; .gitleaks.toml discovery stays the default")
    if "continue-on-error" in text:
        fail("run_gitleaks.sh must not ignore a non-zero gitleaks exit")
    for line in text.splitlines():
        if SCAN_LINE in line and "|| true" in line:
            fail("the gitleaks scan command must not be masked with || true")


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


def init_repo():
    repo = Path(tempfile.mkdtemp(prefix="gitleaks-fixture-"))
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "user.name", "gitleaks-fixture")
    git(repo, "config", "commit.gpgsign", "false")
    return repo


def commit_file(repo, name, content, message):
    path = repo / name
    path.write_text(content)
    git(repo, "add", name)
    git(repo, "commit", "-q", "-m", message)


def run_scan(repo, install_dir, script=SCRIPT):
    env = os.environ.copy()
    env["GITLEAKS_INSTALL_DIR"] = str(install_dir)
    env.pop("GITLEAKS_CONFIG", None)
    env.pop("GITLEAKS_CONFIG_TOML", None)
    return subprocess.run(
        ["bash", str(script), str(repo)],
        capture_output=True,
        text=True,
        env=env,
        cwd=ROOT,
    )


def github_pat():
    alphabet = string.ascii_letters + string.digits
    return "ghp_" + "".join(secrets.choice(alphabet) for _ in range(36))


def assert_scan_behavior():
    install_dir = Path(tempfile.mkdtemp(prefix="gitleaks-install-"))
    clean = leaked = allowed = None
    try:
        clean = init_repo()
        commit_file(clean, "README.md", "no secrets here\n", "init")
        clean_run = run_scan(clean, install_dir)
        if clean_run.returncode != 0:
            fail(f"clean repository must pass gitleaks git\n{clean_run.stdout}\n{clean_run.stderr}")

        leaked = init_repo()
        secret = github_pat()
        commit_file(leaked, "secret.txt", f'github_token = "{secret}"\n', "add token")
        (leaked / "secret.txt").unlink()
        git(leaked, "add", "-u")
        git(leaked, "commit", "-q", "-m", "remove token")
        leaked_run = run_scan(leaked, install_dir)
        if leaked_run.returncode == 0:
            fail("gitleaks git must exit non-zero when a secret exists only in history")
        combined = leaked_run.stdout + leaked_run.stderr
        if secret in combined:
            fail("gitleaks output included the raw secret; --redact is required")

        allowed = init_repo()
        commit_file(allowed, "secret.txt", f'github_token = "{secret}"\n', "add token")
        (allowed / ".gitleaks.toml").write_text(
            "title = \"fixture\"\n"
            "[extend]\n"
            "useDefault = true\n"
            "[[allowlists]]\n"
            "description = \"fixture path\"\n"
            "paths = ['''secret\\.txt''']\n"
        )
        git(allowed, "add", ".gitleaks.toml")
        git(allowed, "commit", "-q", "-m", "allowlist fixture path")
        allowed_run = run_scan(allowed, install_dir)
        if allowed_run.returncode != 0:
            fail(
                "a repo-root .gitleaks.toml allowlist must still apply\n"
                f"{allowed_run.stdout}\n{allowed_run.stderr}"
            )
    finally:
        for path in (clean, leaked, allowed, install_dir):
            if path is not None:
                shutil.rmtree(path, ignore_errors=True)


def assert_bad_checksum_fails():
    mutated = Path(tempfile.mkdtemp(prefix="gitleaks-bad-script-")) / "run_gitleaks.sh"
    text = SCRIPT.read_text()
    text = text.replace(SHA_LINUX_X64, "0" * 64).replace(SHA_LINUX_ARM64, "0" * 64)
    mutated.write_text(text)
    install_dir = Path(tempfile.mkdtemp(prefix="gitleaks-bad-install-"))
    repo = init_repo()
    try:
        commit_file(repo, "README.md", "no secrets here\n", "init")
        result = run_scan(repo, install_dir, script=mutated)
        if result.returncode == 0:
            fail("a checksum mismatch must fail the scan")
        if "no leaks found" in (result.stdout + result.stderr):
            fail("checksum mismatch must fail before a scan is reported clean")
    finally:
        shutil.rmtree(repo, ignore_errors=True)
        shutil.rmtree(install_dir, ignore_errors=True)
        shutil.rmtree(mutated.parent, ignore_errors=True)


def main():
    workflow = WORKFLOW.read_text()
    assert_workflow(workflow)
    if not SCRIPT.is_file():
        fail("scripts/run_gitleaks.sh is missing")
    assert_script(SCRIPT.read_text())
    assert_scan_behavior()
    assert_bad_checksum_fails()
    print("security-scan contract: ok")


if __name__ == "__main__":
    main()
