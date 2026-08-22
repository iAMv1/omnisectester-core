"""Supply-chain / CI-CD poisoning scanner. Offline file inspection only.

Checks (all deterministic, no network):
  S001  .env present and not gitignored
  S002  hardcoded secret-shaped assignments inside GitHub workflows
  S003  third-party GitHub Actions pinned to mutable refs (@main/@master)
        instead of SHAs or version tags -> poisoning surface
  S004  npm lifecycle scripts executing network pipes (curl/wget | bash/sh)
  S005  Python/npm manifests with completely unpinned dependencies
  S006  manifest without lockfile
"""

import json
import os
import re

SECRET_ASSIGN_RE = re.compile(
    r"(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][A-Za-z0-9+/_\-]{12,}['\"]",
    re.I)
UNPINNED_ACTION_RE = re.compile(r"uses:\s*\S+@(main|master|latest)\b", re.I)
NPM_PIPE_RE = re.compile(r"(curl|wget)[^&|;]*\|\s*(sudo\s+)?(ba)?sh", re.I)


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _finding(fid, title, severity, evidence, remediation, path):
    return {"id": fid, "title": title, "severity": severity,
            "evidence": evidence[:400], "remediation": remediation,
            "cwe": _CWE.get(fid, "CWE-0"), "path": path}


_CWE = {
    "S001": "CWE-798", "S002": "CWE-798", "S003": "CWE-1357",
    "S004": "CWE-78", "S005": "CWE-1104", "S006": "CWE-1104",
}


def run_scm_scan(root: str) -> dict:
    from .scanner import _sort
    root = os.path.abspath(root)
    findings = []

    # --- S001: .env not ignored ---
    env_path = os.path.join(root, ".env")
    if os.path.isfile(env_path):
        gi = _read(os.path.join(root, ".gitignore"))
        if ".env" not in gi:
            findings.append(_finding(
                "S001", ".env committed to repository root", "critical",
                ".env exists but is absent from .gitignore.", 
                "Rotate any secrets inside; add .env to .gitignore.", env_path))

    # --- workflows ---
    wf_dir = os.path.join(root, ".github", "workflows")
    if os.path.isdir(wf_dir):
        for fname in sorted(os.listdir(wf_dir)):
            if not fname.endswith((".yml", ".yaml")):
                continue
            wpath = os.path.join(wf_dir, fname)
            content = _read(wpath)
            for m in SECRET_ASSIGN_RE.finditer(content):
                findings.append(_finding(
                    "S002", f"Hardcoded secret in workflow {fname}", "high",
                    f"{m.group(0)[:60]}...", 
                    "Replace with encrypted secrets (github Actions secrets).",
                    wpath))
            for m in UNPINNED_ACTION_RE.finditer(content):
                findings.append(_finding(
                    "S003", f"Action pinned to mutable ref in {fname}",
                    "medium",
                    f"`{m.group(0)}` - tag can be repointed at malicious code.",
                    "Pin to a full commit SHA.", wpath))

    # --- npm lifecycle pipes ---
    pkg_path = os.path.join(root, "package.json")
    if os.path.isfile(pkg_path):
        try:
            pkg = json.loads(_read(pkg_path))
            scripts = pkg.get("scripts", {})
            for name, cmd in sorted(scripts.items()):
                if NPM_PIPE_RE.search(str(cmd)):
                    findings.append(_finding(
                        "S004", f"npm script `{name}` pipes network to shell",
                        "high", f"scripts.{name}: {cmd[:120]}",
                        "Remove the pipe; pin and review bootstrap scripts.",
                        pkg_path))
        except ValueError:
            findings.append(_finding(
                "S006", "package.json unparseable JSON", "medium",
                "Invalid JSON breaks tooling and may hide tampering.",
                pkg_path))

    # --- unpinned / lockfile checks ---
    req = os.path.join(root, "requirements.txt")
    if os.path.isfile(req):
        lines = [l.strip() for l in _read(req).splitlines()
                 if l.strip() and not l.strip().startswith(("#", "-"))]
        unpinned = [l for l in lines if "==" not in l]
        if unpinned:
            findings.append(_finding(
                "S005", f"requirements.txt: {len(unpinned)} unpinned deps",
                "low", ", ".join(unpinned[:5]), req))
    if os.path.isfile(pkg_path) and not any(
            os.path.isfile(os.path.join(root, lf)) for lf in
            ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml")):
        findings.append(_finding(
            "S006", "package.json without lockfile", "medium",
            "Installs are non-reproducible; ranges can resolve to "
            "compromised releases.", "Commit a lockfile and enforce "
            "npm ci.", pkg_path))

    return {
        "command": "scan", "platform": "supply-chain", "target": root,
        "ok": True,
        "findings": _sort(findings),
        "stats": {"requests": 0, "total": len(findings),
                  "critical": sum(1 for f in findings if f["severity"] == "critical"),
                  "high": sum(1 for f in findings if f["severity"] == "high")},
    }
