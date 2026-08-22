"""Post-exploitation assessment: map collected evidence to MITRE ATT&CK
post-compromise techniques and produce a prioritized attack-planning view.

Honest scope: this is an ASSESSMENT/planning artifact built from what the
deterministic scanner observed (exposed secrets, internal hosts, cookies).
It does not itself exploit anything.
"""

import re

from .scanner import _sort

# (technique_id, name, tactic, trigger predicate key)
MAPPINGS = [
    ("T1552", "Unsecured Credentials", "credential-access",
     "has_exposed_secrets"),
    ("T1552.001", "Credentials In Files", "credential-access",
     "has_env_file"),
    ("T1087", "Account Discovery", "discovery",
     "has_user_params"),
    ("T1046", "Network Service Discovery", "discovery",
     "has_internal_hosts"),
    ("T1539", "Steal Web Session Cookie", "credential-access",
     "has_session_cookie"),
    ("T1078", "Valid Accounts", "defense-evasion",
     "has_valid_login"),
]


def harvest_internal_hosts(text: str) -> list:
    """Private-scope IPs and *.internal/.local hostnames in page bodies."""
    priv = re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3}"
        r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")
    host = re.compile(r"\b[\w.-]+\.(?:internal|local|corp)\b", re.I)
    return sorted(set(priv.findall(text)) | set(h.lower() for h in host.findall(text)))


def analyze(scan_result: dict) -> dict:
    findings = scan_result.get("findings", [])
    surface = scan_result.get("surface", {})
    ids = {f["id"] for f in findings}
    evidence = {
        "has_exposed_secrets": bool({"P001"} & ids),
        "has_env_file": bool({"P001"} & ids),
        "has_user_params": any(t.get("param") in
                               ("user", "username", "uid", "id")
                               for t in surface.get("probe_targets", [])),
        "has_internal_hosts": bool(scan_result.get("internal_hosts")),
        "has_session_cookie": bool({"C003"} & ids) or bool(
            scan_result.get("cookies_seen")),
        "has_valid_login": bool(surface.get("forms")),
    }
    triggers = {"has_internal_hosts": scan_result.get("internal_hosts", [])}

    rows = []
    for tid, name, tactic, key in MAPPINGS:
        if not evidence.get(key):
            continue
        detail = ""
        if key == "has_internal_hosts":
            detail = f"observed: {', '.join(triggers[key][:4])}"
        elif key == "has_exposed_secrets":
            detail = ".env / secret material returned 200 pre-auth"
        elif key == "has_valid_login":
            detail = "login forms discovered - stolen creds would replay"
        else:
            detail = "observed during crawl"
        rows.append({"technique": tid, "name": name, "tactic": tactic,
                     "relevance": "high", "evidence": detail})
    return {
        "command": "postexploit", "ok": True,
        "assessment": "PLANNING ARTIFACT ONLY - maps observed weaknesses "
                      "onto MITRE ATT&CK post-compromise techniques.",
        "mitre_rows": rows,
        "summary": {"techniques_applicable": len(rows)},
    }
