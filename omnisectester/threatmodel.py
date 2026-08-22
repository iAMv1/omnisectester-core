"""STRIDE threat model generated from observable target facts."""

from urllib.parse import urlparse

THREATS = [
    ("S", "Spoofing", "Credential stuffing / phishing against exposed login surface",
     "Enforce MFA, rate-limit auth endpoints, monitor credential-stuffing patterns."),
    ("T", "Tampering", "Unvalidated input rendered or persisted",
     "Validate + encode at boundaries; sign integrity-critical payloads."),
    ("R", "Repudiation", "Insufficient audit logging for privileged actions",
     "Append-only structured logs with actor, action, timestamp; alert on gaps."),
    ("I", "Information Disclosure", "Verbose errors/headers leaking stack and versions",
     "Generic error pages; strip version headers; encrypt transport."),
    ("D", "Denial of Service", "Unthrottled expensive endpoints",
     "Per-IP and per-account rate limits; queue + shed load at the edge."),
    ("E", "Elevation of Privilege", "Broken access control on admin routes",
     "Deny-by-default authorization checks server-side; test IDOR matrix."),
]


def build_threat_model(target: str, adversary: list | None = None,
                       frameworks: list | None = None,
                       observed: dict | None = None) -> dict:
    """STRIDE rows whose relevance derives from observed surface facts
    (forms found, params discovered, plaintext, exposed paths) instead of
    static boilerplate. When `observed` is absent the model marks rows
    as baseline (pre-scan)."""
    parsed = urlparse(target if "://" in target else f"https://{target}")
    surface = parsed.netloc or target
    obs = observed or {}

    def relevance(idx, threat_key):
        if not observed:
            return "baseline"
        if threat_key == "spoofing":
            return "high" if obs.get("params", 0) or obs.get("forms", 0) else "medium"
        if threat_key == "tampering":
            return "high" if obs.get("forms", 0) or obs.get("params", 0) else "medium"
        if threat_key == "info_disclosure":
            return "critical" if obs.get("exposed_paths") else (
                "high" if obs.get("plaintext") else "medium")
        if threat_key == "dos":
            return "medium" if obs.get("params", 0) else "low"
        return "medium"

    keys = ["spoofing", "tampering", "repudiation",
            "info_disclosure", "dos", "elevation"]
    rows = [
        {"stride": s, "category": cat, "threat": desc, "mitigation": mit,
         "relevance": relevance(i, key),
         "based_on": ("observed surface" if observed else "baseline pre-scan")}
        for i, ((s, cat, desc, mit), key) in enumerate(zip(THREATS, keys))
    ]
    if observed and obs.get("exposed_paths"):
        rows.append({
            "stride": "I", "category": "Information Disclosure",
            "threat": f"Sensitive paths exposed: {', '.join(obs['exposed_paths'][:5])}",
            "mitigation": "Remove/deny these paths; rotate any secrets they contained.",
            "relevance": "critical", "based_on": "observed surface"})
    high = sum(1 for r in rows if r["relevance"] in ("critical", "high"))
    return {
        "command": "threat-model",
        "target": target,
        "attack_surface": surface,
        "frameworks": frameworks or ["STRIDE"],
        "adversary_profiles": adversary or ["APT29"],
        "methodology": ("Rows derive from OBSERVED facts when available "
                        "(post-crawl); otherwise baseline pre-scan."),
        "observed_facts": obs or None,
        "threats": rows,
        "summary": {"total": len(rows), "high_or_above": high},
        "ok": True,
    }
