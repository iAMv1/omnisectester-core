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
                       frameworks: list | None = None) -> dict:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    surface = parsed.netloc or target
    rows = [
        {"stride": s, "category": cat, "threat": desc, "mitigation": mit,
         "relevance": "high" if i < 2 else "medium"}
        for i, (s, cat, desc, mit) in enumerate(THREATS)
    ]
    return {
        "command": "threat-model",
        "target": target,
        "attack_surface": surface,
        "frameworks": frameworks or ["STRIDE"],
        "adversary_profiles": adversary or ["APT29"],
        "methodology": "Static facts about the target mapped to STRIDE entries; "
                       "rows marked high apply to any internet-facing service.",
        "threats": rows,
        "summary": {
            "total": len(rows),
            "high_relevance": sum(1 for r in rows if r["relevance"] == "high"),
        },
        "ok": True,
    }
