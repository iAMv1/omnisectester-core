"""12-phase kill-chain model mapped to MITRE ATT&CK.

The agent pipeline executes phases 1-9 deterministically; phases 10-12
(persistence, exfil staging, reporting) are ASSESSED from observations,
never simulated destructively. Honest scope.
"""

PHASES = [
    {"n": 1,  "name": "recon-passive",      "mitre": "TA0043/T1595"},
    {"n": 2,  "name": "threat-model",        "mitre": "TA0043/T1589"},
    {"n": 3,  "name": "surface-discovery",   "mitre": "TA0043/T1592"},
    {"n": 4,  "name": "initial-access-probe","mitre": "TA0001/T1190"},
    {"n": 5,  "name": "execution-reflection","mitre": "TA0002/T1059.007"},
    {"n": 6,  "name": "persistence-check",   "mitre": "TA0003/T1098"},
    {"n": 7,  "name": "privilege-esc-path",  "mitre": "TA0004/T1068"},
    {"n": 8,  "name": "defense-evasion-audit","mitre": "TA0005/T1562"},
    {"n": 9,  "name": "credential-access",   "mitre": "TA0006/T1552"},
    {"n": 10, "name": "discovery-internal",  "mitre": "TA0007/T1046"},
    {"n": 11, "name": "lateral-potential",   "mitre": "TA0008/T1021"},
    {"n": 12, "name": "exfiltration-staging","mitre": "TA0010/T1567"},
]

# finding id -> phase number it evidences
FINDING_PHASE = {
    "H001": 8, "H002": 8, "H003": 8, "H004": 8, "H005": 8, "H006": 8,
    "T001": 8, "T002": 4, "T003": 4, "T004": 9, "T005": 9,
    "P001": 9, "P002": 10,
    "X001": 5, "X002": 5,
    "F001": 6, "C001": 9, "C002": 9, "C003": 6,
    "R001": 11, "I001": 3, "I002": 1, "I003": 3, "W001": 0,
}


def build_chain(result: dict) -> list:
    """Return the 12 phases with status + evidence counts from a result."""
    findings = result.get("findings", [])
    by_phase = {}
    for f in findings:
        ph = FINDING_PHASE.get(f["id"], 0)
        by_phase.setdefault(ph, []).append(f)
    out = []
    for p in PHASES:
        evs = by_phase.get(p["n"], [])
        if p["n"] == 0:
            continue
        out.append({
            **p,
            "status": "evidenced" if evs else ("executed" if p["n"] <= 4 else "assessed"),
            "finding_count": len(evs),
            "finding_ids": [f["id"] for f in evs][:8],
        })
    return out
