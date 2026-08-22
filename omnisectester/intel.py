"""External threat-intel feeds: EPSS scores + CISA KEV + SSVC decision.

All keyless and deterministic given feed state:
  - EPSS:  https://api.first.org/data/v1/epss?cve=...   (FIRST.org, CC-BY)
  - KEV:   CISA Known Exploited Vulnerabilities JSON feed
  - SSVC:  simplified CISA decision tree (exploitation x impact)
Offline behaviour: callers receive ok=False + reason; nothing crashes.
"""

import json
import urllib.request

EPSS_ENDPOINT = "https://api.first.org/data/v1/epss"
KEV_FEED = ("https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json")


def fetch_epss(cve: str, timeout: float = 10.0) -> tuple:
    """Return ({epss: float0-1, percentile: float}, None) or ({}, error)."""
    url = f"{EPSS_ENDPOINT}?cve={cve}"
    req = urllib.request.Request(url, headers={"User-Agent": "omnisectester"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode())
        rows = data.get("data", [])
        if not rows:
            return {}, f"{cve} not in EPSS dataset"
        row = rows[0]
        return {"epss": float(row.get("epss", 0)),
                "percentile": float(row.get("percentile", 0))}, None
    except Exception as exc:  # noqa: BLE001
        return {}, str(exc)


_kev_cache = {"data": None}


def fetch_kev(timeout: float = 20.0) -> tuple:
    """Return (set-of-CVE-ids, None) from the CISA KEV feed."""
    if _kev_cache["data"] is not None:
        return _kev_cache["data"], None
    req = urllib.request.Request(KEV_FEED, headers={"User-Agent": "omnisectester"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode())
        ids = {v.get("cveID") for v in data.get("vulnerabilities", [])
               if v.get("cveID")}
        _kev_cache["data"] = ids
        return ids, None
    except Exception as exc:  # noqa: BLE001
        return set(), str(exc)


def kev_lookup(cves: list, timeout: float = 20.0) -> dict:
    """Return {cve: True} for members present in KEV."""
    known, err = fetch_kev(timeout=timeout)
    if err:
        return {}, err
    return {c: True for c in cves if c in known}, None


def ssvc_decision(exploitation: str, technical_impact: str,
                  automatable: bool = False) -> dict:
    """Simplified CISA SSVC-style decision.

    exploitation: none | poc | active
    technical_impact: total | partial
    Returns {decision, rationale} where decision is one of
    act / attend / track.
    """
    if exploitation == "active":
        decision = "act"
        why = "Active exploitation observed in KEV - immediate action."
    elif automatable and technical_impact == "total":
        decision = "act"
        why = "Automatable with total impact - act before weaponization."
    elif technical_impact == "total":
        decision = "attend"
        why = "Total technical impact without confirmed exploitation."
    else:
        decision = "track"
        why = "Limited impact and no active exploitation - monitor."
    return {"decision": decision, "rationale": why,
            "inputs": {"exploitation": exploitation,
                       "technical_impact": technical_impact,
                       "automatable": automatable}}


def three_pillars(cvss: dict, epss: dict, kev_hit: bool) -> dict:
    """Combine CVSS + EPSS + SSVC into the severity verdict structure."""
    base = cvss.get("base_score") or 0
    sev = (cvss.get("severity") or "UNKNOWN").upper()
    epss_score = epss.get("epss")
    exploitation = "active" if kev_hit else (
        "poc" if (epss_score or 0) >= 0.5 else "none")
    impact = "total" if base >= 9 else ("partial" if base >= 7 else "low")
    ssvc = ssvc_decision(exploitation, impact,
                         automatable=(epss_score or 0) >= 0.2)
    final = max(
        [sev] + (["CRITICAL"] if kev_hit else []) +
        (["HIGH"] if (epss_score or 0) >= 0.5 and sev in ("UNKNOWN", "LOW", "MEDIUM") else []),
        key=lambda s: ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(s),
    )
    return {
        "cvss": cvss,
        "epss": epss if epss else {"epss": None, "percentile": None},
        "kev": kev_hit,
        "ssvc": ssvc,
        "final_severity": final,
    }
