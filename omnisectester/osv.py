"""OSV.dev vulnerability matching - free, keyless, deterministic.

POST https://api.osv.dev/v1/query  {"package": {...}, "version": "..."}
Degrades gracefully offline: errors become metadata, never crashes SBOM.
"""

import json
import urllib.error
import urllib.request

OSV_ENDPOINT = "https://api.osv.dev/v1/query"
ECOSYSTEM_MAP = {"pypi": "PyPI", "npm": "npm"}


def query_package(name: str, version: str, ecosystem: str, timeout: float = 8.0):
    """Return list of OSV vuln dicts for one package version, or error dict."""
    eco = ECOSYSTEM_MAP.get(ecosystem)
    if not eco or version in ("", "unknown"):
        return [], None
    payload = json.dumps({
        "package": {"name": name, "ecosystem": eco},
        "version": version,
    }).encode()
    req = urllib.request.Request(
        OSV_ENDPOINT, data=payload,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
            return data.get("vulns", []), None
    except urllib.error.HTTPError as exc:
        return [], f"HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001
        return [], str(exc)


def enrich_components(components: list, ecosystem: str, timeout: float = 8.0) -> tuple[list, list]:
    """Attach vulnerabilities to matching components. Returns (vulns, errors)."""
    vulnerabilities = []
    errors = []
    for comp in components:
        if comp.get("version") in ("", "unknown"):
            continue
        vulns, err = query_package(comp["name"], comp["version"], ecosystem, timeout)
        if err:
            errors.append(f"{comp['name']}: {err}")
            continue
        for v in vulns:
            vuln_id = v.get("id", "UNKNOWN")
            sev = None
            for s in v.get("severity", []):
                if s.get("type") == "CVSS_V3":
                    sev = s.get("score")
            aliases = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
            vulnerabilities.append({
                "id": vuln_id,
                "source": "OSV.dev",
                "aliases": aliases,
                "summary": (v.get("summary") or v.get("details") or "")[:300],
                "severity_cvss_v3": sev,
                "affected": [{"ref": comp["bom-ref"], "package": comp["name"],
                              "version": comp["version"]}],
            })
    return vulnerabilities, errors
