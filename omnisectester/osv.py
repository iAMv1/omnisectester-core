"""OSV.dev vulnerability matching - free, keyless, deterministic.

POST https://api.osv.dev/v1/query  {"package": {...}, "version": "..."}
Degrades gracefully offline: errors become metadata, never crashes SBOM.
"""

import json
import urllib.error
import urllib.request

OSV_ENDPOINT = "https://api.osv.dev/v1/query"
OSV_BATCH_ENDPOINT = "https://api.osv.dev/v1/querybatch"
ECOSYSTEM_MAP = {"pypi": "PyPI", "npm": "npm"}


def query_batch(items: list, timeout: float = 12.0):
    """items: [(name, version, ecosystem)]. Returns [vuln-lists] aligned to
    input order, or (None, error) on transport failure."""
    queries = []
    for name, version, ecosystem in items:
        eco = ECOSYSTEM_MAP.get(ecosystem)
        q = {"package": {"name": name, "ecosystem": eco}} if eco else {"package": {"name": name}}
        if version and version != "unknown":
            q["version"] = version
        queries.append(q)
    body = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        OSV_BATCH_ENDPOINT, data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        return [entry.get("vulns", []) for entry in data.get("results", [])], None
    except urllib.error.HTTPError as exc:
        return None, f"HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)


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


def enrich_components(components: list, ecosystem: str, timeout: float = 8.0,
                      batch: bool = True) -> tuple[list, list]:
    """Attach vulnerabilities to matching components. Returns (vulns, errors).
    batch=True uses the single-request querybatch endpoint (one round-trip
    for the whole SBOM); falls back to error reporting on transport failure."""
    vulnerabilities = []
    errors = []
    if not components:
        return vulnerabilities, errors

    items = [(c["name"], c.get("version", "unknown"), ecosystem) for c in components]
    if batch:
        results, err = query_batch(items, timeout=timeout)
        if err:
            errors.append(f"querybatch: {err}")
            return vulnerabilities, errors
    else:
        results = None

    for idx, comp in enumerate(components):
        if comp.get("version") in ("", "unknown"):
            continue
        vulns = results[idx] if (results is not None and idx < len(results)) else []
        if results is None:  # non-batch fallback path
            vulns, err = query_package(*items[idx], timeout=timeout)
            if err:
                errors.append(f"{comp['name']}: {err}")
        for v in vulns:
            vuln_id = v.get("id", "UNKNOWN")
            aliases = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
            sev = next((s.get("score") for s in v.get("severity", [])
                        if s.get("type") == "CVSS_V3"), None)
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
