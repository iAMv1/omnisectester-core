"""SBOM generation: requirements.txt / package.json -> CycloneDX 1.5 JSON."""

import hashlib
import json
import os
from datetime import datetime, timezone


def _bom_ref(name: str, version: str) -> str:
    return f"pkg:{name}@{version}"


def _purl_ecosystem(ecosystem: str) -> str:
    return {"pypi": "pypi", "npm": "npm"}.get(ecosystem, "generic")


def parse_manifest(path: str) -> tuple[list, str] | None:
    """Return ([(name, version, ecosystem)], ecosystem) or None."""
    if path.endswith("requirements.txt"):
        deps = []
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith(("#", "-")):
                    continue
                for sep in ("==", ">=", "~=", "!="):
                    if sep in line:
                        name, ver = line.split(sep, 1)
                        deps.append((name.strip(), ver.split(",")[0].strip(), "pypi"))
                        break
                else:
                    deps.append((line, "unknown", "pypi"))
        return deps, "pypi"
    if path.endswith("package.json"):
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        deps = [(n, str(v).lstrip("^~>= "), "npm")
                for n, v in {**data.get("dependencies", {}), **data.get("devDependencies", {})}.items()]
        return deps, "npm"
    return None


def find_manifests(root: str) -> list:
    hits = []
    for base, _dirs, files in os.walk(root):
        # skip heavy/irrelevant dirs
        _dirs[:] = [d for d in _dirs if d not in (".git", "node_modules", "__pycache__", ".venv")]
        for fname in ("requirements.txt", "package.json"):
            if fname in files:
                hits.append(os.path.join(base, fname))
    return sorted(hits)


def generate_sbom(root: str, include_vulns: bool = False) -> dict:
    components = []
    seen = set()
    manifests_scanned = 0
    for manifest_path in find_manifests(root):
        parsed = parse_manifest(manifest_path)
        if not parsed:
            continue
        manifests_scanned += 1
        deps, eco = parsed
        for name, version, ecosystem in deps:
            key = (name, version, ecosystem)
            if key in seen:
                continue
            seen.add(key)
            purl = f"pkg:{_purl_ecosystem(ecosystem)}/{name}"
            if version and version != "unknown":
                purl += f"@{version}"
            digest = hashlib.sha256(purl.encode()).hexdigest()[:12]
            components.append({
                "type": "library",
                "bom-ref": f"{purl}?digest={digest}",
                "name": name,
                "version": version,
                "purl": purl,
            })
    sbom = {
        "command": "sbom",
        "ok": True,
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "omnisectester", "name": "omnisectester-core", "version": "0.1.0"}],
            "properties": [
                {"name": "manifestsScanned", "value": str(manifests_scanned)},
                {"name": "root", "value": root},
            ],
        },
        "components": sorted(components, key=lambda c: (c["name"], c["version"])),
    }
    if include_vulns:
        sbom["vulnerabilities"] = []  # OSV enrichment lands in v0.2
        sbom["metadata"]["properties"].append(
            {"name": "vulnEnrichment", "value": "deferred-to-v0.2"})
    return sbom
