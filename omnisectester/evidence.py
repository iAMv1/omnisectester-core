"""SHA-256 evidence chain-of-custody for scan results.

Builds a manifest: every finding's evidence is hashed, the ordered
manifest itself is hashed into a root digest, and an ISO UTC timestamp
anchors it. Attach to any result via attach(result).
"""

import hashlib
import json
from datetime import datetime, timezone


def _h(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()


def build_manifest(result: dict) -> dict:
    entries = []
    for idx, f in enumerate(result.get("findings", [])):
        evidence_hash = _h(f.get("evidence", ""))
        poc = f.get("poc")
        entries.append({
            "index": idx,
            "finding_id": f["id"],
            "evidence_sha256": evidence_hash,
            "poc_sha256": _h(poc) if poc else None,
        })
    root_payload = json.dumps(
        {"target": result.get("target"), "entries": entries},
        sort_keys=True)
    return {
        "algorithm": "sha256",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "entries": entries,
        "root_digest": _h(root_payload),
    }


def verify(manifest: dict, result: dict) -> tuple:
    """Recompute and compare. Returns (ok: bool, mismatches: list)."""
    rebuilt = build_manifest({"target": result.get("target"),
                              "findings": result.get("findings", [])})
    mismatches = []
    if rebuilt["root_digest"] != manifest.get("root_digest"):
        mismatches.append("root_digest")
    for old, new in zip(manifest.get("entries", []), rebuilt["entries"]):
        if old["evidence_sha256"] != new["evidence_sha256"]:
            mismatches.append(old["finding_id"])
    return (not mismatches), mismatches


def attach(result: dict) -> dict:
    result["chain_of_custody"] = build_manifest(result)
    return result
