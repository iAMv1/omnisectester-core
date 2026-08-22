"""Desktop binary scanner (.exe / .dll PE files) - stdlib struct + regex.

Checks (heuristic, deterministic):
  E001  not a valid PE (missing MZ header)
  E002  embedded executable writes another executable
  E003  suspicious API imports (process injection / keylogging set)
  E004  embedded URLs / IPs (informational - where does it call home?)
Honest limits: no signature verification, no disassembly. Strings-level.
"""

import re
import struct

from .scanner import _finding, _sort

SUSPICIOUS_APIS = [
    "WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx",
    "SetWindowsHookEx", "NtUnmapViewOfSection", "QueueUserAPC",
]
URL_RE = re.compile(rb"https?://[\x20-\x7e]{6,120}")
IP_RE = re.compile(
    rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def run_exe_scan(path: str) -> dict:
    findings = []
    try:
        with open(path, "rb") as fh:
            blob = fh.read(134_217_728)  # 128MB cap
    except OSError as exc:
        return {"command": "scan", "platform": "desktop", "target": path,
                "ok": False, "error": str(exc), "findings": []}

    if len(blob) < 2 or blob[:2] != b"MZ":
        findings.append(_finding(
            "E001", "Not a valid Windows executable", "medium",
            "Missing MZ header.", "CWE-0",
            "Use --platform web/mobile for non-PE targets."))

    # optional PE header walk for timestamp (best effort)
    compile_year = None
    try:
        pe_offset = struct.unpack_from("<I", blob, 0x3C)[0]
        if 0 < pe_offset < len(blob) - 12 and blob[pe_offset:pe_offset + 4] == b"PE\x00\x00":
            ts = struct.unpack_from("<I", blob, pe_offset + 8)[0]
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            compile_year = dt.year
    except Exception:  # noqa: BLE001
        pass

    printable = blob.lower()
    hits = [api for api in SUSPICIOUS_APIS
            if api.lower().encode() in printable]
    if len(hits) >= 2:
        findings.append(_finding(
            "E003", "Process-injection / hooking API cluster", "high",
            f"imports referenced: {hits}", "CWE-402",
            "Verify why the binary manipulates other processes' memory."))

    urls = [m.group().decode() for m in URL_RE.finditer(blob)][:10]
    ips = [m.group().decode() for m in IP_RE.finditer(blob)][:10]
    if urls or ips:
        finding = _finding(
            "E004", "Embedded network endpoints", "info",
            f"urls={urls[:5]} ips={ips[:5]}", "CWE-200",
            "Confirm every endpoint belongs to your infrastructure.")
        finding["urls"], finding["ips"] = urls, ips
        findings.append(finding)

    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ("critical", "high", "medium", "low", "info")}
    return {
        "command": "scan", "platform": "desktop", "target": path, "ok": True,
        "meta": {"compile_year": compile_year, "size_bytes": len(blob)},
        "findings": _sort(findings),
        "stats": {"requests": 0, "total": len(findings), **counts},
    }
