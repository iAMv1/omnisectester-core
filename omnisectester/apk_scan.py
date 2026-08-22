"""Android APK static analysis - stdlib zipfile + binary-XML string scan.

Heuristics on the manifest string pool and archive contents:
  M001  dangerous permissions requested
  M002  android:debuggable present (release builds must not be)
  M003  allowBackup enabled (data exfil via adb backup)
  M004  no v1/v2 signature files in META-INF
  I001  exported activity/service/receiver strings present
Honest limits: binary XML attribute VALUES are length-prefixed UTF-16;
we detect flag STRINGS, not parsed attributes. Findings = suspected.
"""

import re
import zipfile

DANGEROUS_PERMISSIONS = [
    "READ_SMS", "RECEIVE_SMS", "READ_CONTACTS", "WRITE_CONTACTS",
    "ACCESS_FINE_LOCATION", "CAMERA", "RECORD_AUDIO", "READ_CALL_LOG",
    "CALL_PHONE", "SEND_SMS", "READ_EXTERNAL_STORAGE", "QUERY_ALL_PACKAGES",
]


def run_apk_scan(path: str) -> dict:
    from .scanner import _finding, _sort
    findings = []
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        return {"command": "scan", "platform": "mobile", "target": path,
                "ok": False, "error": f"not a readable APK/zip: {exc}",
                "findings": []}

    names = zf.namelist()
    manifest_name = next((n for n in names
                          if n.lower() == "androidmanifest.xml"), None)

    if not manifest_name:
        findings.append(_finding(
            "M000", "No AndroidManifest.xml found", "high",
            f"Archive entries: {names[:8]}", "CWE-0",
            "Not an Android APK? Use --platform desktop for binaries."))
    else:
        raw = zf.read(manifest_name)
        text = raw.decode("utf-16-le", errors="ignore")
        printable = re.sub(r"[^\x20-\x7e]", " ", text)

        for perm in DANGEROUS_PERMISSIONS:
            if f"android.permission.{perm}" in printable:
                findings.append(_finding(
                    "M001", f"Dangerous permission: {perm}", "medium",
                    f"Manifest requests android.permission.{perm}.",
                    "CWE-250",
                    "Justify at runtime; drop if non-essential."))

        if "debuggable" in printable:
            findings.append(_finding(
                "M002", "android:debuggable referenced", "high",
                "debuggable attribute string present in compiled manifest.",
                "CWE-489",
                "Set android:debuggable=false for release builds."))
        if "allowBackup" in printable:
            findings.append(_finding(
                "M003", "allowBackup attribute present", "low",
                "If true, app data is extractable via adb backup.",
                "CWE-538",
                "Set allowBackup=false unless backup is a feature."))

        sig_files = [n for n in names if n.startswith("META-INF/")
                     and n.upper().endswith((".RSA", ".DSA", ".EC"))]
        if not sig_files:
            findings.append(_finding(
                "M004", "No signing signature in META-INF", "high",
                f"META-INF entries: {[n for n in names if n.startswith('META-INF/')][:5]}",
                "CWE-494",
                "Sign the release APK (apksigner / jarsigner)."))

        exported = re.findall(r"Exported(?:Activity|Service|Receiver)",
                              printable)
        if exported:
            findings.append(_finding(
                "I001", f"Exported components referenced x{len(exported)}",
                "info", f"count={len(exported)}", "CWE-926",
                "Verify each export is intentional and permission-guarded."))

    zf.close()
    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ("critical", "high", "medium", "low", "info")}
    return {
        "command": "scan", "platform": "mobile", "target": path, "ok": True,
        "findings": _sort(findings),
        "stats": {"requests": 0, "total": len(findings), **counts},
    }
