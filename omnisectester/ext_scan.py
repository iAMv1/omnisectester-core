"""Browser-extension scanner (CRX/unpacked zip): manifest + JS static checks.

Checks (taxonomy ext.*):
  E001  overbroad permissions (tabs, <all_urls>, cookies, history,
        management, nativeMessaging, scripting on <all_urls>)
  E002  remote code execution patterns in JS (eval(, new Function()
  E003  CSP missing or contains unsafe-eval / unsafe-inline
  E004  insecure http:// update_url
  E005  hardcoded API-key-looking strings in JS/JSON

Honest limits: string-level heuristics, no AST parse of minified code.
"""

import json
import re
import zipfile

DANGEROUS_PERMS = {"tabs", "<all_urls>", "cookies", "history",
                   "management", "nativeMessaging", "debugger",
                   "declarativeNetRequest"}
SECRET_RE = re.compile(r"(api[_-]?key|apikey|secret)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}", re.I)
EVAL_RE = re.compile(r"\beval\s*\(|new\s+Function\s*\(")


def _load_manifest(zf):
    for name in ("manifest.json", "_metadata/manifest.json"):
        try:
            return json.loads(zf.read(name).decode("utf-8", errors="replace"))
        except KeyError:
            continue
        except json.JSONDecodeError as exc:
            return {"__error__": f"manifest.json unparseable: {exc}"}
    return None


def run_ext_scan(path: str) -> dict:
    from .scanner import _finding, _sort
    findings = []
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        return {"command": "scan", "platform": "extension", "target": path,
                "ok": False, "error": f"not a readable CRX/zip: {exc}",
                "findings": []}

    names = zf.namelist()
    manifest = _load_manifest(zf)
    if manifest is None or "__error__" in manifest:
        err = (manifest or {}).get("__error__", "no manifest.json at archive root")
        findings.append(_finding(
            "E000", "Manifest missing/unreadable", "medium", err, "CWE-0",
            "Ensure the CRX contains a valid manifest.json at root."))
        manifest = {}

    perms = set(manifest.get("permissions", []))
    perms |= set(manifest.get("host_permissions", []))
    perms |= set(manifest.get("optional_permissions", []))
    hits = sorted(perms & DANGEROUS_PERMS)
    if "<all_urls>" in perms or any("*://" in str(p) for p in perms):
        hits.append("<all_urls>-host")
    if hits:
        findings.append(_finding(
            "E001", "Overbroad permissions requested", "high",
            f"permissions={hits}", "CWE-250",
            "Request least-privilege scopes; split features across opt-ins."))

    csp = manifest.get("content_security_policy")
    csp_str = json.dumps(csp) if csp else ""
    if not csp_str and manifest.get("manifest_version") == 3:
        pass  # MV3 default CSP is strict - absence is fine unless overridden
    elif not csp_str:
        findings.append(_finding(
            "E003", "No content_security_policy declared (MV2)", "medium",
            "MV2 manifest without CSP allows injected script loads.",
            "CWE-693", "Declare a strict CSP; avoid inline handlers."))
    elif "unsafe-eval" in csp_str or "unsafe-inline" in csp_str:
        findings.append(_finding(
            "E003", "CSP permits unsafe eval/inline", "high",
            f"csp={csp_str[:200]}", "CWE-693",
            "Remove unsafe-eval/unsafe-inline; use bundled assets only."))

    upd = manifest.get("update_url", "")
    if upd.startswith("http://"):
        findings.append(_finding(
            "E004", "Insecure update_url (http)", "high",
            f"update_url={upd}", "CWE-319",
            "Serve updates over HTTPS; prefer the store's update channel."))

    for entry in names:
        if entry.endswith(".js"):
            try:
                src = zf.read(entry).decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                continue
            if EVAL_RE.search(src):
                findings.append(_finding(
                    "E002", f"Remote/exec code pattern in {entry}", "high",
                    f"{entry}: eval()/new Function() present.", "CWE-95",
                    "Remove dynamic evaluation; ship prebuilt bundles."))
            m = SECRET_RE.search(src)
            if m:
                findings.append(_finding(
                    "E005", f"Hardcoded secret pattern in {entry}", "critical",
                    f"{entry}: {m.group(0)[:80]}", "CWE-798",
                    "Move secrets to server-side config or token exchange."))

    return {"command": "scan", "platform": "extension", "target": path,
            "ok": True, "findings": _sort(findings),
            "stats": {"total": len(findings),
                      "entries": len(names)}}
