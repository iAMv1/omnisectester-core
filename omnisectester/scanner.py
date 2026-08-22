"""Web scanner: security headers, TLS, fingerprinting, path probe, XSS probe.

Every finding follows one shape:
    {id, title, severity (critical|high|medium|low|info), evidence,
     remediation, cwe}
Output ordering is deterministic: severity desc, then id.
"""

import re
import socket
from urllib.parse import urlparse

from . import httpc

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Exit-code gate: severities at/above this level trigger exit 2 (findings
# found) rather than 0. Mirrors Strix-style CI semantics: a scan that
# succeeded but found criticals must fail the pipeline.
FAIL_ON_RANK = {"none": 99, "info": 4, "low": 3, "medium": 2, "high": 1, "critical": 0}

SECURITY_HEADERS = [
    ("strict-transport-security", "high", "H001",
     "Missing Strict-Transport-Security (HSTS)", "CWE-319",
     "Add `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`."),
    ("content-security-policy", "high", "H002",
     "Missing Content-Security-Policy", "CWE-79",
     "Add a CSP that restricts script/style/img sources to what the app needs."),
    ("x-content-type-options", "medium", "H003",
     "Missing X-Content-Type-Options", "CWE-430",
     "Send `X-Content-Type-Options: nosniff`."),
    ("x-frame-options", "medium", "H004",
     "Missing X-Frame-Options / frame-ancestors", "CWE-1021",
     "Send `X-Frame-Options: DENY` or CSP frame-ancestors 'none'."),
    ("referrer-policy", "low", "H005",
     "Missing Referrer-Policy", "CWE-200",
     "Send `Referrer-Policy: strict-origin-when-cross-origin`."),
    ("permissions-policy", "low", "H006",
     "Missing Permissions-Policy", "CWE-693",
     "Send a Permissions-Policy restricting camera/microphone/geolocation."),
]

COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.env", "/.git/config", "/backup.zip",
    "/admin", "/phpinfo.php", "/wp-login.php", "/.DS_Store", "/server-status",
]

XSS_PROBE = "<script>omni_probe()</script>"
XSS_MARKER = "omni_probe"


def _finding(fid, title, severity, evidence, cwe, remediation):
    return {
        "id": fid, "title": title, "severity": severity,
        "evidence": evidence[:500], "cwe": cwe, "remediation": remediation,
    }


def _sort(findings):
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f["severity"]], f["id"]))


def check_headers(resp) -> list:
    found = []
    for header, sev, fid, title, cwe, fix in SECURITY_HEADERS:
        if header not in resp["headers"]:
            found.append(_finding(fid, title, sev, f"Response missing `{header}`.", cwe, fix))
    server = resp["headers"].get("server")
    if server:
        found.append(_finding("I001", "Server version disclosed", "info",
                              f"`Server: {server}` reveals software/version.", "CWE-200",
                              "Strip or genericize the Server header at the edge."))
    return found


def check_tls(host: str) -> list:
    parsed_host = host.split(":")[0]
    info = httpc.tls_info(parsed_host)
    found = []
    if not info.get("enabled"):
        return found  # plain HTTP target; transport finding added by caller
    proto = info.get("protocol") or ""
    if proto in ("TLSv1", "TLSv1.1"):
        found.append(_finding("T001", f"Weak TLS protocol {proto}", "high",
                              f"Negotiated {proto}.", "CWE-327",
                              "Disable TLS < 1.2; prefer TLS 1.3."))
    if info.get("not_after"):
        found.append(_finding("I002", "TLS certificate present", "info",
                              f"notAfter={info['not_after']}, issuer={info.get('issuer', {}).get('organizationName', '?')}",
                              "CWE-000", "No action - informational."))
    return found


def check_paths(base_url: str, limiter) -> list:
    found = []
    for path in COMMON_PATHS:
        limiter.wait()
        resp = httpc.request(base_url.rstrip("/") + path)
        if resp.get("ok") and resp.get("status") == 200 and len(resp.get("body", "")) > 0:
            sev = "critical" if any(p in path for p in ("/.env", "/.git/", "backup")) else "medium"
            fid = "P001" if sev == "critical" else "P002"
            found.append(_finding(
                fid, f"Sensitive path exposed: {path}", sev,
                f"GET {path} -> 200 with {len(resp['body'])} bytes.", "CWE-538",
                "Remove or deny access to internal/backup paths at the edge."))
    return found


def extract_forms(html: str) -> list:
    forms = []
    for match in re.finditer(r"<form[^>]*>(.*?)</form>", html, re.I | re.S):
        block = match.group(1)
        action = re.search(r"action=[\"']?([^\"' >]+)", block, re.I)
        has_input = re.search(r"<input", block, re.I)
        forms.append({"action": action.group(1) if action else "", "has_input": bool(has_input)})
    return forms


def check_xss_reflected(base_url: str, limiter) -> list:
    """Light probe: inject marker into a reflected query param on the homepage."""
    found = []
    sep = "&" if "?" in base_url else "?"
    probe_url = f"{base_url}{sep}q={XSS_PROBE}"
    limiter.wait()
    resp = httpc.request(probe_url)
    if resp.get("ok") and XSS_MARKER in resp.get("body", "") and "<script>omni_probe()" in resp["body"]:
        found.append(_finding(
            "X001", "Reflected input rendered without encoding", "high",
            f"Marker from query param reflected verbatim at {probe_url[:120]}", "CWE-79",
            "HTML-encode reflected values; add CSP as defense-in-depth."))
    return found


def scan_web(target: str, rate_limit: float = 1.0) -> dict:
    """Full web scan. Returns bridge-compatible result dict."""
    parsed = urlparse(target if "://" in target else f"https://{target}")
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    host = parsed.netloc
    limiter = httpc.RateLimiter(rate_limit)

    findings = []

    limiter.wait()
    resp = httpc.request(base_url)
    if not resp.get("ok"):
        return {"command": "scan", "platform": "web", "target": target,
                "ok": False, "error": f"unreachable: {resp.get('error')}",
                "findings": [], "stats": {"requests": 1}}

    findings += check_headers(resp)
    findings += check_tls(host)

    if parsed.scheme != "https":
        findings.append(_finding("T002", "Target served over plaintext HTTP", "high",
                                 f"{base_url} uses scheme {parsed.scheme}.", "CWE-319",
                                 "Serve and redirect to HTTPS."))

    findings += check_paths(base_url, limiter)
    findings += check_xss_reflected(base_url, limiter)

    for form in extract_forms(resp.get("body", "")):
        findings.append(_finding("I003", "HTML form discovered", "info",
                                 f"form action={form['action'] or '(self)'} inputs={form['has_input']}",
                                 "CWE-000", "Review form handling server-side."))

    requests_made = 1 + len(COMMON_PATHS) + 1
    return {
        "command": "scan", "platform": "web", "target": target, "ok": True,
        "findings": _sort(findings),
        "stats": {"requests": requests_made,
                  "critical": sum(1 for f in findings if f["severity"] == "critical"),
                  "high": sum(1 for f in findings if f["severity"] == "high"),
                  "total": len(findings)},
    }
