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
    "/.env", "/.git/config", "/backup.zip",
    "/admin", "/phpinfo.php", "/wp-login.php", "/.DS_Store", "/server-status",
]

# Content signatures: a 200 alone proves nothing on SPAs whose catch-all
# route serves the app shell for every path (measured on Juice Shop:
# /.env, /backup.zip, /phpinfo.php all returned the same index.html).
# A path counts as exposed only if the body differs from that shell AND
# matches the artifact's expected content signature.
PATH_SIGNATURES = {
    "/.env": re.compile(r"^[A-Za-z_][A-Za-z0-9_]{2,}\s*=", re.M),
    "/.git/config": re.compile(r"\[core\]"),
    "/admin": re.compile(r"<title>|login|dashboard|sign in|administrator", re.I),
    "/phpinfo.php": re.compile(r"phpinfo\(\)|PHP Version", re.I),
    "/wp-login.php": re.compile(r"wp-admin|user_login|wordpress", re.I),
    "/server-status": re.compile(
        r"Apache Server Status|Server uptime|Server Version", re.I),
}
BINARY_PATHS = {"/backup.zip", "/.DS_Store"}

XSS_PROBE = "<script>omni_probe()</script>"
XSS_MARKER = "omni_probe"
REFLECTION_MARKER = "omni_probe7x"


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


def _cert_days_remaining(not_after: str):
    """Parse SSL 'Mar 12 23:59:59 2027 GMT' style dates -> (days, error)."""
    from datetime import datetime, timezone
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT",
                "%Y-%m-%dT%H:%M:%SZ"):
        try:
            expiry = datetime.strptime(not_after.strip(), fmt).replace(
                tzinfo=timezone.utc)
            return (expiry - datetime.now(timezone.utc)).days, None
        except ValueError:
            continue
    return None, f"unparseable date: {not_after}"


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
    not_after = info.get("not_after")
    if not_after:
        days_left, parse_err = _cert_days_remaining(not_after)
        if parse_err is None:
            if days_left < 0:
                found.append(_finding("T005", "TLS certificate EXPIRED", "critical",
                                      f"Expired {-days_left} days ago ({not_after}).",
                                      "CWE-298", "Renew the certificate immediately."))
            elif days_left <= 30:
                sev = "high" if days_left <= 14 else "medium"
                found.append(_finding("T004", f"TLS cert expires in {days_left} days",
                                      sev, f"notAfter={not_after}.", "CWE-298",
                                      "Renew the certificate."))
            else:
                found.append(_finding("I002", "TLS certificate valid", "info",
                                      f"Expires in {days_left} days ({not_after}).",
                                      "CWE-000", "No action - informational."))
        else:
            found.append(_finding("I002", "TLS certificate present", "info",
                                  f"notAfter={not_after} (issuer "
                                  f"{info.get('issuer', {}).get('organizationName', '?')}).",
                                  "CWE-000", "No action - informational."))
    return found


def _catch_all_baseline(base_url: str, limiter) -> int | None:
    """Length of the SPA/app-shell body served for nonexistent paths.
    Returns None when the server 404s random paths (no catch-all)."""
    from uuid import uuid4
    nonce = f"/omnisectester-baseline-{uuid4().hex[:12]}"
    limiter.wait()
    resp = httpc.request(base_url.rstrip("/") + nonce)
    if resp.get("ok") and resp.get("status") == 200:
        return len(resp.get("body", ""))
    return None


def check_paths(base_url: str, limiter) -> list:
    found = []
    baseline_len = _catch_all_baseline(base_url, limiter)
    for path in COMMON_PATHS:
        limiter.wait()
        resp = httpc.request(base_url.rstrip("/") + path)
        if not (resp.get("ok") and resp.get("status") == 200):
            continue
        body = resp.get("body", "")
        if not body:
            continue
        # Catch-all filter: same-size shell as a random nonce path.
        if baseline_len is not None and abs(len(body) - baseline_len) <= max(
                64, int(0.05 * baseline_len)):
            continue
        looks_html = bool(re.search(
            r"<html|<!doctype html", body[:512], re.I))
        if path in BINARY_PATHS:
            # Backup/archive artifacts must not arrive as an HTML shell,
            # and zip archives must carry the PK magic.
            if looks_html:
                continue
            if path == "/backup.zip" and "PK\x03\x04" not in body:
                continue
        else:
            sig = PATH_SIGNATURES.get(path)
            if sig is not None and not sig.search(body):
                continue
            if sig is None and looks_html and path not in ("/admin",):
                # Unsignatured text artifacts served as HTML are suspect.
                continue
        sev = "critical" if any(p in path for p in ("/.env", "/.git/", "backup")) else "medium"
        fid = "P001" if sev == "critical" else "P002"
        found.append(_finding(
            fid, f"Sensitive path exposed: {path}", sev,
            f"GET {path} -> 200 with {len(body)} bytes (content signature "
            f"matched; differs from app shell).", "CWE-538",
            "Remove or deny access to internal/backup paths at the edge."))
    return found


SUSPICIOUS_REDIRECT_PARAMS = {"url", "redirect", "redirect_uri", "next",
                              "target", "rurl", "return", "returnurl", "goto"}

# Browser-like script parsing: a <script> block ends at the FIRST closing
# tag. SPAs hydrate state into inline <script> JSON and may echo arbitrary
# query params verbatim there; such reflections render inert, so they must
# not be reported as XSS.
_SCRIPT_BLOCK = re.compile(r"<script\b[^>]*>.*?</script\s*>", re.I | re.S)
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
def _reflection_confirmed(body: str, marker: str,
                          content_type: str = "") -> bool:
    """True when `marker` lands in executable markup context.

    Only HTML/XML responses can execute injected markup: JSON or plain
    text bodies render inert (e.g. echo endpoints like httpbin /post
    return the payload inside a JSON string - not XSS).
    On top of that, a verbatim reflection must FORM its own <script>
    block; markers merely echoed inside existing inline scripts (SPA
    state hydration) or comments do not execute either. Parsing mirrors
    browsers: a block ends at the first closing tag.
    """
    ct = (content_type or "").lower()
    if ct and "html" not in ct and "xml" not in ct:
        return False
    if marker not in body:
        return False

    def _keep(match):
        core = re.sub(r"</?\s*script\b[^>]*>", "", match.group(0),
                      flags=re.I).strip()
        # A block consisting solely of the payload is the injected
        # artifact itself - keep it. Anything bigger is host code.
        return match.group(0) if core in ("omni_probe()", REFLECTION_MARKER) else ""

    stripped = _HTML_COMMENT.sub("", _SCRIPT_BLOCK.sub(_keep, body))
    return marker in stripped and "<script>" in stripped.lower()


def check_open_redirect(base_url: str, probe_targets: list, limiter) -> list:
    """For discovered params named like redirect sinks, inject an external
    absolute URL and inspect the response Location header."""
    from urllib.parse import urlencode
    found = []
    external = "https://omnisectester-redirect-probe.example/"
    for pt in probe_targets:
        param = pt["param"].lower()
        if param not in SUSPICIOUS_REDIRECT_PARAMS:
            continue
        probe_url = f"{base_url.rstrip('/')}{pt['path']}?{urlencode({pt['param']: external})}"
        limiter.wait()
        resp = httpc.request_nofollow(probe_url)
        location = (resp.get("headers") or {}).get("location", "")
        if resp.get("ok") and location.startswith("http") \
                and "omnisectester-redirect-probe.example" in location:
            finding = _finding(
                "R001", f"Open redirect via `{pt['param']}`", "high",
                f"{probe_url[:120]} -> Location: {location[:120]}", "CWE-601",
                "Validate redirect destinations against an allowlist; "
                "prefer relative paths.")
            finding["poc"] = f"curl -sI '{probe_url}' | grep -i '^location:'"
            finding["url"] = probe_url
            found.append(finding)
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
    if resp.get("ok") and _reflection_confirmed(
            resp.get("body", ""), XSS_MARKER,
            (resp.get("headers") or {}).get("content-type", "")):
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


def check_cookie_flags(resp) -> list:
    """Audit Set-Cookie attributes: Secure, HttpOnly, SameSite."""
    found = []
    raw = [v for k, v in (resp.get("headers") or {}).items()
           if k.lower() == "set-cookie"]
    for sc in raw:
        name = sc.split("=")[0].strip()
        low = sc.lower()
        if "secure" not in low:
            found.append(_finding("C001", f"Cookie `{name}` missing Secure", "medium",
                                  f"Set-Cookie without Secure: {sc[:120]}", "CWE-614",
                                  "Add the Secure attribute."))
        if "httponly" not in low:
            found.append(_finding("C002", f"Cookie `{name}` missing HttpOnly", "low",
                                  f"Set-Cookie without HttpOnly: {sc[:120]}", "CWE-1004",
                                  "Add HttpOnly to block script access."))
        if "samesite" not in low:
            found.append(_finding("C003", f"Cookie `{name}` missing SameSite", "low",
                                  f"Set-Cookie without SameSite: {sc[:120]}", "CWE-1275",
                                  "Add SameSite=Lax or Strict."))
    return found


def check_post_forms(forms: list, base_url: str) -> list:
    """Static POST-form audit: CSRF presence + transport security."""
    found = []
    for f in forms:
        if f["method"] != "POST":
            continue
        action = f["action"] or base_url
        if action.startswith("http://"):
            found.append(_finding(
                "T003", "Form submits over plaintext HTTP", "high",
                f"POST {action} (fields: {', '.join(f['fields'][:5]) or 'n/a'})",
                "CWE-319", "Serve the form and its action endpoint over HTTPS."))
        if f["fields"] and not any(re.search(r"csrf|token|nonce|_token", x, re.I)
                                   for x in f["fields"]):
            found.append(_finding(
                "F001", "POST form without visible CSRF token", "medium",
                f"Static markup audit: POST {action} fields={f['fields']} "
                f"shows no csrf/token/nonce field. Forms that add tokens "
                f"via JS at submit time are out of scope for this check.",
                "CWE-352",
                "Add per-session CSRF tokens and verify server-side."))
    return found


def probe_post_reflection(forms: list, limiter) -> list:
    """Submit marker into the first field of each POST form; flag verbatim
    reflection with a curl PoC."""
    from urllib.parse import urlencode
    found = []
    for f in forms:
        if f["method"] != "POST" or not f["fields"]:
            continue
        data = urlencode({f["fields"][0]: f"<script>{REFLECTION_MARKER}</script>"})
        limiter.wait()
        resp = httpc.request(f["action"], method="POST", data=data.encode(),
                             headers={"Content-Type": "application/x-www-form-urlencoded"})
        if resp.get("ok") and REFLECTION_MARKER in resp.get("body", "") \
                and _reflection_confirmed(
                    resp.get("body", ""), REFLECTION_MARKER,
                    (resp.get("headers") or {}).get("content-type", "")):
            finding = _finding(
                "X002", f"Reflected XSS via POST `{f['fields'][0]}`", "high",
                "POST body value echoed verbatim.", "CWE-79",
                "Encode on output; validate input; consider SameSite+CSRF.")
            finding["poc"] = (
                f"curl -s -X POST '{f['action']}' "
                f"-d '{data}' | grep -F '{REFLECTION_MARKER}'")
            finding["url"] = f["action"]
            found.append(finding)
    return found
