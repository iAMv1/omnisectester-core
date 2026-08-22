"""Website deepening probes: HTTP methods, TRACE, security.txt."""

from . import httpc
from .scanner import _finding


def check_http_methods(base_url: str, limiter) -> tuple:
    """OPTIONS audit: dangerous verbs advertised; TRACE probed directly.
    Returns (findings, requests_made)."""
    found = []
    requests = 0
    limiter.wait()
    resp = httpc.request(base_url, method="OPTIONS")
    requests += 1
    allow = (resp.get("headers") or {}).get("allow", "")
    if allow:
        verbs = {v.strip().upper() for v in allow.split(",") if v.strip()}
        dangerous = verbs & {"PUT", "DELETE", "TRACE", "CONNECT"}
        if dangerous:
            found.append(_finding(
                "H007", f"Dangerous HTTP methods allowed: "
                        f"{', '.join(sorted(dangerous))}", "medium",
                f"OPTIONS Allow header lists {sorted(verbs)}.",
                "CWE-650",
                "Disable unused methods at the server/proxy level."))
    # TRACE directly: XST if status 200 and body echoed
    limiter.wait()
    trace = httpc.request(base_url, method="TRACE")
    requests += 1
    if trace.get("ok") and trace.get("status") == 200:
        found.append(_finding(
            "H008", "TRACE method enabled (Cross-Site Tracing)", "medium",
            f"TRACE {base_url} returned 200.", "CWE-693",
            "Disable TRACE at the web server."))
    return found, requests


def check_security_txt(base_url: str, limiter) -> tuple:
    """RFC 9116: /.well-known/security.txt should exist for contact.
    Returns (findings, requests_made)."""
    found = []
    requests = 0
    for path in ("/.well-known/security.txt", "/security.txt"):
        limiter.wait()
        resp = httpc.request(base_url.rstrip("/") + path)
        requests += 1
        if resp.get("ok") and resp.get("status") == 200 \
                and "contact" in resp.get("body", "").lower():
            return [], requests
    found.append(_finding(
        "W002", "No security.txt (RFC 9116)", "low",
        "No /.well-known/security.txt - researchers have no "
        "disclosure contact.", "CWE-0",
        "Publish /.well-known/security.txt with a Contact: field."))
    return found, requests
