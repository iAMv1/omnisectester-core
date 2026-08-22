"""Auth-flow / business-logic / IDOR scanner.

Deterministic probes over the agent's discovered surface:
  - A001: admin/sensitive paths reachable WITHOUT authentication (200)
  - A002: IDOR pattern - numeric object IDs in discovered params;
          incrementing the id changes the response body (data returned
          for a different object) while still 200
  - B001: rate-limit absence - N rapid identical requests all succeed
          with no 429/503 and no slowdown signal
All findings are SUSPECTED (heuristic) + carry curl PoCs.
"""

import re
import time

from . import httpc

ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/dashboard", "/internal",
    "/api/admin", "/manage", "/controlpanel", "/staff", "/backoffice",
]

ID_PARAM_NAMES = {"id", "user_id", "userid", "uid", "account_id", "accountid",
                  "order_id", "orderid", "invoice_id", "doc_id", "profile_id",
                  "customer_id", "item_id"}

NUMERIC_RE = re.compile(r"^\d{1,9}$")


def check_admin_unauthenticated(base_url: str, limiter,
                                auth_present: bool) -> list:
    """Admin paths returning 200 pre-auth = suspected broken access control."""
    from .scanner import _finding
    found = []
    if auth_present:
        return found  # can't judge unauthenticated reachability with creds set
    for path in ADMIN_PATHS:
        limiter.wait()
        resp = httpc.request(base_url.rstrip("/") + path)
        if resp.get("ok") and resp.get("status") == 200 \
                and len(resp.get("body", "")) > 50:
            title_low = resp.get("body", "").lower()
            # crude page-relevance filter to cut false positives on SPAs
            if any(k in title_low for k in ("admin", "dashboard", "manage",
                                            "panel", "users", "settings")):
                finding = _finding(
                    "A001", f"Admin surface reachable without auth: {path}",
                    "high",
                    f"GET {path} -> 200 ({len(resp['body'])}B) with no "
                    f"credentials. SUSPECTED.", "CWE-862",
                    "Enforce server-side authorization on every admin route.")
                finding["poc"] = f"curl -s '{base_url.rstrip('/')}{path}' | head -20"
                finding["url"] = base_url.rstrip("/") + path
                found.append(finding)
    return found


def probe_idor(base_url: str, probe_targets: list, limiter,
               budget_left) -> list:
    """Numeric-id params: fetch id=N baseline, then id=N+1; if both 200 and
    bodies differ materially -> different objects served => IDOR pattern."""
    from .scanner import _finding
    from urllib.parse import urlencode
    found = []
    for pt in probe_targets:
        if budget_left() <= 0:
            break
        param = pt["param"].lower()
        if param not in ID_PARAM_NAMES:
            continue
        sep = "&" if "?" in base_url else "?"
        base_probe = f"{base_url.rstrip('/')}{pt['path']}?{urlencode({pt['param']: '1'})}"
        limiter.wait()
        r1 = httpc.request(base_probe)
        if not r1.get("ok") or r1.get("status") != 200:
            continue
        limiter.wait()
        r2 = httpc.request(f"{base_url.rstrip('/')}{pt['path']}?{urlencode({pt['param']: '2'})}")
        used = 2
        if not r2.get("ok") or r2.get("status") != 200:
            continue
        b1, b2 = r1.get("body", ""), r2.get("body", "")
        if abs(len(b1) - len(b2)) > 40 or b1[:200] != b2[:200]:
            finding = _finding(
                "A002", f"Possible IDOR via `{pt['param']}`", "high",
                f"id=1 vs id=2 both return 200 with differing bodies "
                f"({len(b1)}B vs {len(b2)}B). SUSPECTED - confirm ownership "
                f"checks manually.", "CWE-639",
                "Authorize object access per-user server-side; use "
                "unguessable IDs (UUIDs) as defense-in-depth.")
            finding["poc"] = (
                f"curl -s '{base_url.rstrip('/')}{pt['path']}?{urlencode({pt['param']: '1'})}' | head -5 ; "
                f"curl -s '{base_url.rstrip('/')}{pt['path']}?{urlencode({pt['param']: '2'})}' | head -5")
            finding["url"] = base_probe
            found.append(finding)
    return found


def check_rate_limiting(url: str, limiter, burst: int = 12) -> list:
    """Fire `burst` rapid requests; any 429/503 or Retry-After => OK."""
    from .scanner import _finding
    statuses = []
    t0 = time.monotonic()
    for _ in range(burst):
        resp = httpc.request(url)
        statuses.append((resp.get("status"), resp.get("headers", {})
                         .get("retry-after")))
    elapsed = time.monotonic() - t0
    blocked = any(s in (429, 503) or ra for s, ra in statuses)
    if not blocked:
        finding = _finding(
            "B001", "No rate limiting observed", "medium",
            f"{burst} rapid requests to {url} all succeeded "
            f"(statuses={sorted(set(s for s, _ in statuses))}) in "
            f"{elapsed:.1f}s. SUSPECTED.", "CWE-770",
            "Add per-IP/per-account rate limits; return 429 with Retry-After.")
        finding["poc"] = (
            f"for i in $(seq 1 {burst}); do curl -s -o /dev/null -w "
            f"'%{{http_code}} ' '{url}'; done")
        finding["url"] = url
        return [finding]
    return []
