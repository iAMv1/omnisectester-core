"""The scanning agent: perceive -> decide -> act -> validate -> report.

Phases (threat model runs FIRST - a project promise):
  1. model     initial STRIDE pass from seed facts
  2. crawl     discover the real attack surface (crawler.py)
  3. probe     headers on every page; reflected-XSS per discovered
               GET param; sensitive paths; plaintext checks
  4. validate  every reflection finding gets an executable curl PoC
  5. report    de-duplicated findings + surface stats + updated TM

Deterministic: same target + budget => same result.
"""

from urllib.parse import urlparse

from . import crawler as crawler_mod
from . import httpc
from .scanner import (_finding, _sort, check_paths, check_tls, check_post_forms,
                      probe_post_reflection, SECURITY_HEADERS)
from .threatmodel import build_threat_model

DEFAULT_BUDGET = 60          # max total HTTP requests for the whole agent run
REFLECTION_MARKER = "omni_probe7x"


def _curl_poc(url: str) -> str:
    return f"curl -s '{url}' | grep -F '{REFLECTION_MARKER}'   # non-empty = vulnerable"


def _probe_reflection(url: str, path: str, param: str, limiter) -> list:
    from urllib.parse import urlencode
    probe_url = f"{url.rstrip('/')}{path}?{urlencode({param: '<script>' + REFLECTION_MARKER + '</script>'})}"
    limiter.wait()
    resp = httpc.request(probe_url)
    if resp.get("ok") and REFLECTION_MARKER in resp.get("body", "") \
            and f"<script>{REFLECTION_MARKER}" in resp["body"]:
        finding = _finding(
            "X001", f"Reflected XSS via `{param}`", "high",
            f"{len(resp['body'])}B response echoes param verbatim.",
            "CWE-79",
            "Context-encode output; CSP defense-in-depth.")
        finding["poc"] = _curl_poc(probe_url)
        finding["url"] = probe_url
        return [finding]
    return []


def _headers_on_page(page_url: str, limiter, header_miss_counter: dict) -> None:
    limiter.wait()
    resp = httpc.request(page_url)
    if not resp.get("ok"):
        return
    for header, sev, fid, title, cwe, fix in SECURITY_HEADERS:
        if header not in resp["headers"]:
            header_miss_counter[fid] = header_miss_counter.get(fid, 0) + 1


def run_agent(target: str, rate_limit: float = 4.0, max_pages: int = 25,
              fail_on: str = "none", budget: int = DEFAULT_BUDGET,
              auth_type: str = "none", auth_token=None) -> dict:
    limiter = httpc.RateLimiter(rate_limit)
    if auth_type != "none" and auth_token:
        httpc.set_auth(auth_type, auth_token)

    # ---- phase 1: threat model BEFORE any testing (project promise) ----
    tm = build_threat_model(target)

    # ---- phase 2: crawl ----
    surface = crawler_mod.crawl(target, max_pages=max_pages, rate_limit=rate_limit)

    # ---- phase 3: probe (budget-aware) ----
    findings = []
    used = surface["stats"]["requests"]

    def budget_left():
        return max(0, budget - used)

    # headers across discovered pages (capped by remaining budget)
    misses = {}
    for page in surface["pages"]:
        if budget_left() <= 0:
            break
        before = used
        _headers_on_page(page["url"], limiter, misses)
        used += 1
    for fid, count in sorted(misses.items()):
        meta = next(m for m in SECURITY_HEADERS if m[2] == fid)
        sev = "medium" if count == len(surface["pages"]) else "low"
        findings.append(_finding(
            fid, meta[3] + f" ({count}/{len(surface['pages'])} pages)", sev,
            f"Missing on {count} of {len(surface['pages'])} crawled pages.",
            meta[4], meta[5]))

    base_findings_probe = urlparse(target if "://" in target else f"https://{target}")
    if base_findings_probe.scheme != "https":
        findings.append(_finding("T002", "Target served over plaintext HTTP", "high",
                                 f"{surface['base']} uses {base_findings_probe.scheme}.",
                                 "CWE-319", "Serve and redirect to HTTPS."))
    tls_findings = check_tls(base_findings_probe.netloc)
    findings += tls_findings
    if tls_findings or base_findings_probe.scheme != "https":
        used += 1

    # reflected XSS on DISCOVERED param endpoints (the agentic part:
    # these were never hardcoded)
    skipped_probes = 0
    for pt in surface["probe_targets"]:
        if budget_left() <= 0:
            skipped_probes += 1
            continue
        found = _probe_reflection(surface["base"], pt["path"], pt["param"], limiter)
        used += 1
        findings += found
    if skipped_probes:
        findings.append(_finding(
            "W001", "Probe budget exhausted", "info",
            f"{budget}-request budget reached with {skipped_probes} of "
            f"{len(surface['probe_targets'])} param endpoints left unprobed.",
            "CWE-000", "Raise the budget or --max-pages, or narrow scope."))

    # sensitive paths still worth checking once
    if budget_left() > 0:
        findings += check_paths(surface["base"], limiter)

    # POST forms: CSRF/plaintext audit + authenticated reflection probe
    findings += check_post_forms(surface["forms"], surface["base"])
    for f in surface["forms"]:
        if budget_left() <= 0:
            break
        if f["method"] == "POST" and f["fields"]:
            findings += probe_post_reflection([f], limiter)
            used += 1

    # ---- phase 4/5: dedupe + validate + refresh TM ----
    dedup = {}
    for f in findings:
        key = (f["id"], f["title"])
        if key in dedup:
            dedup[key]["evidence"] += f" | x{1}"
        else:
            dedup[key] = f
    final = _sort(dedup.values())

    # TM relevance now reflects observations (forms found -> tampering high etc.)
    facts = {
        "forms": len(surface["forms"]),
        "params": len(surface["probe_targets"]),
        "plaintext": base_findings_probe.scheme != "https",
    }
    tm_updated = build_threat_model(
        target, adversary=tm.get("adversary_profiles"),
        frameworks=tm.get("frameworks"), observed=facts)

    counts = {s: sum(1 for f in final if f["severity"] == s)
              for s in ("critical", "high", "medium", "low", "info")}
    return {
        "command": "scan", "platform": "web", "target": target, "ok": True,
        "agent": {"phases": ["model", "crawl", "probe", "validate", "report"],
                  "budget": budget, "requests_used": used},
        "surface": {"pages_crawled": surface["stats"]["pages_crawled"],
                    "forms": surface["stats"]["forms"],
                    "param_endpoints": surface["stats"]["param_endpoints"],
                    "probe_targets": surface["probe_targets"]},
        "threat_model": tm_updated,
        "findings": final,
        "stats": {"requests": used, "total": len(final), **counts},
    }
