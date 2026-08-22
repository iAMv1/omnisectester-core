"""Same-origin crawler: discovers pages, links, query params, and forms.

This is what upgrades the scanner from a fixed checklist to an agent:
the attack surface is DISCOVERED from the target, not assumed.
"""

import re
from collections import deque
from urllib.parse import urljoin, urlparse, parse_qsl

from . import httpc

LINK_RE = re.compile(r"<a[^>]+href=[\"']?([^\"' >]+)", re.I)
FORM_RE = re.compile(r"<form([^>]*)>(.*?)</form>", re.I | re.S)
INPUT_RE = re.compile(r"<input[^>]*>", re.I)
NAME_RE = re.compile(r"name=[\"']?([^\"' >]+)", re.I)
ACTION_RE = re.compile(r"action=[\"']?([^\"' >]+)", re.I)
METHOD_RE = re.compile(r"method=[\"']?(get|post)", re.I)


def _same_origin(url, base_netloc):
    try:
        return urlparse(url).netloc in ("", base_netloc)
    except ValueError:
        return False


def crawl(seed_url: str, max_pages: int = 25, rate_limit: float = 4.0) -> dict:
    """BFS crawl within origin. Returns an attack-surface map."""
    parsed = urlparse(seed_url if "://" in seed_url else f"https://{seed_url}")
    base = f"{parsed.scheme}://{parsed.netloc}"
    netloc = parsed.netloc

    limiter = httpc.RateLimiter(rate_limit)
    queue = deque([base + (parsed.path or "/")])
    seen = set()
    pages = []          # [{url, status, links_count}]
    params = {}         # path -> set(query param names observed)
    forms = []          # {page, action, method, fields[]}
    requests_made = 0

    while queue and len(pages) < max_pages:
        url = queue.popleft()
        norm = url.split("#")[0]
        if norm in seen:
            continue
        seen.add(norm)

        limiter.wait()
        resp = httpc.request(norm)
        requests_made += 1
        if not resp.get("ok") or resp.get("status", 500) >= 400:
            continue

        body = resp.get("body", "")
        pages.append({"url": norm, "status": resp["status"], "bytes": len(body)})

        for qs_name, _val in parse_qsl(urlparse(norm).query, keep_blank_values=True):
            params.setdefault(urlparse(norm).path, set()).add(qs_name)

        for href in LINK_RE.findall(body):
            absolute = urljoin(norm, href.split("#")[0])
            if _same_origin(absolute, netloc) and absolute not in seen:
                queue.append(absolute)

        for fm in FORM_RE.finditer(body):
            attrs, block = fm.group(1), fm.group(2)
            action_raw = ACTION_RE.search(attrs)
            action = urljoin(norm, action_raw.group(1)) if action_raw else norm
            method_m = METHOD_RE.search(attrs)
            method = (method_m.group(1) if method_m else "get").upper()
            fields = [n.group(1) for n in (NAME_RE.search(inp) for inp in INPUT_RE.findall(block)) if n]
            forms.append({"page": norm, "action": action, "method": method, "fields": fields})
            if method == "GET":
                target_path = urlparse(action).path or "/"
                params.setdefault(target_path, set()).update(fields)

    # param-bearing endpoints are prime probe targets - sorted for determinism
    probe_targets = []
    for path, names in sorted(params.items()):
        for name in sorted(names):
            probe_targets.append({"path": path, "param": name})

    return {
        "base": base,
        "pages": pages,
        "forms": forms,
        "probe_targets": probe_targets,
        "stats": {"pages_crawled": len(pages), "requests": requests_made,
                  "forms": len(forms), "param_endpoints": len(probe_targets)},
    }
