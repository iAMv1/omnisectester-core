"""Stdlib HTTP client with rate limiting, TLS inspection, and timeouts.

No third-party dependencies: urllib + ssl + json only (v0.1.0 constraint).
"""

import json
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request


class RateLimiter:
    """Thread-safe minimum-interval rate limiter."""

    def __init__(self, requests_per_second: float = 1.0):
        self._min_interval = 1.0 / max(requests_per_second, 0.01)
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self):
        with self._lock:
            now = time.monotonic()
            delta = self._min_interval - (now - self._last)
            if delta > 0:
                time.sleep(delta)
            self._last = time.monotonic()


def tls_info(host: str, port: int = 443, timeout: float = 8.0) -> dict:
    """Inspect a TLS endpoint: protocol version, cipher, cert subject/issuer/dates."""
    result = {"enabled": False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                result = {
                    "enabled": True,
                    "protocol": tls.version(),
                    "cipher": tls.cipher()[0] if tls.cipher() else None,
                    "subject": dict(x[0] for x in cert.get("subject", [])) if cert else {},
                    "issuer": dict(x[0] for x in cert.get("issuer", [])) if cert else {},
                    "not_after": cert.get("notAfter") if cert else None,
                }
    except Exception as exc:  # noqa: BLE001 - report, don't crash scans
        result["error"] = str(exc)
    return result


def request(url: str, method: str = "GET", headers: dict | None = None,
            timeout: float = 10.0) -> dict:
    """Perform one HTTP request and normalize the response into a dict."""
    req = urllib.request.Request(url, method=method, headers=headers or {},
                                 data=None)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(262144).decode("utf-8", errors="replace")
            return {
                "ok": True,
                "status": resp.status,
                "headers": {k.lower(): v for k, v in resp.headers.items()},
                "body": body,
                "url": resp.url,
            }
    except urllib.error.HTTPError as exc:
        return {
            "ok": True,
            "status": exc.code,
            "headers": {k.lower(): v for k, v in exc.headers.items()},
            "body": (exc.read(262144) or b"").decode("utf-8", errors="replace"),
            "url": url,
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "url": url}


def fetch_json(url: str, timeout: float = 8.0):
    """GET a URL and parse JSON; returns (parsed, error_string)."""
    resp = request(url, timeout=timeout)
    if not resp.get("ok") or resp.get("status") != 200:
        return None, resp.get("error", f"HTTP {resp.get('status')}")
    try:
        return json.loads(resp["body"]), None
    except ValueError as exc:
        return None, str(exc)
