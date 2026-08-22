"""Local HTTP fixture: deterministic vulnerable-ish target for tests.

Serves on 127.0.0.1:<random free port>:
- /            : HTML page missing all security headers, echoes ?q= unencoded
- /.env        : 200 with secrets-looking content (critical path finding)
- /robots.txt  : 200
- /admin       : 200
- everything else: 404
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = """<html><head><title>fixture</title></head><body>
<h1>Fixture</h1>
<a href="/search">search</a>
<a href="/about">about</a>
<form action="/search" method="get"><input name="q"></form>
</body></html>"""
SEARCH_PAGE = "<html><body>results for [{}]</body></html>"
ABOUT_PAGE = "<html><body>about us</body></html>"


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence test output
        pass

    def _send(self, code, body, content_type="text/html"):
        payload = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs, urlencode
        path = self.path.split("?")[0]
        if self.path.startswith("/?") or path == "/":
            self._send(200, PAGE + (self.path[self.path.find("?"):] if "?" in self.path else ""))
        elif path == "/search":
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            # reflects q verbatim inside brackets - XSS probe target
            self._send(200, SEARCH_PAGE.format(q))
        elif path == "/about":
            self._send(200, ABOUT_PAGE)
        elif path == "/.env":
            self._send(200, "SECRET_KEY=abc123\nDB_PASSWORD=hunter2\n")
        elif path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin\n", "text/plain")
        elif path == "/admin":
            self._send(200, "<html>admin panel</html>")
        else:
            self._send(404, "not found")


class FixtureServer:
    def __init__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
