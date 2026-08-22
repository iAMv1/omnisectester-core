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
<form action="/search" method="get"><input name="q"></form>
</body></html>"""


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
        path = self.path.split("?")[0]
        if self.path.startswith("/?") or path == "/":
            # reflect q= verbatim (XSS probe target)
            self._send(200, PAGE + (self.path[self.path.find("?"):] if "?" in self.path else ""))
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
