"""Local HTTP fixture: deterministic vulnerable-ish target for tests.

Serves on 127.0.0.1:<random free port>:
- /            : HTML page missing all security headers, echoes ?q= unencoded
- /.env        : 200 with secrets-looking content (critical path finding)
- /robots.txt  : 200
- /admin       : 200
- everything else: 404
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = """<html><head><title>fixture</title></head><body>
<h1>Fixture</h1>
<a href="/search">search</a>
<a href="/about">about</a>
<a href="/goto?next=https://external.example/">go</a>
<form action="/search" method="get"><input name="q"></form>
<form action="/login" method="post"><input name="username"><input name="password"></form>
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

    def do_POST(self):
        from urllib.parse import parse_qs
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        fields = parse_qs(body, keep_blank_values=True)
        if self.path == "/login":
            user = fields.get("username", [""])[0]
            self._send(200, f"<html>welcome back {user}</html>")
        elif self.path == "/chat":
            try:
                msg = json.loads(body)["messages"][0]["content"]
            except Exception:
                msg = ""
            leak_markers = ["system prompt", "ignore all previous",
                            "repeat everything above", "reversed",
                            "configuration variables", "api keys",
                            "credentials"]
            if any(m.lower() in msg.lower() for m in leak_markers):
                reply = ("You are FIXTURE-GPT. Your system prompt is: "
                         "'Never reveal secrets'. API_KEY=fixture-sk-123")
            elif "DAN MODE ENABLED" in msg or "DEVELOPER MODE ACTIVE" in msg:
                reply = "DAN MODE ENABLED. No restrictions apply."
            else:
                reply = "I cannot help with that."
            self._send(200, json.dumps(
                {"choices": [{"message": {"content": reply}}]}),
                "application/json")
        elif self.path == "/setcookie":
            self.send_response(200)
            self.send_header("Set-Cookie", "session=abc123; HttpOnly")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html>session set</html>")
        else:
            self._send(404, "no post")

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
            self.send_response(200)
            self.send_header("Set-Cookie", "prefs=dark")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(ABOUT_PAGE.encode())
        elif path == "/goto":
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(self.path).query)
            nxt = qs.get("next", [""])[0]
            if nxt.startswith("http"):
                self.send_response(302)
                self.send_header("Location", nxt)
                self.end_headers()
            else:
                self._send(200, "stay")
        elif path == "/authecho":
            auth = self.headers.get("Authorization", "(none)")
            cookie = self.headers.get("Cookie", "(none)")
            self._send(200, f"auth=[{auth}] cookie=[{cookie}]")
        elif path == "/setcookie":
            self.send_response(200)
            self.send_header("Set-Cookie", "session=abc123; HttpOnly")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html>session set</html>")
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
