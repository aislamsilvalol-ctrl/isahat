"""A deliberately insecure demo app for IsaHat's own tests and demos.

Runs on the Python standard library alone (no dependencies). It intentionally
ships common misconfigurations so IsaHat has something realistic to find:

* no security headers (CSP/HSTS/etc.);
* an insecure session cookie (no Secure/HttpOnly/SameSite);
* an exposed ``/.env`` and ``/.git/HEAD``;
* a version-disclosing ``Server`` header.

!!! Never expose this app on a public network. It exists only for local labs.
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_INDEX = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>IsaHat Lab — Vulnerable App</title>
    <meta name="generator" content="LabCMS 1.2.3" />
  </head>
  <body>
    <h1>IsaHat Lab</h1>
    <p>Deliberately insecure demo. See <a href="/dashboard">dashboard</a> and
       <a href="/login">login</a>.</p>
  </body>
</html>
"""

_DASHBOARD = """<!doctype html><html><head><title>Dashboard</title></head>
<body><h1>Dashboard</h1><a href="/api/users">users api</a></body></html>
"""

_ENV_FILE = "DATABASE_URL=postgres://user:password@localhost/app\nAPI_KEY=sk_live_abc123\n"
_GIT_HEAD = "ref: refs/heads/main\n"


class VulnerableHandler(BaseHTTPRequestHandler):
    server_version = "LabServer/1.0.0"  # version disclosure on purpose
    sys_version = ""

    def _send(self, status: int, body: str, content_type: str = "text/html") -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        # Intentionally missing: CSP, HSTS, X-Content-Type-Options, etc.
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        if self.path in ("/", "/index.html"):
            # Insecure cookie on purpose (no Secure/HttpOnly/SameSite).
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "session=abc123def456; Path=/")
            body = _INDEX.encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/dashboard":
            self._send(200, _DASHBOARD)
        elif self.path == "/api/users":
            self._send(200, '{"users":[{"id":1,"email":"a@example.com"}]}', "application/json")
        elif self.path == "/login":
            self._send(200, "<!doctype html><html><body><form></form></body></html>")
        elif self.path == "/.env":
            self._send(200, _ENV_FILE, "text/plain")
        elif self.path == "/.git/HEAD":
            self._send(200, _GIT_HEAD, "text/plain")
        else:
            self._send(404, "<!doctype html><html><body>not found</body></html>")

    def log_message(self, *_args: object) -> None:  # silence request logging
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="IsaHat vulnerable lab app")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8123)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), VulnerableHandler)
    print(f"IsaHat lab app listening on http://{args.host}:{args.port} (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
