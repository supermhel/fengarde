"""Live nginx check for the WS-7 template (opt-in, needs Docker).

`test_fix_read_plane.py` only proves strings exist in the template. This
runs the REAL pinned nginx image with the rendered template (`nginx -t`),
puts stub upstreams on a Docker network under the real service names, and
sends real requests, so location precedence and the auth_request gates are
proven, not just present (PR #175 review).

Not part of run_all_tests.sh (the gate is zero-infra). Run:
    python services/ws7-dashboard/live_nginx_check.py
"""
from __future__ import annotations

import json
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEMPLATE = HERE / "templates" / "default.conf.template"
NGINX = "nginx:alpine@sha256:4a73073bd557c65b759505da037898b61f1be6cbcc3c2c3aeac22d2a470c1752"
PY = "python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de"
ENV = {"DASHBOARD_AUTH_REALM": "off", "WS3_TRIAGE_PORT": "8013", "OPENSEARCH_HOST": "opensearch:9200"}

# One stub serves every upstream: echoes who it is and the path it received.
# /auth/check-admin: 200 admin key, 403 analyst key, 401 otherwise.
STUB = r'''
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
NAME, PORT = sys.argv[1], int(sys.argv[2])
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        key = self.headers.get("X-Api-Key")
        code = 200
        if self.path.startswith("/auth/check-admin"):
            code = {"admin-key": 200, "analyst-key": 403}.get(key, 401)
        body = json.dumps({"stub": NAME, "path": self.path}).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
HTTPServer(("0.0.0.0", PORT), H).serve_forever()
'''

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def docker(*args: str, check_rc: bool = True) -> str:
    out = subprocess.run(["docker", *args], capture_output=True, text=True)
    if check_rc and out.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args[:3])}... failed: {out.stderr.strip()}")
    return out.stdout.strip()


def get(port: int, path: str, key: str | None = None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                 headers={"X-Api-Key": key} if key else {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read().decode("utf-8", "replace")
            return r.status, body
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def stub_of(body: str):
    try:
        return json.loads(body)
    except ValueError:
        return {}


def main() -> None:
    tag = "fgnx-" + secrets.token_hex(4)
    net, containers = tag, []
    docker("network", "create", net)
    try:
        for name, port in (("ws3-indexer", 8013), ("ws1-collectors", 8001), ("ws5-ai", 8005)):
            cid = docker("run", "-d", "--rm", "--network", net, "--network-alias", name,
                         PY, "python", "-c", STUB, name, str(port))
            containers.append(cid)
        env = [x for k, v in ENV.items() for x in ("-e", f"{k}={v}")]
        mount = f"{TEMPLATE}:/etc/nginx/templates/default.conf.template:ro"
        syntax = subprocess.run(["docker", "run", "--rm", "-v", mount, *env, NGINX, "nginx", "-t"],
                                capture_output=True, text=True)
        check(syntax.returncode == 0, f"nginx -t failed: {syntax.stderr[-400:]}")
        cid = docker("run", "-d", "--rm", "--network", net, "-p", "127.0.0.1::80", "-v", mount, *env, NGINX)
        containers.append(cid)
        port = int(docker("port", cid, "80/tcp").splitlines()[0].rsplit(":", 1)[1])
        for _ in range(50):
            try:
                get(port, "/")
                break
            except OSError:
                time.sleep(0.2)

        # admin-only ops routes: auth_request really gates them
        check(get(port, "/api/ops/ws1")[0] == 401, "/api/ops/ws1 anonymous must be 401")
        check(get(port, "/api/ops/ws1", "analyst-key")[0] == 403, "/api/ops/ws1 analyst must be 403")
        code, body = get(port, "/api/ops/ws1", "admin-key")
        check(code == 200 and stub_of(body) == {"stub": "ws1-collectors", "path": "/metrics"},
              f"/api/ops/ws1 admin must reach ws1 /metrics: {code} {body[:120]}")
        code, body = get(port, "/api/ops/ws5", "admin-key")
        check(stub_of(body).get("stub") == "ws5-ai", f"/api/ops/ws5 admin: {code} {body[:120]}")
        # exact match: longer paths never reach the health port (review finding)
        for p in ("/api/ops/ws1/anything", "/api/ops/ws10", "/api/ops/ws1/"):
            code, body = get(port, p, "admin-key")
            check(stub_of(body).get("stub") != "ws1-collectors",
                  f"{p} must not be proxied to the ws1 health port: {code} {body[:120]}")
        # console feeds go through ws3's tenant-scoped /dashboard routes
        for front, back in (("/api/alerts", "/dashboard/alerts"), ("/api/ai-triage", "/dashboard/ai-triage")):
            code, body = get(port, front)
            check(stub_of(body).get("path", "").startswith(back),
                  f"{front} must proxy to ws3 {back}: {code} {body[:120]}")
    finally:
        for c in containers:
            docker("rm", "-f", c, check_rc=False)
        docker("network", "rm", net, check_rc=False)

    if FAILS:
        print(f"[FAIL] live nginx check: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] live nginx: nginx -t passes; /api/ops/* admin-gated (401/403/200) and exact-match; "
          "console feeds proxy to ws3 /dashboard/* -- real nginx, real requests")


if __name__ == "__main__":
    main()
