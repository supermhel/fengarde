"""WS-7 read-plane regression test (static, no browser needed).

nginx read-plane regression for the v1 console (the legacy-console assertions
went away with the legacy UI on 2026-10-20; the React console has its own
vitest suite). WP-6.1 (owner decision, option C: sessions only) re-routed the
auth model in 2026-11-06:

  * read-plane #6 (SUPERSEDED) the /api/config.js API-key bootstrap is REMOVED.
    The browser no longer holds FENGARDE_API_KEY; the SPA does not even load
    config.js, and index.html carries no script tag for it. The API key is
    reserved for machine clients, which send X-Api-Key on their own.
  * nginx key gate (REMOVED) the blanket `if ($http_x_api_key != ...) return
    401;` guard is gone. Auth is delegated to ws3-indexer, whose _check_auth
    accepts an X-Api-Key OR an RBAC session cookie -- the single authority.
    /api/auth/* (login/me/logout/mfa) is intentionally keyless so a not-yet-
    logged-in browser can still log in.
  * auth-less upsteams (KEPT, reworded) routes that proxy to something that
    cannot check credentials itself -- OpenSearch direct reads (/api/alerts,
    /api/events, /api/ai-triage), the /api/ops/* health endpoints, and
    /api/prom/* -- now carry `auth_request /api/auth/check;`, an nginx
    subrequest to ws3 that returns 200 only when key-OR-session is valid, so
    they stay protected without re-introducing a browser-side key.
  * cache (2026-10-15) the SPA index.html is served no-cache and /assets/
    immutable, and every location that sets its own add_header repeats all
    four security headers.
  * prom (2026-10-15) /api/prom/ is a GET-only allowlist onto Prometheus:
    /api/v1/targets and /api/v1/query only, no body or credentials forwarded,
    headers inherited -- now gated by the same auth_request as the other
    auth-less upstreams.

Substring assertions plus a node --check syntax gate (test_contract.py) are
the static contract; this test proves the specific returns that greps cannot.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FAILS: list[str] = []


def check(c, m):
    if not c:
        FAILS.append(m)


def block(tpl: str, head: str) -> str:
    """Slice one location block (brace-naive: stops at the first '\\n    }\n')."""
    if head not in tpl:
        return ""
    s = tpl.index(head)
    return tpl[s:tpl.index("\n    }\n", s)]


def run():
    tpl = (HERE / "templates" / "default.conf.template").read_text(encoding="utf-8")

    # ---- WP-6.1 (option C): /api/config.js key bootstrap REMOVED --------------
    check("location = /api/config.js" not in tpl,
          "wp-6.1: /api/config.js location still exists (must be removed)")
    check("window.FENGARDE_API_KEY" not in tpl,
          "wp-6.1: template still serves window.FENGARDE_API_KEY")
    # The SPA must not even load config.js (index.html carries no script tag
    # for it). The template's own comments may LEGITIMATELY mention the
    # removed bootstrap as prose, so the gone-gate assertion is on the serving
    # lines, not on the phrase.
    idx = (HERE / "app" / "index.html").read_text(encoding="utf-8")
    check('src="/api/config.js"' not in idx,
          "wp-6.1: index.html still loads the config.js bootstrap script")
    check("/api/config.js" not in idx,
          "wp-6.1: index.html still references the config.js endpoint")

    # ---- WP-6.1: blanket nginx X-Api-Key gate REMOVED -------------------------
    check('if ($http_x_api_key != "' not in tpl,
          "wp-6.1: nginx still compares X-Api-Key itself (gate must be removed)")
    # A machine client's key must still be forwarded so ws3 can accept it.
    check("proxy_set_header X-Api-Key $http_x_api_key;" in tpl,
          "wp-6.1: machine-client X-Api-Key is no longer forwarded to ws3")

    # ---- WP-6.1: auth_request guard on the auth-less upstreams ----------------
    # OpenSearch direct-read routes (OpenSearch has no auth of its own).
    for loc in (" = /api/alerts {", " = /api/events {", " = /api/ai-triage {"):
        b = block(tpl, f"location{loc}")
        check("auth_request /api/auth/check;" in b,
              f"wp-6.1: {loc.strip()} lacks the auth_request /auth/check guard")
        check('if ($http_x_api_key != "' not in b,
              f"wp-6.1: {loc.strip()} still carries the old X-Api-Key gate")
    # Ops health endpoints + Prometheus -- auth_request too.
    for loc in ("location /api/ops/ws1 {", "location /api/ops/ws8 {",
                "location ~ ^/api/prom/api/v1/(targets|query)$ {"):
        b = block(tpl, loc)
        check("auth_request /api/auth/check;" in b,
              f"wp-6.1: {loc} lacks the auth_request /auth/check guard")
    ops_8 = block(tpl, "location /api/ops/ws8 {")
    check("auth_request /api/auth/check;" in ops_8,
          "wp-6.1: ws8 ops route is not gated behind auth_request")

    # ws3-served routes must NOT be nginx-key-gated (ws3 enforces key-or-session).
    ws3_locs = ("location /api/triage/ {", "location /api/rules {",
                "location /api/incidents {", "location /api/incidents/ {",
                "location /api/entities/ {", "location /api/audit {")
    for loc in ws3_locs:
        b = block(tpl, loc)
        check('if ($http_x_api_key != "' not in b,
              f"wp-6.1: {loc} still carries the nginx X-Api-Key gate")
    # The login/bootstrap surface must be keyless or a fresh browser could not log in.
    auth_b = block(tpl, "location /api/auth/ {")
    check("auth_request" not in auth_b,
          "wp-6.1: /api/auth/ is auth_request-gated (must stay keyless for login)")
    check('if ($http_x_api_key != "' not in auth_b,
          "wp-6.1: /api/auth/ still carries the old X-Api-Key gate")

    # Any auth_request-guarded location must still proxy somewhere -- a guard
    # replacement that eats the location's upstream (live-caught on WP-6.1:
    # /api/ai-triage 404'd from nginx for exactly this reason) is a regression
    # no syntax check can catch, since a proxyless location is valid nginx.
    for loc in (" = /api/alerts {", " = /api/events {", " = /api/ai-triage {",
                "location /api/ops/ws1 {", "location /api/ops/ws8 {"):
        anchor = f"location{loc}" if loc.startswith(" =") else loc
        b = block(tpl, anchor)
        check("proxy_pass" in b,
              f"wp-6.1: {anchor} lost its proxy_pass when the gate was replaced")

    # ---- 2026-10-15: HTML entry points revalidate, hashed assets immutable ----
    blocks = {b.split("{", 1)[0].strip(): b.split("}", 1)[0]
              for b in re.split(r"\n\s*location ", tpl)[1:]}
    check('add_header Cache-Control "no-cache";' in blocks.get("= /index.html", ""),
          "cache: location = /index.html does not send Cache-Control: no-cache")
    check('Cache-Control "public, max-age=31536000, immutable"' in blocks.get("/assets/", ""),
          "cache: location /assets/ does not mark hashed bundles immutable")
    # Any location with its own add_header loses the server-level ones, so every
    # such block must repeat all four security headers.
    for loc, body in blocks.items():
        if "add_header" not in body:
            continue
        for h in ("X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy",
                  "Content-Security-Policy"):
            check(f"add_header {h} " in body,
                  f"security headers: location {loc} sets add_header but drops {h}")

    # ---- system health (2026-10-15): read-only Prometheus proxy --------------
    prom_locs = re.findall(r"\n\s*location\s+([^{]*?)\s*\{", tpl)
    prom_locs = [loc for loc in prom_locs if "/api/prom" in loc]
    allow_head = "location ~ ^/api/prom/api/v1/(targets|query)$ {"
    check(sorted(prom_locs) == sorted(["/api/prom/", "~ ^/api/prom/api/v1/(targets|query)$"]),
          f"prom: expected exactly the deny prefix + the 2-path allow regex, got {prom_locs}")
    check("return 403;" in block(tpl, "location /api/prom/ {"),
          "prom: /api/prom/ prefix block does not deny every non-allowlisted path")
    allow = block(tpl, allow_head)
    check(bool(allow), "prom: allowlist location missing")
    rx = re.compile(r"^/api/prom/api/v1/(targets|query)$")
    for p in ("/api/prom/api/v1/targets", "/api/prom/api/v1/query"):
        check(rx.match(p) is not None, f"prom: allowlist regex rejects {p}")
    for p in ("/api/prom/api/v1/admin/tsdb/delete_series", "/api/prom/api/v1/admin/tsdb/snapshot",
              "/api/prom/api/v1/write", "/api/prom/api/v1/query_range", "/api/prom/api/v1/series",
              "/api/prom/-/quit", "/api/prom/-/reload", "/api/prom/api/v1/targets/../admin",
              "/api/prom/api/v1/querys", "/api/prom/api/v1/query/", "/api/prom/federate"):
        check(rx.match(p) is None, f"prom: allowlist regex admits {p}")
    check(re.search(r"limit_except GET \{\s*deny all;\s*\}", allow) is not None,
          "prom: allowlist location does not restrict to GET (HEAD implied)")
    check("auth_request /api/auth/check;" in allow,
          "prom: allowlist location lacks the auth_request /auth/check guard")
    check("resolver 127.0.0.11" in allow and 'set $prometheus "http://prometheus:9090";' in allow
          and "proxy_pass $prometheus;" in allow,
          "prom: upstream not resolved at request time via a variable (nginx would fail to start without prometheus)")
    check("proxy_pass_request_body off;" in allow, "prom: request body is forwarded upstream")
    for hdr in ("Authorization", "Cookie", "X-Api-Key"):
        check(f'proxy_set_header {hdr} "";' in allow, f"prom: caller {hdr} is forwarded to Prometheus")
    check("proxy_connect_timeout 2s;" in allow and "proxy_read_timeout 5s;" in allow,
          "prom: allowlist location lacks short timeouts")
    check("add_header" not in allow,
          "prom: allowlist location sets add_header, dropping the inherited security headers")
    server_hdrs = tpl[:tpl.index("location / {")]
    for h in ("X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Content-Security-Policy"):
        check(f"add_header {h} " in server_hdrs, f"prom: server-level {h} the proxy inherits is missing")


def main():
    run()
    if FAILS:
        print(f"[FAIL] WS-7 read-plane regression: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-7 read-plane regression PASS")


if __name__ == "__main__":
    main()