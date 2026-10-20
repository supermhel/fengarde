"""WS-7 read-plane gap-hunt regression test (static, no browser needed).

nginx read-plane regression (the legacy-console assertions that used to live here -- getAlerts/LIVE ownership, the
outage marker, the honest badge copy -- went away with the legacy UI on 2026-10-20; the React console has its own vitest suite):

  * read-plane #6     the /api/config.js API-key bootstrap is served only to
                      same-origin browser subresource fetches (Sec-Fetch-Site:
                      same-origin, GET/HEAD only) and the residual exposure is
                      documented loudly (see also SECURITY.md: not an access boundary).
  * cache (2026-10-15) the SPA index.html is served no-cache and /assets/
                      immutable, and every location that sets its own
                      add_header repeats all four security headers.
  * prom (2026-10-15) /api/prom/ is a GET-only, X-Api-Key-gated allowlist
                      onto Prometheus: /api/v1/targets and /api/v1/query only,
                      no body or credentials forwarded, headers inherited.

Substring assertions plus a node --check syntax gate (test_contract.py) are the
static contract; this test proves the specific returns that the greps cannot.
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


def run():
    tpl = (HERE / "templates" / "default.conf.template").read_text(encoding="utf-8")

    # ---- read-plane #6: config.js served only to same-origin browser fetches ----
    cfg = tpl[tpl.index("location = /api/config.js"):]
    check("$http_sec_fetch_site" in cfg,
          "read-plane #6: config.js location does not gate on Sec-Fetch-Site")
    check('$http_sec_fetch_site = "same-origin"' in cfg,
          "read-plane #6: config.js does not require Sec-Fetch-Site: same-origin")
    check("limit_except GET HEAD" in cfg,
          "read-plane #6: config.js location does not restrict to GET/HEAD")
    check("fengarde_cfg_ok" in cfg,
          "read-plane #6: config.js same-origin gate is missing the allow flag")
    check("read-plane #6" in tpl,
          "read-plane #6: the residual-exposure tradeoff is not documented loudly in the template")

    # ---- 2026-10-15: HTML entry points revalidate, hashed assets are immutable ----
    blocks = {b.split("{", 1)[0].strip(): b.split("}", 1)[0]
              for b in re.split(r"\n\s*location ", tpl)[1:]}
    for loc in ("= /index.html",):
        check('add_header Cache-Control "no-cache";' in blocks.get(loc, ""),
              f"cache: location {loc} does not send Cache-Control: no-cache")
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

    # ---- system health (2026-10-15): read-only Prometheus proxy ----
    # Whole-block slices (the brace-naive `blocks` map above stops at the first
    # inner `}`, e.g. limit_except's).
    def block(head):
        if head not in tpl:
            return ""
        s = tpl.index(head)
        return tpl[s:tpl.index("\n    }\n", s)]
    prom_locs = re.findall(r"\n\s*location\s+([^{]*?)\s*\{", tpl)
    prom_locs = [loc for loc in prom_locs if "/api/prom" in loc]
    allow_head = "location ~ ^/api/prom/api/v1/(targets|query)$ {"
    check(sorted(prom_locs) == sorted(["/api/prom/", "~ ^/api/prom/api/v1/(targets|query)$"]),
          f"prom: expected exactly the deny prefix + the 2-path allow regex, got {prom_locs}")
    check("return 403;" in block("location /api/prom/ {"),
          "prom: /api/prom/ prefix block does not deny every non-allowlisted path")
    allow = block(allow_head)
    check(bool(allow), "prom: allowlist location missing")
    # The regex itself admits only the two read endpoints (nginx and Python
    # regex agree on this subset: anchors, literal text, one alternation).
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
    check('if ($http_x_api_key != "${FENGARDE_API_KEY}") { return 401; }' in allow,
          "prom: allowlist location lacks the X-Api-Key gate used by /api/ops/* and /api/rules")
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
