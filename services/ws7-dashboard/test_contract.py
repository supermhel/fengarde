"""WS-7 contract test -- static checks, no browser needed.

The classic single-file console (index.html, /legacy/) was retired 2026-10-20; WS-7 is the React console in app/ (its
type-check and vitest suite run in run_all_tests.sh). This test pins the container/proxy contract around it:
  * the Dockerfile builds the console and serves its dist/ at the web root, and ships no legacy UI,
  * the nginx template has no /legacy/ location and still proxies the read API,
  * the console source tree exists with a lockfile (reproducible build).
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FAILS: list[str] = []


def check(c, m):
    if not c:
        FAILS.append(m)


def run():
    dockerfile = (HERE / "Dockerfile").read_text(encoding="utf-8")
    tpl = (HERE / "templates" / "default.conf.template").read_text(encoding="utf-8")
    check("COPY --from=console /build/dist/ /usr/share/nginx/html/" in dockerfile,
          "Dockerfile does not serve the built React console at the web root")
    check("/legacy/" not in dockerfile.replace("/legacy/ was", ""), "Dockerfile still ships a /legacy/ UI")
    check("location = /legacy/" not in tpl and "/legacy/index.html" not in tpl, "nginx template still has a /legacy/ location")
    check("location /api/" in tpl or "location = /api/" in tpl or "/api/alerts" in tpl, "nginx template lost the /api proxy")
    check(not (HERE / "index.html").exists(), "the retired legacy index.html is back")
    check((HERE / "app" / "package.json").exists() and (HERE / "app" / "package-lock.json").exists(),
          "console source tree or lockfile missing (app/package.json, app/package-lock.json)")
    check((HERE / "app" / "src").is_dir(), "console source directory app/src missing")


def main():
    run()
    if FAILS:
        print(f"[FAIL] WS-7: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-7 contract test PASS")


if __name__ == "__main__":
    main()
