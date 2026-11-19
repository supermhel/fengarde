"""WP-3.2 follow-up: the prod gate is only armed if the SHIPPED compose file forwards its env vars.

Review finding: no compose file passed FENGARDE_PROFILE, so ``FENGARDE_PROFILE=prod docker compose up``
left every prod_or_die a no-op. This renders infra/docker-compose.yml the way compose does (YAML ->
``${VAR:-default}`` interpolation against a given environment) and asserts the variables reach each
gated service, and that an unset profile renders EMPTY (demo behaviour unchanged).

Zero-infra (no docker): a tiny interpolator for the ``${NAME}`` / ``${NAME:-default}`` forms the file uses.
HA overlay: docker-compose.ha.yml only adds/overrides keys in ``environment`` (a map-merge), it never
removes FENGARDE_PROFILE; asserted below by checking it does not redefine the gate vars.

Run: python tools/test_compose_prod_env.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "infra" / "docker-compose.yml"
HA = ROOT / "infra" / "docker-compose.ha.yml"

# Every service whose entrypoint calls prod_or_die (docs/secure-defaults.md "Which entrypoints enforce the gate").
GATED = ("ws1-collectors", "ws2-normalization", "ws3-indexer", "ws4-detection",
         "ws5-ai", "ws6-inventory", "ws8-correlation", "ws9-resolver")
WS3_EXTRA = ("FENGARDE_RBAC_DB", "FENGARDE_ADMIN_PASSWORD", "FENGARDE_FIRST_BOOT_FILE", "FENGARDE_API_KEY")

_VAR = re.compile(r"\$\{(\w+)(?::?-([^}]*))?\}")
FAILS: list[str] = []


def check(cond: object, msg: str) -> None:
    if not cond:
        FAILS.append(msg)


def interpolate(value: str, environ: dict) -> str:
    def sub(m: re.Match) -> str:
        got = environ.get(m.group(1))
        return got if got else (m.group(2) or "")
    return _VAR.sub(sub, value)


def rendered_env(service: dict, environ: dict) -> dict:
    raw = service.get("environment") or []
    if isinstance(raw, dict):
        items = [f"{k}={'' if v is None else v}" for k, v in raw.items()]
    else:
        items = list(raw)
    out = {}
    for item in items:
        k, _, v = str(item).partition("=")
        out[k] = interpolate(v, environ)
    return out


def main() -> int:
    services = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]
    prod_env = {"FENGARDE_PROFILE": "prod", "FENGARDE_RBAC_DB": "/app/ws3-indexer/data/rbac.sqlite",
                "FENGARDE_ADMIN_PASSWORD": "a-long-test-admin-pw", "FENGARDE_FIRST_BOOT_FILE": "/secrets/pw.txt",
                "FENGARDE_API_KEY": "k" * 24, "REDIS_PASSWORD": "r" * 16}
    for name in GATED:
        svc = services.get(name)
        check(svc is not None, f"{name} missing from docker-compose.yml")
        if svc is None:
            continue
        got = rendered_env(svc, prod_env)
        check(got.get("FENGARDE_PROFILE") == "prod",
              f"{name}: FENGARDE_PROFILE=prod must reach the container, got {got.get('FENGARDE_PROFILE')!r}")
        demo = rendered_env(svc, {})
        check(demo.get("FENGARDE_PROFILE") == "",
              f"{name}: unset profile must render EMPTY (demo no-op), got {demo.get('FENGARDE_PROFILE')!r}")
        if name != "ws6-inventory" and name != "ws3-indexer":
            # redis-bus consumers: the password and the URL carrying it must both reach the gate
            check(got.get("REDIS_PASSWORD") == "r" * 16, f"{name}: REDIS_PASSWORD not forwarded")
            check(got.get("REDIS_URL", "").startswith("redis://:" + "r" * 16 + "@"), f"{name}: REDIS_URL must carry the password")
    ws3 = rendered_env(services["ws3-indexer"], prod_env)
    for var in WS3_EXTRA:
        check(ws3.get(var) == prod_env[var], f"ws3-indexer: {var} must be forwarded to the container, got {ws3.get(var)!r}")
    ws3_demo = rendered_env(services["ws3-indexer"], {})
    for var in ("FENGARDE_RBAC_DB", "FENGARDE_ADMIN_PASSWORD", "FENGARDE_FIRST_BOOT_FILE"):
        check(ws3_demo.get(var) == "", f"ws3-indexer: unset {var} must render empty (RBAC stays off by default)")
    # HA overlay merges environment by key: it must not redefine the gate vars (it would shadow the base)
    ha_text = HA.read_text(encoding="utf-8")
    for var in ("FENGARDE_PROFILE", "FENGARDE_RBAC_DB", "FENGARDE_FIRST_BOOT_FILE", "FENGARDE_ADMIN_PASSWORD"):
        check(var not in ha_text, f"docker-compose.ha.yml must not redefine {var} (inherits from the base file)")
    if FAILS:
        print(f"[FAIL] compose prod env: {len(FAILS)} problem(s)")
        for f in FAILS[:20]:
            print("  -", f)
        return 1
    print(f"[OK] compose prod env: FENGARDE_PROFILE reaches {len(GATED)} gated services; "
          "ws3 RBAC/admin/first-boot vars forwarded; unset renders empty")
    return 0


if __name__ == "__main__":
    sys.exit(main())
