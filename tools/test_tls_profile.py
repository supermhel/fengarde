"""Contract tests for the WP-3.1 TLS profile (infra/docker-compose.tls.yml).

The profile must guarantee: in TLS mode the console (ws7) and the ingest
endpoint (ws1) answer ONLY over TLS. These static checks pin that promise
without Docker:

- the override removes the plaintext publishes of ws7 and ws1 (`!override`,
  the compose-spec merge tag) instead of adding alongside them;
- Caddy is in the ``tls`` profile, publishes 443, proxies BOTH sites;
- the Caddyfile serves `siem.internal` -> ws7 and `ingest.internal` -> ws1,
  each with `tls internal` (local-CA default, no public DNS/ACME required).

The full merge is additionally verified live by `docker compose config` at
development time (pasted in docs/tls-profile.md) and by the gate's live path.

Run: python tools/test_tls_profile.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FAILS: list[str] = []


def check(cond: object, msg: str) -> None:
    if not cond:
        FAILS.append(msg)


def test_override_structure():
    text = (ROOT / "infra" / "docker-compose.tls.yml").read_text(encoding="utf-8")
    # both endpoints must have their publishes REMOVED via the compose spec
    # !override tag ("ports: !override []"), never appended next to them
    # (the exact per-service semantics are asserted in test_yaml_parses)
    check("ws7-dashboard:" in text and "ports: !override []" in text,
          "ws7 plaintext publish is not removed in the tls override")
    # at least the two service removals carry the tag (the header comment may
    # mention it too)
    check(text.count("ports: !override []") >= 2,
          "expected >= 2 !override port removals (ws7, ws1)")
    check('profiles: ["tls"]' in text,
          "caddy must be a tls-profile-only service")
    check('"443:443/tcp"' in text, "caddy must publish 443")
    check("caddy-data:" in text and "caddy-config:" in text,
          "caddy data/config volumes must be declared")
    check("ws7-dashboard" in text and "ws1-collectors" in text,
          "caddy must depend on both endpoints")


def test_caddyfile_sites():
    text = (ROOT / "infra" / "caddy" / "Caddyfile").read_text(encoding="utf-8")
    check("siem.internal {" in text, "console site missing")
    check("ingest.internal {" in text, "ingest site missing")
    check("tls internal" in text, "local-CA (tls internal) default missing")
    check("ws7-dashboard:80" in text and "ws1-collectors:8554" in text,
          "reverse_proxy targets wrong")


def test_yaml_parses():
    import yaml  # noqa: PLC0415

    # docker compose's `!override` merge tag is not standard YAML: accept it
    # as "replace with the wrapped value" so the files can be parsed here.
    class _ComposeLoader(yaml.SafeLoader):  # noqa: N801
        pass

    def _override(loader, node):  # noqa: ANN001, ANN202
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node, deep=True)
        return loader.construct_object(node, deep=True)

    _ComposeLoader.add_constructor("!override", _override)

    base = yaml.load((ROOT / "infra" / "docker-compose.yml").read_text(encoding="utf-8"),
                     Loader=_ComposeLoader)
    ovr = yaml.load((ROOT / "infra" / "docker-compose.tls.yml").read_text(encoding="utf-8"),
                    Loader=_ComposeLoader)
    for name in ("ws7-dashboard", "ws1-collectors"):
        check(name in base["services"], f"{name} missing from the base compose")
        check(name in ovr["services"], f"{name} missing from the tls override")
        check(ovr["services"][name].get("ports") == [],
              f"{name} must declare ports: !override []")
    check("caddy" in ovr["services"] and "volumes" in ovr,
          "override must add caddy + its named volumes")


def test_documentation_is_honest():
    text = (ROOT / "docs" / "tls-profile.md").read_text(encoding="utf-8")
    check("internal" in text and "443" in text,
          "doc must state the local-CA default and the port")


def main() -> int:
    tests = [test_override_structure, test_caddyfile_sites,
             test_yaml_parses, test_documentation_is_honest]
    for t in tests:
        t()
    if FAILS:
        print(f"[FAIL] tls_profile: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("  -", f)
        return 1
    print(f"[OK] tls_profile: {len(tests)} test groups — plaintext removal, "
          "caddy wiring, local-CA default, honest docs")
    return 0


if __name__ == "__main__":
    sys.exit(main())