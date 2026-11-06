"""Contract tests for the WP-3.1 TLS profile (infra/docker-compose.tls.yml).

The profile must guarantee: in TLS mode the console (ws7) and the HTTP ingest
endpoint (ws1) answer ONLY over TLS, and syslog is not published at all. The
checks run on the MERGED compose config (``docker compose config --format
json`` when docker is available, else a YAML merge that models ``!override``),
so a comment or an unrelated string can no longer satisfy them:

- NO service publishes on all interfaces by default; caddy publishes exactly
  127.0.0.1:443/tcp (FENGARDE_TLS_BIND opts in to a LAN address);
- ws1 and ws7 publish nothing; no UDP port is published anywhere;
- the Caddyfile serves `siem.internal` -> ws7 and `ingest.internal` -> ws1 with
  `tls internal`; ws1 trusts the proxy range for client IPs; ws7 mounts the
  real-ip file; Caddy has a fixed address and ONLY that address is trusted for
  X-Forwarded-For in ws1 and in nginx; the docs carry the real verification commands (`--cacert`, root
  export, no `curl -k`).

The live transcript in docs/tls-profile.md is MANUAL; CI does not reproduce it.

Run: python tools/test_tls_profile.py
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INFRA = ROOT / "infra"
ALL_IFACES = (None, "", "0.0.0.0", "::", "[::]")

FAILS: list[str] = []


def check(cond: object, msg: str) -> None:
    if not cond:
        FAILS.append(msg)


def _merged_from_docker(env: dict | None = None) -> dict | None:
    if not shutil.which("docker"):
        return None
    try:
        r = subprocess.run(
            ["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.tls.yml",
             "--profile", "tls", "config", "--format", "json"],
            cwd=INFRA, capture_output=True, text=True, timeout=60, env={**os.environ, **(env or {})})
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    return json.loads(r.stdout)


def _parse_port(spec) -> dict:
    """Short or long compose port syntax -> {host_ip, published, target, protocol}."""
    if isinstance(spec, dict):
        return {"host_ip": spec.get("host_ip"), "published": str(spec.get("published", "")),
                "target": str(spec.get("target", "")), "protocol": spec.get("protocol", "tcp")}
    s = str(spec)
    proto = "tcp"
    if "/" in s:
        s, proto = s.rsplit("/", 1)
    parts = s.split(":")
    host_ip = parts[0] if len(parts) == 3 else None
    return {"host_ip": host_ip, "published": parts[-2] if len(parts) > 1 else "",
            "target": parts[-1], "protocol": proto}


def _merged_from_yaml() -> dict:
    import yaml  # noqa: PLC0415

    class _Tagged(list):
        """A list carrying the compose `!override` tag."""

    class _L(yaml.SafeLoader):  # noqa: N801
        pass

    def _override(loader, node):  # noqa: ANN001, ANN202
        seq = loader.construct_sequence(node, deep=True) if isinstance(node, yaml.SequenceNode) \
            else loader.construct_object(node, deep=True)
        return _Tagged(seq)

    _L.add_constructor("!override", _override)
    base = yaml.load((INFRA / "docker-compose.yml").read_text(encoding="utf-8"), Loader=_L)
    text = (INFRA / "docker-compose.tls.yml").read_text(encoding="utf-8")
    # ${VAR:-default} with the variable unset (the default case)
    text = re.sub(r"\$\{[A-Z_]+:-([^}]*)\}", r"\1", text)
    ovr = yaml.load(text, Loader=_L)
    services = base["services"]
    for name, svc in ovr["services"].items():
        cur = services.setdefault(name, {})
        for k, v in svc.items():
            if k == "ports":
                # untagged lists APPEND in compose; the !override tag replaces
                cur["ports"] = list(v) if isinstance(v, _Tagged) else list(cur.get("ports", [])) + list(v)
            elif isinstance(v, list) and isinstance(cur.get(k), list):
                cur[k] = list(cur[k]) + list(v)
            else:
                cur[k] = v
    return {"services": services, "networks": {**base.get("networks", {}), **ovr.get("networks", {})}}


def _env_list(service: dict) -> list:
    env = service.get("environment") or []
    if isinstance(env, dict):
        return [f"{k}={v}" for k, v in env.items()]
    return list(env)


def test_merged_ports():
    merged = _merged_from_docker() or _merged_from_yaml()
    pub = {n: [_parse_port(p) for p in (s.get("ports") or [])]
           for n, s in merged["services"].items()}
    for n in ("ws1-collectors", "ws7-dashboard"):
        check(n in pub, f"{n} missing from the merged config")
        check(pub.get(n) == [], f"{n} must publish nothing in the tls profile, got {pub.get(n)}")
    check("caddy" in pub, "caddy missing from the merged tls config")
    public = [(n, p["published"], p["protocol"]) for n, ps in pub.items() for p in ps
              if p["host_ip"] in ALL_IFACES]
    check(public == [], f"nothing may publish on all interfaces by default, got {public}")
    check(pub.get("caddy") == [{"host_ip": "127.0.0.1", "published": "443", "target": "443", "protocol": "tcp"}],
          f"caddy must publish exactly 127.0.0.1:443/tcp by default, got {pub.get('caddy')}")
    udp = [(n, p) for n, ps in pub.items() for p in ps if p["protocol"] == "udp"]
    check(not udp, f"no UDP port may be published in the tls profile (syslog), got {udp}")
    svc = merged["services"]
    check(svc["caddy"].get("profiles") == ["tls"], "caddy must be a tls-profile-only service")
    # only Caddy's fixed address is trusted (any container on the network could otherwise forge X-Forwarded-For)
    nets = merged.get("networks", {}).get("default", {}).get("ipam", {}).get("config", [])
    subnet = ipaddress.ip_network(nets[0]["subnet"]) if nets else None
    ip_range = nets[0].get("ip_range") if nets else None
    caddy_ip = ((svc["caddy"].get("networks") or {}).get("default") or {}).get("ipv4_address")
    check(subnet is not None and caddy_ip and ipaddress.ip_address(caddy_ip) in subnet,
          f"caddy needs a fixed ipv4_address inside the ipam subnet, got {caddy_ip} / {subnet}")
    check(ip_range and caddy_ip and ipaddress.ip_address(caddy_ip) not in ipaddress.ip_network(ip_range),
          f"ip_range must exclude Caddy's fixed address (else another container can take it first), got {ip_range}")
    trusted = [str(e).split("=", 1)[1] for e in _env_list(svc["ws1-collectors"])
               if str(e).startswith("INGEST_HTTP_TRUSTED_PROXIES=")]
    check(trusted == [caddy_ip], f"ws1 must trust exactly Caddy's address {caddy_ip}, got {trusted}")
    real_ip = (INFRA / "caddy" / "nginx-real-ip.conf").read_text(encoding="utf-8")
    nginx_trusted = re.findall(r"^set_real_ip_from\s+(\S+);", real_ip, re.M)
    check(nginx_trusted == [caddy_ip], f"nginx must trust exactly Caddy's address {caddy_ip}, got {nginx_trusted}")
    check("real-ip" in json.dumps(svc["ws7-dashboard"].get("volumes")),
          "ws7 must mount the nginx real-ip file in the tls profile")


def test_lan_bind_is_opt_in():
    """FENGARDE_TLS_BIND is the only way to expose Caddy beyond loopback (needs the docker engine to interpolate)."""
    merged = _merged_from_docker({"FENGARDE_TLS_BIND": "192.0.2.10"})
    if merged is None:
        return
    ports = [_parse_port(p) for p in merged["services"]["caddy"]["ports"]]
    check([(p["host_ip"], p["published"]) for p in ports] == [("192.0.2.10", "443")],
          f"FENGARDE_TLS_BIND must set the caddy publish address, got {ports}")


def test_caddyfile_sites():
    text = (INFRA / "caddy" / "Caddyfile").read_text(encoding="utf-8")
    check("siem.internal {" in text, "console site missing")
    check("ingest.internal {" in text, "ingest site missing")
    check(text.count("tls internal") >= 2, "local-CA (tls internal) default missing on a site")
    check("ws7-dashboard:80" in text and "ws1-collectors:8554" in text,
          "reverse_proxy targets wrong")
    real_ip = (INFRA / "caddy" / "nginx-real-ip.conf").read_text(encoding="utf-8")
    check("set_real_ip_from" in real_ip and "real_ip_header X-Forwarded-For" in real_ip
          and "real_ip_recursive on" in real_ip, "nginx real-ip file incomplete")


def test_documentation_is_honest():
    doc = (ROOT / "docs" / "tls-profile.md").read_text(encoding="utf-8")
    for needle in ("--cacert", "--resolve", "cp caddy:/data/caddy/pki/authorities/local/root.crt",
                   "root.key", "caddy trust", "NOT reproduced by CI", "FENGARDE_TLS_BIND",
                   "without authentication", "172.31.250.2"):
        check(needle in doc, f"docs/tls-profile.md must contain {needle!r}")
    for f in (ROOT / "docs" / "tls-profile.md", INFRA / "docker-compose.tls.yml", INFRA / "caddy" / "Caddyfile"):
        text = f.read_text(encoding="utf-8")
        # prose may say "never `curl -k`"; a runnable insecure command starts a line with curl
        bad = [ln for ln in text.splitlines()
               if ln.lstrip("# ").startswith("curl") and (" -k " in ln or " -sk " in ln or "--insecure" in ln)]
        check(not bad, f"{f.name} shows an insecure curl command: {bad}")
        check("everything in and out of ws1 is TLS-terminated" not in text,
              f"{f.name} makes a false TLS claim about syslog")


def main() -> int:
    tests = [test_merged_ports, test_lan_bind_is_opt_in, test_caddyfile_sites, test_documentation_is_honest]
    for t in tests:
        t()
    if FAILS:
        print(f"[FAIL] tls_profile: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("  -", f)
        return 1
    print(f"[OK] tls_profile: {len(tests)} test groups — merged-config ports, caddy wiring, "
          "real-ip, doc commands")
    return 0


if __name__ == "__main__":
    sys.exit(main())
