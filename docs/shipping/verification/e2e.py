"""MANUAL live driver (needs Docker; NOT part of CI, not a test): shipper containers -> host ws1 listeners (memory bus) -> the real WS-2 path.

Usage: python docs/shipping/verification/e2e.py <recipe> [seconds]
recipe: fb-docker fb-n8n vec-n8n fb-dns vec-dns vec-docker fb-journald vec-journald rs-fwd rs-relay ng-fwd ng-relay
Env: BIND (listener address, default 127.0.0.1), SP (scratch dir, default a temp dir), FULL=1 (print shipper logs),
NMSG / GAP / RESTART (journald recipes), DNSFILE (dnsmasq input). The ingest token is generated per run and handed to the
container by variable NAME, never printed. See README.md in this directory.
"""
import json, os, re, secrets, shutil, socket, subprocess, sys, tempfile, threading, time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SP = Path(os.environ.get("SP") or tempfile.mkdtemp(prefix="fengarde-e2e-"))
CFG = REPO / "docs/shipping/configs"
sys.path.insert(0, str(REPO / "services" / "ws2-normalization"))
sys.path.insert(0, str(REPO / "services"))
sys.path.append(str(REPO / "services" / "ws1-collectors"))
os.environ["BUS_BACKEND"] = "memory"
from shared.bus import Bus  # noqa
from collectors.http_json_collector import HttpJsonCollector  # noqa
from collectors.syslog_tcp_server import SyslogTCPServer  # noqa
from adapters import adapt_record  # noqa
from main import normalize_one  # noqa
from parsers import resolve  # noqa

FB = "fluent/fluent-bit:5.1.5"
VEC = "timberio/vector:0.61.0-alpine"
BIND = os.environ.get("BIND", "127.0.0.1")
HOSTN = "host.docker.internal"
TOKEN = secrets.token_urlsafe(24)
os.environ["FENGARDE_INGEST_TOKEN"] = TOKEN  # passed by name (-e NAME) so it is never on a command line


def sh(*a, inp=None, check=False, timeout=180):
    r = subprocess.run(list(a), input=inp, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode:
        raise RuntimeError(f"{a[:4]} rc={r.returncode}: {r.stderr[-400:]}")
    return r


class Tee:
    """Raw-byte capture proxy in front of the real listener (shows the exact framing a shipper emits)."""
    def __init__(self, target_port):
        self.s = socket.socket(); self.s.bind((BIND, 0)); self.s.listen(8)
        self.port = self.s.getsockname()[1]; self.target = target_port; self.raw = bytearray()
        threading.Thread(target=self._acc, daemon=True).start()
    def _acc(self):
        while True:
            try: c, _ = self.s.accept()
            except OSError: return
            threading.Thread(target=self._pump, args=(c,), daemon=True).start()
    def _pump(self, c):
        u = socket.create_connection(("127.0.0.1", self.target))
        while True:
            d = c.recv(65536)
            if not d: break
            self.raw += d; u.sendall(d)
        u.close(); c.close()


def prep_cfg(name, subs):
    d = SP / f"cfg-{name}"
    if d.exists(): shutil.rmtree(d)
    shutil.copytree(CFG, d)
    for f in d.iterdir():
        t = f.read_text(encoding="utf-8")
        for a, b in subs.items(): t = t.replace(a, b)
        f.write_text(t, encoding="utf-8", newline="\n")
    return d


def start(name, image, args, vols=(), cfg=None, env_token=True, extra=()):
    sh("docker", "rm", "-f", name)
    cmd = ["docker", "run", "-d", "--name", name, "--add-host", f"{HOSTN}:host-gateway"]
    if env_token: cmd += ["-e", "FENGARDE_INGEST_TOKEN", "-e", "COMPUTERNAME=win-lab-01"]
    if cfg: cmd += ["-v", f"{cfg}:/cfg:ro"]
    for v in vols: cmd += ["-v", v]
    cmd += list(extra) + [image] + list(args)
    sh(*cmd, check=True)


def append(vol, path, text, base="/v"):
    r = subprocess.run(["docker", "run", "--rm", "-i", "-v", f"{vol}:{base}", "alpine:3.20", "sh", "-c",
       f"mkdir -p $(dirname {base}/{path}) && cat >> {base}/{path}"], input=text.encode(), capture_output=True)
    assert r.returncode == 0, r.stderr


def logs(name):
    r = sh("docker", "logs", name); t = (r.stdout + r.stderr).replace(TOKEN, "<TOKEN>")
    return t


def stop(*names):
    for n in names: sh("docker", "rm", "-f", n)


def report(bus, label, raw_tee=None):
    msgs = bus.drain("raw.events")
    out = []
    for m in msgs:
        p = m.payload
        meta = p.get("meta", {})
        adapted = adapt_record(json.loads(json.dumps(p)))
        parser = resolve(adapted)
        ev, errs = normalize_one(json.loads(json.dumps(p)))
        raw = p.get("raw")
        out.append(dict(source_type=p.get("source_type"), shipper=meta.get("shipper"), source=meta.get("source"),
                        format=meta.get("format"), raw=raw, parser=type(parser).__name__ if parser else None,
                        parser_mod=getattr(parser, "__module__", None) if parser else None,
                        class_uid=(ev or {}).get("class_uid"), errors=errs))
    print(f"==== {label}: {len(out)} bus message(s)")
    for o in out: print(json.dumps(o, default=str))
    if raw_tee is not None: print("RAW BYTES:", bytes(raw_tee.raw)[:600])
    return out


def servers():
    bus = Bus()
    http = HttpJsonCollector(bus, ingest_token=TOKEN, host=BIND, port=0); http.start()
    sysl = SyslogTCPServer(bus, host=BIND, port=0); sysl.start()
    return bus, http, sysl


DOCKER_LINES = (
    '{"log":"n8n webhook received order 42\\n","stream":"stdout","time":"2026-11-05T08:30:00.123456789Z"}\n'
    '{"log":"Failed password for invalid user root from 198.51.100.23 port 51234 ssh2\\n","stream":"stderr","time":"2026-11-05T08:30:01.111111111Z"}\n'
)
CID = "5f9e2c4a1b8d7e3f" + "a" * 48
N8N = ('{"eventType":"webhook.created","user":"alice","ip":"203.0.113.9","workflowId":"wf-42","path":"/webhook/x","ts":1751500000000}\n'
       '{"eventType":"user.login","user":"bob","ip":"203.0.113.10","ts":1751500001000}\n')
DNS = ("Nov  5 08:30:00 dnsmasq[123]: query[A] evil-c2.example.com from 10.0.0.5\n"
       "Nov  5 08:30:01 dnsmasq[123]: reply evil-c2.example.com is 203.0.113.66\n")
DNS = open(os.environ["DNSFILE"],encoding="utf-8").read() if os.environ.get("DNSFILE") else DNS
PRIMER = '{"log":"primer\\n","stream":"stdout","time":"2026-11-05T08:29:59.000000001Z"}\n'
PRIMER2 = "\n"
SSHD = "Failed password for invalid user admin from 198.51.100.7 port 51000 ssh2"


def main(rec, secs):
    bus, http, sysl = servers()
    hp, sp_ = http.port, sysl.port
    tee = Tee(sp_)
    subs = {"192.0.2.10:5515": f"{HOSTN}:{tee.port}", "192.0.2.10": HOSTN, "5515": str(tee.port), "8554": str(hp)}
    vol = f"fengarde-e2e-{rec}"
    sh("docker", "volume", "rm", "-f", vol)
    cfg = prep_cfg(rec, subs)
    name = f"fengarde-e2e-{rec}"
    try:
        if rec == "fb-docker":
            append(vol, f"{CID}/{CID}-json.log", PRIMER, "/var/lib/docker/containers")
            start(name, FB, ["/fluent-bit/bin/fluent-bit", "-c", "/cfg/fluent-bit-docker.conf"], [f"{vol}:/var/lib/docker/containers"], cfg)
            time.sleep(4); append(vol, f"{CID}/{CID}-json.log", DOCKER_LINES, "/var/lib/docker/containers")
        elif rec == "fb-n8n":
            append(vol, "fengarde-audit.log", PRIMER2, "/home/node/.n8n")
            start(name, FB, ["/fluent-bit/bin/fluent-bit", "-c", "/cfg/fluent-bit-n8n.conf"], [f"{vol}:/home/node/.n8n"], cfg)
            time.sleep(4); append(vol, "fengarde-audit.log", N8N, "/home/node/.n8n")
        elif rec == "vec-n8n":
            append(vol, "fengarde-audit.log", PRIMER2, "/home/node/.n8n")
            start(name, VEC, ["--config", "/cfg/vector-n8n.toml"], [f"{vol}:/home/node/.n8n"], cfg,
                  extra=["-e", "VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=" + os.environ.get("VINT", "true")])
            time.sleep(5); append(vol, "fengarde-audit.log", N8N, "/home/node/.n8n")
        elif rec == "fb-dns":
            append(vol, "pihole.log", PRIMER2, "/var/log/pihole")
            start(name, FB, ["/fluent-bit/bin/fluent-bit", "-c", "/cfg/fluent-bit-dnsmasq.conf"], [f"{vol}:/var/log/pihole"], cfg, env_token=False)
            time.sleep(4); append(vol, "pihole.log", DNS, "/var/log/pihole")
        elif rec == "vec-dns":
            append(vol, "pihole.log", PRIMER2, "/var/log/pihole")
            start(name, VEC, ["--config", "/cfg/vector-dnsmasq.toml"], [f"{vol}:/var/log/pihole"], cfg, env_token=False)
            time.sleep(5); append(vol, "pihole.log", DNS, "/var/log/pihole")
        elif rec == "vec-docker":
            # test copy only: restrict to our own app container so other containers' logs are not shipped
            t = (cfg / "vector-docker.toml").read_text().replace('type = "docker_logs"', 'type = "docker_logs"\ninclude_containers = ["fengarde-e2e-app"]')
            (cfg / "vector-docker.toml").write_text(t, newline="\n")
            start(name, VEC, ["--config", "/cfg/vector-docker.toml"], ["/var/run/docker.sock:/var/run/docker.sock"], cfg, env_token=False)
            time.sleep(6)
            sh("docker", "rm", "-f", "fengarde-e2e-app")
            sh("docker", "run", "--name", "fengarde-e2e-app", "alpine:3.20", "sh", "-c",
               "echo 'n8n webhook received order 42'; echo 'Failed password for invalid user root from 198.51.100.23 port 51234 ssh2' >&2")
        elif rec in ("fb-journald", "vec-journald"):
            mid = SP / "machine-id"; mid.write_text("0123456789abcdef0123456789abcdef\n", newline="\n")
            jv = "fengarde-e2e-jv"; jn = "fengarde-e2e-j"
            sh("docker", "volume", "rm", "-f", jv); sh("docker", "rm", "-f", jn)
            sh("docker", "run", "-d", "--name", jn, "--hostname", "web01", "-v", f"{mid}:/etc/machine-id:ro", "-v", f"{jv}:/var/log/journal",
               "debian:trixie-slim", "sh", "-c",
               "apt-get update -qq >/dev/null && apt-get install -y -qq systemd >/dev/null 2>&1; mkdir -p /run/systemd/journal; "
               "/usr/lib/systemd/systemd-journald & sleep 2; touch /tmp/ready; sleep 600", check=True)
            for _ in range(120):
                if sh("docker", "exec", jn, "test", "-f", "/tmp/ready").returncode == 0: break
                time.sleep(2)
            else: raise SystemExit("journald container never became ready")
            if rec == "fb-journald":
                sh("docker", "volume", "rm", "-f", "fengarde-e2e-fbdb")
                start(name, FB, ["/fluent-bit/bin/fluent-bit", "-c", "/cfg/fluent-bit-journald.conf"],
                      [f"{jv}:/var/log/journal:ro", f"{mid}:/etc/machine-id:ro", "fengarde-e2e-fbdb:/var/lib/fluent-bit"], cfg)
            else:
                # test copy only: no systemd in the log-producing container => no _SYSTEMD_UNIT, so include_units would drop everything
                p = cfg / "vector-journald.toml"; p.write_text(p.read_text().replace('include_units = ["ssh", "sshd"]\n', ''), newline="\n")
                start(name, VEC.replace("alpine", "debian"), ["--config", "/cfg/vector-journald.toml"],
                      [f"{jv}:/var/log/journal:ro", f"{mid}:/etc/machine-id:ro"], cfg, env_token=False)
            time.sleep(6)
            for i in range(int(os.environ.get("NMSG","2"))):
                time.sleep(float(os.environ.get("GAP","0")))
                r = sh("docker", "exec", jn, "systemd-cat", "-t", "sshd", "-p", "info", "echo", SSHD + f" #{i}")
                print("systemd-cat rc", r.returncode, r.stderr[:200])
            sh("docker", "exec", jn, "journalctl", "--flush")
            if rec == "fb-journald" and os.environ.get("RESTART"):
                time.sleep(6); print("before restart:", len(bus.drain("raw.events")), "msgs")
                print(sh("docker", "stop", name).stdout.strip(), "stopped; db volume kept"); time.sleep(2)
                sh("docker", "start", name); time.sleep(6)
                sh("docker", "exec", jn, "systemd-cat", "-t", "sshd", "-p", "info", "echo", SSHD + " #AFTER-RESTART")
                time.sleep(6)
            print(sh("docker", "exec", jn, "journalctl", "-t", "sshd", "-o", "short", "--no-pager").stdout[:600])
        elif rec in ("rs-fwd", "rs-relay", "ng-fwd", "ng-relay"):
            kind = "rsyslog" if rec.startswith("rs") else "syslog-ng"
            conf = {"rs-fwd": "rsyslog-forward.conf", "rs-relay": "rsyslog-relay.conf", "ng-fwd": "syslog-ng-forward.conf", "ng-relay": "syslog-ng-relay.conf"}[rec]
            if kind == "rsyslog":
                (cfg / "main.conf").write_text(f'module(load="imuxsock")\ninclude(file="/cfg/{conf}")\n', newline="\n")
                start(name, "rsyslog/rsyslog:2026-10", ["-n", "-f", "/cfg/main.conf"], cfg=cfg, env_token=False, extra=["--user", "root", "--entrypoint", "rsyslogd"])
            else:
                start(name, "balabit/syslog-ng:4.12.0", ["-F", "-f", f"/cfg/{conf}"], cfg=cfg, env_token=False, extra=["--entrypoint", "syslog-ng"])
            time.sleep(5)
            msg = SSHD + " (" + rec + ")"
            if rec.endswith("fwd"):
                r = sh("docker", "exec", name, "logger", "-i", "-t", "sshd", "-p", "auth.info", msg)
            elif kind == "rsyslog":
                r = sh("docker", "exec", name, "logger", "-n", "127.0.0.1", "-P", "514", "-d", "--rfc3164", "-i", "-t", "sshd", "-p", "auth.info", msg)
            else:
                r = sh("docker", "exec", name, "bash", "-c", f'echo -n "<38>Nov  5 10:00:01 fw01 sshd[77]: {msg}" > /dev/udp/127.0.0.1/514')
            print("send rc", r.returncode, r.stderr[:300])
        else:
            raise SystemExit(f"unknown recipe {rec}")
        time.sleep(secs)
        if os.environ.get("FULL"): print("\n".join(l[:400] for l in logs(name).splitlines()))
        print("--- shipper logs (tail)"); print("\n".join(logs(name).splitlines()[-12:]))
        out = report(bus, rec, tee if rec.endswith(("dns",)) or rec.startswith("rs") else None)
        print("http metrics:", {k: v for k, v in http.metrics().items() if isinstance(v, (int, float))} if hasattr(http, "metrics") else "")
        print("tcp raw bytes:", bytes(tee.raw)[:600])
    finally:
        stop(name, "fengarde-e2e-app", "fengarde-e2e-j"); sh("docker", "volume", "rm", "-f", vol); sh("docker", "volume", "rm", "-f", "fengarde-e2e-jv"); sh("docker", "volume", "rm", "-f", "fengarde-e2e-fbdb")
        http.stop(); sysl.stop()


if __name__ == "__main__":
    main(sys.argv[1], float(sys.argv[2]) if len(sys.argv) > 2 else 12)
