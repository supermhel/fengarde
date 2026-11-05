"""WP-1.4 shipping-recipe checks (zero-infra).

Every sample in docs/shipping/samples/ is run through the real WS-2 path
(adapt_record -> parsers.resolve -> parse -> OCSF validate, via normalize_one)
exactly as ws1 would hand it over, and must resolve to the parser the recipe
claims. Also checks that each recipe doc names that parser, the README table
lists every recipe, every named source_type is registered, adapter-fixture
samples equal the adapter module's constant, fenced config blocks stay
byte-identical to docs/shipping/configs/, every config sits in a labelled fence
of its owning doc, and HTTP configs carry the source_type / X-Fengarde-Shipper
the samples claim while syslog configs target TCP 5515 (drift fails).

NOT proven here: that Vector / Fluent Bit / rsyslog / syslog-ng accept the
configs or emit the sample shapes (none is run). See docs/shipping/README.md.

Run: python tools/test_shipping_recipes.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "docs" / "shipping"
SERVICES = ROOT / "services"
WS2 = SERVICES / "ws2-normalization"
sys.path.insert(0, str(SERVICES))
sys.path.insert(0, str(WS2))

from adapters import ADAPTERS, adapt_record, docker_json, fluentbit_journald, fluentbit_winevtlog, winlogbeat  # noqa: E402
from main import normalize_one  # noqa: E402
from parsers import known_sources, resolve  # noqa: E402

SAMPLES = HERE / "samples"

# (sample file, recipe doc, declared source_type, shipper label or None,
#  parser expected after resolve(), OCSF class_uid, adapter constant it must equal or None)
CASES = [
    ("windows-sysmon.fluentbit.json", "windows.md", "windows_eventlog", "fluentbit-winevtlog", "sysmon", 1002, fluentbit_winevtlog.FIXTURE),
    ("windows-security.fluentbit.json", "windows.md", "windows_eventlog", "fluentbit-winevtlog", "windows_eventlog", 3002, fluentbit_winevtlog.SECURITY_FIXTURE),
    ("windows-4688.winlogbeat.json", "windows.md", "windows_eventlog", "winlogbeat", "windows_eventlog", 1002, winlogbeat.FIXTURE),
    ("windows-4624.winlogbeat.json", "windows.md", "windows_eventlog", "winlogbeat", "windows_eventlog", 3002, winlogbeat.SECURITY_LOGON_FIXTURE),
    ("linux-sshd.fluentbit-journald.json", "linux-auth.md", "generic_syslog", "fluentbit-journald", "linux_ssh", 3002, fluentbit_journald.FIXTURE),
    ("linux-sshd.vector.syslog.txt", "linux-auth.md", "generic_syslog", None, "linux_ssh", 3002, None),
    ("docker-n8n.fluentbit.json", "docker.md", "generic_syslog", "docker-json", "generic_syslog", 1002, docker_json.FIXTURE),
    ("docker-sshd.fluentbit.json", "docker.md", "generic_syslog", "docker-json", "linux_ssh", 3002, docker_json.SSH_FIXTURE),
    ("docker-n8n.vector.syslog.txt", "docker.md", "generic_syslog", None, "generic_syslog", 1002, None),
    ("dnsmasq.syslog.txt", "dnsmasq-pihole.md", "generic_syslog", None, "dns_query", 4002, None),
    ("dnsmasq.fluentbit-wrapped.syslog.txt", "dnsmasq-pihole.md", "generic_syslog", None, "dns_query", 4002, None),
    ("n8n-audit.json", "n8n.md", "n8n_audit", None, "n8n_audit", 6003, None),
    ("proxmox-sshd.syslog.txt", "network-gear.md", "generic_syslog", None, "linux_ssh", 3002, None),
    ("opnsense-sshd.syslog.txt", "network-gear.md", "generic_syslog", None, "linux_ssh", 3002, None),
    ("pfsense-filterlog.syslog.txt", "network-gear.md", "generic_syslog", None, "generic_syslog", 1002, None),
]


def _docker_host_is_name(line: str) -> str:
    """The Vector remap puts the container NAME in the host slot; the adapter puts the 12-hex id there."""
    m = re.match(r"^(<\d+>.{15}) (\S+) (\S+): ", line)
    return line.replace(f" {m.group(2)} {m.group(3)}: ", f" {m.group(3)} {m.group(3)}: ", 1) if m else line


# Vector-remap samples: adapter output line -> transformed into what the config's remap actually emits
# (journald remap prepends a hardcoded <38>; docker remap puts the name in the host slot).
ADAPTER_OUTPUT = {
    "linux-sshd.vector.syslog.txt": ("fluentbit-journald", fluentbit_journald.FIXTURE, lambda s: "<38>" + s),
    "docker-n8n.vector.syslog.txt": ("docker-json", docker_json.FIXTURE, _docker_host_is_name),
}

# config file -> (owning recipe doc, CASES sample whose source_type/shipper it must carry; None for syslog-socket configs)
CONFIGS = {
    "fluent-bit-windows.conf": ("windows.md", "windows-sysmon.fluentbit.json"),
    "fluent-bit-journald.conf": ("linux-auth.md", "linux-sshd.fluentbit-journald.json"),
    "fluent-bit-docker.conf": ("docker.md", "docker-n8n.fluentbit.json"),
    "fluent-bit-n8n.conf": ("n8n.md", "n8n-audit.json"),
    "vector-n8n.toml": ("n8n.md", "n8n-audit.json"),
    "vector-journald.toml": ("linux-auth.md", None),
    "vector-docker.toml": ("docker.md", None),
    "vector-dnsmasq.toml": ("dnsmasq-pihole.md", None),
    "fluent-bit-dnsmasq.conf": ("dnsmasq-pihole.md", None),
    "rsyslog-forward.conf": ("network-gear.md", None),
    "rsyslog-relay.conf": ("network-gear.md", None),
    "syslog-ng-forward.conf": ("network-gear.md", None),
    "syslog-ng-relay.conf": ("network-gear.md", None),
}
# supporting files that are not shipper configs themselves
SUPPORT = {"docker_ids.lua": "docker.md", "fluent-bit-docker-parsers.conf": "docker.md"}

FAILS: list[str] = []


def check(cond, label):
    if not cond:
        FAILS.append(label)


def check_config(name: str, text: str, doc_text: str, sample: str | None) -> list[str]:
    """Drift errors for one config: HTTP configs must carry the CASES source_type/shipper; syslog configs TCP 5515."""
    errs: list[str] = []
    m = re.search(r"^\s*URI\s+(\S+)", text, re.M) or re.search(r'^\s*uri\s*=\s*"([^"]+)"', text, re.M)
    if m:  # HTTP ingest config
        want = next(c for c in CASES if c[0] == sample)
        uri = urlsplit(m.group(1))
        st = parse_qs(uri.query).get("source_type", [None])[0]
        if uri.path != "/v1/ingest":
            errs.append(f"{name}: path {uri.path!r} is not /v1/ingest")
        if st != want[2]:
            errs.append(f"{name}: URI source_type {st!r} != CASES {want[2]!r}")
        sm = (re.search(r"^\s*Header\s+X-Fengarde-Shipper\s+(\S+)", text, re.M)
              or re.search(r'"X-Fengarde-Shipper"\s*=\s*"([^"]+)"', text))
        ship = sm.group(1) if sm else None
        if want[3] is not None and ship != want[3]:
            errs.append(f"{name}: X-Fengarde-Shipper {ship!r} != CASES {want[3]!r}")
        if want[3] is None and ship in ADAPTERS:
            errs.append(f"{name}: label {ship!r} would select a WS-2 adapter the recipe does not claim")
        if not re.search(r"\b8554\b", text):
            errs.append(f"{name}: HTTP ingest port 8554 not found")
        if ("Authorization" in text or "auth.token" in text) and "WARNING" not in text:
            errs.append(f"{name}: sends a bearer token without the cleartext WARNING comment")
    else:  # syslog TCP config
        ports = set(re.findall(r"(?i)\bport[\s=:\x22(]{0,30}(\d+)", text)) | set(re.findall(r':(\d{4,5})"', text))
        if "5515" not in ports or "5514" in ports:
            errs.append(f"{name}: syslog ports {sorted(ports)}; recipe claims TCP 5515")
        if not re.search(r"(?i)\btcp\b", text):
            errs.append(f"{name}: no tcp transport found, recipe claims TCP 5515")
        if "5515" not in doc_text:
            errs.append(f"{name}: owning doc does not state port 5515")
    return errs


def load(name: str):
    text = (SAMPLES / name).read_text(encoding="utf-8")
    return json.loads(text) if name.endswith(".json") else text.rstrip("\n")


def main() -> int:
    registered = set(known_sources())
    readme = (HERE / "README.md").read_text(encoding="utf-8")
    for sample, doc, st, shipper, want_parser, want_class, const in CASES:
        label = sample
        raw = load(sample)
        meta = {"received_at": 1673963483}
        if shipper:
            meta["shipper"] = shipper
        payload = {"source_type": st, "raw": raw, "meta": meta}
        check(st in registered, f"{label}: declared source_type {st!r} not registered")
        adapted = adapt_record(payload)
        parser = resolve(adapted)
        got = parser.SOURCE_TYPE if parser else None
        check(got == want_parser, f"{label}: resolved parser {got!r}, recipe claims {want_parser!r}")
        check(want_parser in registered, f"{label}: parser {want_parser!r} not in registry")
        event, errors = normalize_one(adapted)
        check(event is not None and not errors, f"{label}: no valid OCSF ({errors[:1]})")
        if event:
            check(event.get("class_uid") == want_class,
                  f"{label}: class_uid {event.get('class_uid')} != {want_class}")
        if const is not None:
            check(raw == const, f"{label}: sample differs from the adapter fixture constant")
        if sample in ADAPTER_OUTPUT:
            ship, rec, remap = ADAPTER_OUTPUT[sample]
            out = adapt_record({"source_type": "generic_syslog", "raw": rec,
                                "meta": {"shipper": ship, "received_at": 1}})["raw"]
            check(remap(out.rstrip("\n")) == raw, f"{label}: differs from the adapter output line as the remap would emit it")
        doc_text = (HERE / doc).read_text(encoding="utf-8")
        check(sample in doc_text, f"{label}: not referenced in {doc}")
        check(f"`{want_parser}`" in doc_text, f"{label}: {doc} does not name parser `{want_parser}`")
        check(sample in readme, f"{label}: missing from README table")

    # every sample file is used, every recipe doc is indexed in the README
    used = {c[0] for c in CASES}
    for p in SAMPLES.iterdir():
        check(p.name in used, f"unused sample file {p.name}")
    for doc in sorted({c[1] for c in CASES}):
        check(doc in readme, f"README does not link {doc}")

    # config blocks: ```<lang> <filename> ... ``` must equal docs/shipping/configs/<filename>
    n_blocks = 0
    for doc in sorted(HERE.glob("*.md")):
        for m in re.finditer(r"^```\w+ (\S+)\n(.*?)^```$", doc.read_text(encoding="utf-8"), re.S | re.M):
            n_blocks += 1
            cfg = HERE / "configs" / m.group(1)
            check(cfg.is_file(), f"{doc.name}: block names missing config {m.group(1)}")
            if cfg.is_file():
                check(cfg.read_text(encoding="utf-8") == m.group(2),
                      f"{doc.name}: block {m.group(1)} differs from configs/{m.group(1)}")
    check(n_blocks > 0, "no config blocks found")

    # each config must sit in a LABELLED fence of its owning recipe doc (prose mentions do not count), carry the
    # claimed source_type/shipper/port, and no config-looking fence may be unlabelled
    fenced = {d.name: {m.group(1) for m in re.finditer(r"^```\w+ (\S+)\n", d.read_text(encoding="utf-8"), re.M)}
              for d in HERE.glob("*.md")}
    for cfg in sorted((HERE / "configs").iterdir()):
        if cfg.name in SUPPORT:
            check(cfg.name in fenced.get(SUPPORT[cfg.name], ()), f"{cfg.name}: no labelled fence in {SUPPORT[cfg.name]}")
            continue
        check(cfg.name in CONFIGS, f"config {cfg.name} has no CONFIGS entry (test cannot check it)")
        if cfg.name not in CONFIGS:
            continue
        doc, sample = CONFIGS[cfg.name]
        check(cfg.name in fenced.get(doc, ()), f"{cfg.name}: no labelled code fence in {doc}")
        doc_text = (HERE / doc).read_text(encoding="utf-8")
        text = cfg.read_text(encoding="utf-8")
        for e in check_config(cfg.name, text, doc_text, sample):
            check(False, e)
        if cfg.name == "vector-n8n.toml":  # negative self-test: a drifted config MUST be flagged
            for old, new in (("source_type=n8n_audit", "source_type=bogus"), ("8554", "9999")):
                check(old in text and check_config(cfg.name, text.replace(old, new), doc_text, sample),
                      f"self-test: mutated {old!r} not detected")
        if cfg.name == "rsyslog-forward.conf":
            check(check_config(cfg.name, text.replace("5515", "5514"), doc_text, sample),
                  "self-test: mutated syslog port not detected")
    for d in HERE.glob("*.md"):
        for m in re.finditer(r"^```(ini|toml|lua|conf)[ \t]*$", d.read_text(encoding="utf-8"), re.M):
            check(False, f"{d.name}: unlabelled config-looking code fence ({m.group(1)})")

    if FAILS:
        print("FAIL")
        for f in FAILS:
            print("  -", f)
        return 1
    print(f"[OK] {len(CASES)} shipping samples -> real WS-2 path -> valid OCSF with the claimed parser; "
          f"{n_blocks} config blocks match configs/ (configs themselves NOT machine-linted here)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
