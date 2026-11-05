"""WP-1.4 shipping-recipe checks (zero-infra).

Every sample in docs/shipping/samples/ is run through the real WS-2 path
(adapt_record -> parsers.resolve -> parse -> OCSF validate, via normalize_one)
exactly as ws1 would hand it over, and must resolve to the parser the recipe
claims. Also checks that each recipe doc names that parser, the README table
lists every recipe, every named source_type is registered, adapter-fixture
samples equal the adapter module's constant, and fenced config blocks that
carry a filename stay byte-identical to docs/shipping/configs/.

NOT proven here: that Vector / Fluent Bit / rsyslog / syslog-ng accept the
configs or emit the sample shapes (none is run). See docs/shipping/README.md.

Run: python tools/test_shipping_recipes.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "docs" / "shipping"
SERVICES = ROOT / "services"
WS2 = SERVICES / "ws2-normalization"
sys.path.insert(0, str(SERVICES))
sys.path.insert(0, str(WS2))

from adapters import adapt_record, docker_json, fluentbit_journald, fluentbit_winevtlog, winlogbeat  # noqa: E402
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

# adapter-OUTPUT samples (the line a Vector remap must reproduce)
ADAPTER_OUTPUT = {
    "linux-sshd.vector.syslog.txt": ("fluentbit-journald", fluentbit_journald.FIXTURE),
    "docker-n8n.vector.syslog.txt": ("docker-json", docker_json.FIXTURE),
}

FAILS: list[str] = []


def check(cond, label):
    if not cond:
        FAILS.append(label)


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
            ship, rec = ADAPTER_OUTPUT[sample]
            out = adapt_record({"source_type": "generic_syslog", "raw": rec,
                                "meta": {"shipper": ship, "received_at": 1}})["raw"]
            check(out.rstrip("\n") == raw, f"{label}: differs from the adapter output line")
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
    md_text = "".join(d.read_text(encoding="utf-8") for d in HERE.glob("*.md"))
    for cfg in (HERE / "configs").iterdir():
        check(cfg.name in md_text, f"config {cfg.name} not embedded in any recipe")
    check(n_blocks > 0, "no config blocks found")

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
