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
configs or emit the sample shapes (this test runs none of them). They were linted and run live once by hand
(2026-11-05, container images; pihole-v6.dnsmasq.txt is a capture from the pihole/pihole image);
see the Verification log in docs/shipping/README.md.

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
sys.path.append(str(SERVICES / "ws4-detection"))  # appended: ws2's `main`/`parsers` must win name lookups

from engine import load_rules  # noqa: E402  (ws4 detection engine: evaluates a rule on a normalized event)
from adapters import ADAPTERS, adapt_record, docker_json, fluentbit_journald, fluentbit_winevtlog, winlogbeat  # noqa: E402
from main import normalize_one  # noqa: E402
from parsers import known_sources, resolve  # noqa: E402

SAMPLES = HERE / "samples"
PIHOLE_CAPTURE = "pihole-v6.dnsmasq.txt"
WIN_CAPTURE = "windows-application.fluentbit.json"  # real: Fluent Bit 4.2.8, Windows 11, Application channel

# (sample file, recipe doc, declared source_type, shipper label or None,
#  parser expected after resolve(), OCSF class_uid, adapter constant it must equal or None)
CASES = [
    ("windows-sysmon.fluentbit.json", "windows.md", "windows_eventlog",
     "fluentbit-winevtlog", "sysmon", 1002, fluentbit_winevtlog.FIXTURE),
    ("windows-sysmon-eventdata.fluentbit.json", "windows.md", "windows_eventlog",
     "fluentbit-winevtlog", "sysmon", 1002, None),
    ("windows-security.fluentbit.json", "windows.md", "windows_eventlog",
     "fluentbit-winevtlog", "windows_eventlog", 3002, fluentbit_winevtlog.SECURITY_FIXTURE),
    ("windows-4688.winlogbeat.json", "windows.md", "windows_eventlog", "winlogbeat", "windows_eventlog", 1002, winlogbeat.FIXTURE),
    ("windows-4624.winlogbeat.json", "windows.md", "windows_eventlog",
     "winlogbeat", "windows_eventlog", 3002, winlogbeat.SECURITY_LOGON_FIXTURE),
    ("linux-sshd.fluentbit-journald.json", "linux-auth.md", "generic_syslog",
     "fluentbit-journald", "linux_ssh", 3002, fluentbit_journald.FIXTURE),
    ("linux-sshd-session.journald.json", "linux-auth.md", "generic_syslog",
     "fluentbit-journald", "linux_ssh", 3002, None),
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
SUPPORT = {"docker_ids.lua": "docker.md", "fluent-bit-docker-parsers.conf": "docker.md", "fluent-bit-n8n-parsers.conf": "n8n.md"}

FAILS: list[str] = []


def check(cond, label):
    if not cond:
        FAILS.append(label)


#: Closed set of sample provenance classes. Every sample must be listed here AND its README row must open with that class.
#: Only "captured" may be called a capture / real record anywhere in the docs.
PROVENANCE = {
    "windows-sysmon.fluentbit.json": "hand-transcribed",
    "windows-sysmon-eventdata.fluentbit.json": "template-derived",
    "windows-application.fluentbit.json": "captured",
    "windows-security.fluentbit.json": "template-derived",
    "windows-4688.winlogbeat.json": "template-derived",
    "windows-4624.winlogbeat.json": "template-derived",
    "linux-sshd.fluentbit-journald.json": "schema-derived",
    "linux-sshd-session.journald.json": "captured",
    "linux-sshd.vector.syslog.txt": "adapter-output",
    "docker-n8n.fluentbit.json": "documented",
    "docker-sshd.fluentbit.json": "documented",
    "docker-n8n.vector.syslog.txt": "adapter-output",
    "dnsmasq.syslog.txt": "documented",
    "dnsmasq.fluentbit-wrapped.syslog.txt": "template-derived",
    "pihole-v6.dnsmasq.txt": "captured",
    "n8n-audit.json": "documented",
    "proxmox-sshd.syslog.txt": "illustrative",
    "opnsense-sshd.syslog.txt": "illustrative",
    "pfsense-filterlog.syslog.txt": "illustrative",
}
#: README provenance cell must open with one of these phrases for its class
PROV_OPENING = {
    "captured": r"captured?\b", "hand-transcribed": r"hand transcription", "template-derived": r"template-derived",
    "schema-derived": r"schema-derived", "adapter-output": r"adapter output", "documented": r"documented",
    "illustrative": r"illustrative",
}


def check_provenance(readme: str, docs: dict[str, str], sample_names: set[str]) -> list[str]:
    """Drift errors: one provenance class per sample (closed set), README row agrees, nothing but a capture is called one."""
    errs: list[str] = []
    for n in sorted(sample_names - set(PROVENANCE)):
        errs.append(f"sample {n}: no provenance class in PROVENANCE")
    for n in sorted(set(PROVENANCE) - sample_names):
        errs.append(f"PROVENANCE lists {n}, which is not a sample file")
    for n, cls in PROVENANCE.items():
        if cls not in PROV_OPENING:
            errs.append(f"{n}: provenance {cls!r} is not in the closed set")
    seen: set[str] = set()
    for row in readme.splitlines():
        if not row.startswith("|"):
            continue
        cells = [c.strip() for c in row.strip().strip("|").split("|")]
        files = re.findall(r"\(samples/([^)]+)\)", row)
        if len(files) != 1:
            if files:
                errs.append(f"README row carries {len(files)} samples, needs exactly one: {files}")
            continue
        n = files[0]
        seen.add(n)
        pcls = PROVENANCE.get(n)
        if pcls in PROV_OPENING and not re.match(PROV_OPENING[pcls], cells[-1], re.I):
            errs.append(f"README provenance for {n} must open as {pcls!r}, says {cells[-1][:50]!r}")
    for n in sorted(sample_names - seen):
        errs.append(f"README table has no row for {n}")
    captured = {n for n, c in PROVENANCE.items() if c == "captured"}
    for dn, dt in docs.items():
        for m in re.finditer(r"\[([^\]]*)\]\(samples/([^)]+)\)", dt):
            if m.group(2) in captured:
                continue
            txt = re.sub(r"\bnot an? (?:\w+ )?capture\b", "", m.group(1), flags=re.I)
            if re.search(r"\breal\b|captur", txt, re.I):
                errs.append(f"{dn}: link text calls non-captured sample {m.group(2)} real/captured: {m.group(1)[:60]!r}")
        for ln in dt.splitlines():
            if re.search(r"\breal (?:capture|record)\b", ln, re.I) and not any(c in ln for c in captured) and not re.search(r"\bnot an? (?:\w+ )?capture\b", ln, re.I):  # noqa: E501
                errs.append(f"{dn}: 'real capture/record' on a line naming no captured sample: {ln.strip()[:80]!r}")
        for ln in dt.splitlines():
            if re.search(r"samples are still adapter fixtures / templates, not captures|not captures;", ln):
                errs.append(f"{dn}: blanket 'not captures' contradicts the captured samples: {ln.strip()[:80]!r}")
    return errs


def _sections(text: str) -> list[tuple[str, str]]:
    """(header, body) of every [section] with comment lines dropped (Fluent Bit ini and Vector toml)."""
    out: list[tuple[str, list[str]]] = []
    for ln in text.splitlines():
        if ln.lstrip().startswith("#"):
            continue
        h = re.match(r"^\s*\[([^\]]+)\]\s*$", ln)
        if h:
            out.append((h.group(1).strip(), []))
        elif out:
            out[-1][1].append(ln)
    return [(h, "\n".join(b)) for h, b in out]


def output_construct(name: str, text: str) -> str:
    """The part of a config that IS the output (comments dropped): Fluent Bit [OUTPUT], Vector [sinks.*], rsyslog omfwd action,
    syslog-ng destination. Anything outside it (comments, inputs, other sections) must not satisfy a port/URI/auth check."""
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    if name.startswith("fluent-bit"):
        return "\n".join(b for h, b in _sections(text) if h.upper() == "OUTPUT")
    if name.endswith(".toml"):
        return "\n".join(b for h, b in _sections(text) if h.startswith("sinks."))
    if name.startswith("rsyslog"):
        return "\n".join(re.findall(r'action\(type="omfwd".*?\)', code, re.S))
    if name.startswith("syslog-ng"):
        return "\n".join(re.findall(r"destination\s+\w+\s*\{.*?\};", code, re.S))
    return ""


def check_config(name: str, text: str, doc_text: str, sample: str | None) -> list[str]:
    """Drift errors for one config: HTTP configs must carry the CASES source_type/shipper; syslog configs TCP 5515.

    Port, transport, URI and Authorization are read from the OUTPUT construct only (not from comments or inputs); the cleartext
    WARNING must be a comment line in the first 5 lines.
    """
    errs: list[str] = []
    out = output_construct(name, text)
    if not out:
        return [f"{name}: no output section/sink/action found"]
    m = re.search(r"^\s*URI\s+(\S+)", out, re.M) or re.search(r'^\s*uri\s*=\s*"([^"]+)"', out, re.M)
    pm = re.search(r'(?i)\bport\s*[=( ]\s*"?(\d+)', out) or re.search(r':(\d{2,5})(?:["/]|$)', out, re.M)
    port = pm.group(1) if pm else None
    if m:  # HTTP ingest config
        want = next(c for c in CASES if c[0] == sample)
        uri = urlsplit(m.group(1))
        st = parse_qs(uri.query).get("source_type", [None])[0]
        if uri.path != "/v1/ingest":
            errs.append(f"{name}: path {uri.path!r} is not /v1/ingest")
        if st != want[2]:
            errs.append(f"{name}: URI source_type {st!r} != CASES {want[2]!r}")
        sm = (re.search(r"^\s*Header\s+X-Fengarde-Shipper\s+(\S+)", out, re.M)
              or re.search(r'"X-Fengarde-Shipper"\s*=\s*"([^"]+)"', out))
        ship = sm.group(1) if sm else None
        if want[3] is not None and ship != want[3]:
            errs.append(f"{name}: X-Fengarde-Shipper {ship!r} != CASES {want[3]!r}")
        if want[3] is None and ship in ADAPTERS:
            errs.append(f"{name}: label {ship!r} would select a WS-2 adapter the recipe does not claim")
        if port != "8554":
            errs.append(f"{name}: output section port {port!r}, recipe claims HTTP ingest 8554")
        if re.search(r"(?i)authorization|auth\.token", out) and not any(
                ln.lstrip().startswith("#") and "WARNING" in ln for ln in text.splitlines()[:5]):
            errs.append(f"{name}: sends a bearer token without the cleartext WARNING comment in its first 5 lines")
    else:  # syslog TCP config
        tm = re.search(r'(?i)\b(?:protocol|transport|mode)\s*[=( ]\s*"?(tcp|udp)', out)
        if port != "5515":
            errs.append(f"{name}: output section port {port!r}; recipe claims TCP 5515")
        if not tm or tm.group(1).lower() != "tcp":
            errs.append(f"{name}: output transport {tm and tm.group(1)!r}, recipe claims TCP 5515")
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
        meta: dict[str, object] = {"received_at": 1673963483}
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

    # real capture (pihole/pihole 2026.10.1, scrubbed): every line through the Vector path (<30> prefix) and the Fluent Bit
    # path (header as observed); `query[...]` lines must become dns_query 4002 naming the queried host, nothing else may
    lines = (SAMPLES / PIHOLE_CAPTURE).read_text(encoding="utf-8").splitlines()
    n_q = 0
    for ln in lines:
        is_q = bool(re.search(r"dnsmasq\[\d+\]: query\[", ln))
        n_q += is_q
        for tag, raw in (("vector", "<30>" + ln), ("fluentbit", "<14>Nov  5 09:17:30 pihole01 fluent-bit: " + ln)):
            adapted = adapt_record({"source_type": "generic_syslog", "raw": raw, "meta": {"received_at": 1673963483}})
            p_ = resolve(adapted)
            got = p_.SOURCE_TYPE if p_ else None
            check((got == "dns_query") == is_q, f"{PIHOLE_CAPTURE} [{tag}]: {ln!r} resolved to {got!r}")
            if is_q:
                ev, errs = normalize_one(adapted)
                host = ln.split("] ", 1)[1].split()[0]
                check(ev is not None and not errs and ev.get("class_uid") == 4002
                      and ev["dst_endpoint"]["hostname"] == host, f"{PIHOLE_CAPTURE} [{tag}]: {ln!r} -> {errs[:1]}")
    check(n_q == 25 and len(lines) == 81, f"{PIHOLE_CAPTURE}: expected 81 lines / 25 queries, got {len(lines)} / {n_q}")
    check(not re.search(r"\b172\.(1[6-9]|2\d|3[01])\.", "\n".join(lines)), f"{PIHOLE_CAPTURE}: unscrubbed host address")
    check(PIHOLE_CAPTURE in (HERE / "dnsmasq-pihole.md").read_text(encoding="utf-8"),
          f"{PIHOLE_CAPTURE}: not referenced in dnsmasq-pihole.md")
    check(PIHOLE_CAPTURE in readme, f"{PIHOLE_CAPTURE}: missing from README table")

    # real capture (Fluent Bit 4.2.8 on Windows 11, Application channel, scrubbed): nested EventData must be flattened and the
    # record must reach the windows_eventlog parser; WER 1001 has no EventID mapping so it must yield NO event (not a mis-parse)
    wraw = load(WIN_CAPTURE)
    check(wraw == fluentbit_winevtlog.CAPTURED_WIN11_APPLICATION, f"{WIN_CAPTURE}: differs from CAPTURED_WIN11_APPLICATION")
    check(wraw.get("Computer") == "WIN11-LAB" and "DESKTOP-" not in json.dumps(wraw), f"{WIN_CAPTURE}: unscrubbed host name")
    wad = adapt_record({"source_type": "windows_eventlog", "raw": wraw,
                        "meta": {"received_at": 1673963483, "shipper": "fluentbit-winevtlog"}})
    wp = resolve(wad)
    check(wp is not None and wp.SOURCE_TYPE == "windows_eventlog", f"{WIN_CAPTURE}: resolved {getattr(wp, 'SOURCE_TYPE', None)!r}")
    check("EventData" not in wad["raw"] and wad["raw"].get("EventName") == "crashpad_log", f"{WIN_CAPTURE}: EventData not flattened")
    wev, werrs = normalize_one(wad)
    check(wev is None and werrs, f"{WIN_CAPTURE}: expected an unmapped (no event) result, got {wev and wev.get('class_uid')}")
    check(WIN_CAPTURE in (HERE / "windows.md").read_text(encoding="utf-8"), f"{WIN_CAPTURE}: not referenced in windows.md")
    check(WIN_CAPTURE in readme, f"{WIN_CAPTURE}: missing from README table")

    # Sysmon field mapping (the parser-name/class check above proves nothing about fields). The 2023 hand transcription predates
    # Event_Data_As_Map, so it resolves to `sysmon` but maps NOTHING: assert that known limitation explicitly. The template-derived
    # sample in the real nested-EventData shape must yield image, command line, user, parent image and pid.
    meta_ = {"received_at": 1673963483, "shipper": "fluentbit-winevtlog"}
    old_ev, _ = normalize_one(adapt_record({"source_type": "windows_eventlog",
                                            "raw": load("windows-sysmon.fluentbit.json"), "meta": dict(meta_)}))
    check(old_ev is not None and old_ev["message"] == "Process created: ? (by ?)" and "actor" not in old_ev
          and old_ev["unmapped"]["process_launch"] == {"suspicious": False},
          f"windows-sysmon.fluentbit.json: known no-field-mapping limitation changed: {old_ev and old_ev.get('message')!r}")
    new_ev, _ = normalize_one(adapt_record({"source_type": "windows_eventlog",
                                            "raw": load("windows-sysmon-eventdata.fluentbit.json"), "meta": dict(meta_)}))
    pl = (new_ev or {}).get("unmapped", {}).get("process_launch", {})
    act = (new_ev or {}).get("actor", {})
    check(new_ev is not None and act.get("process") == {"name": r"C:\Windows\System32\cmd.exe", "pid": 8844}
          and act.get("user") == {"name": r"WIN11-LAB\labuser"} and pl.get("image") == r"C:\Windows\System32\cmd.exe"
          and pl.get("command_line") == "cmd.exe /c whoami" and pl.get("parent") == r"C:\Windows\explorer.exe"
          and "?" not in new_ev["message"], f"windows-sysmon-eventdata.fluentbit.json: field mapping wrong: {new_ev}")

    # System 7045 in the REAL Fluent Bit shape (envelope as in WIN_CAPTURE: no EventData map, StringInserts only; values invented)
    # must fire win_service_installed_suspicious_path through the ws4 engine, and a System32 service must not
    def svc_event(path: str, named: dict | None = None):
        rec = {k: v for k, v in load(WIN_CAPTURE).items() if k not in ("EventData", "Message")}
        rec.update(ProviderName="Service Control Manager", Channel="System", EventID=7045, Computer="WIN11-LAB",
                   StringInserts=["Updater", path, "user mode service", "auto start", "LocalSystem"])
        if named:
            rec["EventData"] = named  # the adapter flattens it to the top level, as for a real nested map
        ev_, errs_ = normalize_one(adapt_record({"source_type": "windows_eventlog", "raw": rec, "meta": dict(meta_)}))
        check(ev_ is not None and not errs_, f"System 7045 ({path}, named={named}): no valid OCSF {errs_[:1]}")
        return ev_
    svc_rule = next(r for r in load_rules(ROOT / "contracts" / "rules") if r.title == "Service installed from a suspicious path")
    bad_svc, good_svc = svc_event(r"C:\Users\labuser\AppData\Local\Temp\u.exe"), svc_event(r"C:\Windows\System32\spoolsv.exe")
    check(bad_svc is not None and "Updater -> C:" in bad_svc["message"] and svc_rule.evaluate(bad_svc),
          "System 7045 (StringInserts only) in a Temp path must fire win_service_installed_suspicious_path")
    check(good_svc is not None and not svc_rule.evaluate(good_svc), "System 7045 in System32 must not fire the rule")
    # MIXED named + positional: the named field wins PER FIELD. Name named, path positional (Temp) -> named name, positional path, fires;  # noqa: E501
    # path named (System32), name+path positional (Temp) -> named path wins, positional name used, must not fire
    tmp_path, sys_path = r"C:\Users\labuser\AppData\Local\Temp\u.exe", r"C:\Windows\System32\spoolsv.exe"
    mix_a = svc_event(tmp_path, {"ServiceName": "NamedSvc"})
    check(mix_a is not None and mix_a["message"].startswith("Service installed: NamedSvc -> C:\\Users") and svc_rule.evaluate(mix_a),
          f"System 7045 mixed (named name, positional Temp path) wrong: {mix_a and mix_a['message']!r}")
    mix_b = svc_event(tmp_path, {"ImagePath": sys_path})
    check(mix_b is not None and "Updater -> C:\\Windows\\System32" in mix_b["message"] and not svc_rule.evaluate(mix_b),
          f"System 7045 mixed (named System32 path beats positional Temp path) wrong: {mix_b and mix_b['message']!r}")

    # every sample file is used, every recipe doc is indexed in the README
    used = {c[0] for c in CASES} | {PIHOLE_CAPTURE, WIN_CAPTURE}
    for p in SAMPLES.iterdir():
        check(p.name in used, f"unused sample file {p.name}")
    for doc in sorted({c[1] for c in CASES}):
        check(doc in readme, f"README does not link {doc}")

    # provenance: one closed-set class per sample, README rows agree, only captures are called captures/real
    docs_text = {d.name: d.read_text(encoding="utf-8") for d in HERE.glob("*.md")}
    sample_names = {p.name for p in SAMPLES.iterdir()}
    for e in check_provenance(readme, docs_text, sample_names):
        check(False, e)
    # negative self-tests: each drift below MUST be reported
    bad_docs = dict(docs_text, **{"windows.md": docs_text["windows.md"] + "\n[real record](samples/windows-4624.winlogbeat.json)\n"})
    check(check_provenance(readme, bad_docs, sample_names), "self-test: a non-captured sample called a real record not detected")
    bad_line = dict(docs_text, **{"docker.md": docs_text["docker.md"] + "\nThis is a real capture of n8n.\n"})
    check(check_provenance(readme, bad_line, sample_names), "self-test: 'real capture' on a line naming no captured sample not detected")  # noqa: E501
    row = next(ln for ln in readme.splitlines() if "windows-security.fluentbit.json" in ln)
    check(check_provenance(readme.replace(row, row.rsplit("| template-derived", 1)[0] + "| captured on a laptop |"), docs_text, sample_names),  # noqa: E501
          "self-test: README class disagreeing with PROVENANCE not detected")
    check(check_provenance(readme.replace(row, ""), docs_text, sample_names), "self-test: sample missing from the README table not detected")  # noqa: E501
    check(check_provenance(readme, docs_text, sample_names | {"new-unclassified.json"}), "self-test: unclassified sample not detected")

    # config blocks: ```<lang> <filename> ... ``` must equal docs/shipping/configs/<filename>
    n_blocks = 0
    for md in sorted(HERE.glob("*.md")):
        for m in re.finditer(r"^```\w+ (\S+)\n(.*?)^```$", md.read_text(encoding="utf-8"), re.S | re.M):
            n_blocks += 1
            cfg = HERE / "configs" / m.group(1)
            check(cfg.is_file(), f"{md.name}: block names missing config {m.group(1)}")
            if cfg.is_file():
                check(cfg.read_text(encoding="utf-8") == m.group(2),
                      f"{md.name}: block {m.group(1)} differs from configs/{m.group(1)}")
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
        owner_doc, cfg_sample = CONFIGS[cfg.name]
        check(cfg.name in fenced.get(owner_doc, ()), f"{cfg.name}: no labelled code fence in {owner_doc}")
        doc_text = (HERE / owner_doc).read_text(encoding="utf-8")
        text = cfg.read_text(encoding="utf-8")
        for e in check_config(cfg.name, text, doc_text, cfg_sample):
            check(False, e)
        # negative self-tests: each mutation MUST be reported (and a decoy elsewhere in the file must not satisfy the check)
        muts: list[tuple[str, str]] = []
        if cfg.name == "vector-n8n.toml":
            muts = [("source_type bogus", text.replace("source_type=n8n_audit", "source_type=bogus")),
                    ("port moved, old port left in a comment", "# decoy 8554\n" + text.replace(":8554/", ":9999/")),
                    ("WARNING comment moved out of the first 5 lines", "\n".join(ln for ln in text.splitlines() if "WARNING" not in ln) + "\n# WARNING: late\n"),  # noqa: E501
                    ("WARNING only in a non-comment line", text.replace("# WARNING:", "WARNING:"))]
        if cfg.name == "fluent-bit-docker.conf":
            muts = [("Port moved, decoy in an [INPUT]-side comment", text.replace("Port             8554", "Port             9999").replace("[SERVICE]", "# Port 8554\n[SERVICE]", 1)),  # noqa: E501
                    ("WARNING comment removed", "\n".join(ln for ln in text.splitlines() if "WARNING" not in ln) + "\n")]
        if cfg.name == "rsyslog-forward.conf":
            muts = [("syslog port", text.replace("5515", "5514")),
                    ("port moved, decoy in a comment", text.replace('Port="5515"', 'Port="5514"') + '\n# omfwd Port="5515" Protocol="tcp"\n'),  # noqa: E501
                    ("transport udp", text.replace('Protocol="tcp"', 'Protocol="udp"'))]
        if cfg.name == "syslog-ng-forward.conf":
            muts = [("transport udp", text.replace('transport("tcp")', 'transport("udp")')),
                    ("port moved, decoy in a comment", text.replace("port(5515)", "port(5514)") + "# network(port(5515) transport(\"tcp\"))\n")]  # noqa: E501
        if cfg.name == "vector-journald.toml":
            muts = [("address port moved, decoy in a comment", text.replace(":5515", ":5514") + "# address = 192.0.2.10:5515\n")]
        for label, mutated in muts:
            check(mutated != text and check_config(cfg.name, mutated, doc_text, cfg_sample),
                  f"self-test: {cfg.name} mutation ({label}) not detected")
    for d in HERE.glob("*.md"):
        for m in re.finditer(r"^```(ini|toml|lua|conf)[ \t]*$", d.read_text(encoding="utf-8"), re.M):
            check(False, f"{d.name}: unlabelled config-looking code fence ({m.group(1)})")

    if FAILS:
        print("FAIL")
        for f in FAILS:
            print("  -", f)
        return 1
    print(f"[OK] {len(CASES)} shipping samples -> real WS-2 path -> valid OCSF with the claimed parser; "
          f"{n_blocks} config blocks match configs/ (shipper configs are not executed by this test)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
