"""sysmon_tree -- shared helpers for the process-tree-keyed twin storylines (ADR-012 WP 7).

Not itself a storyline (its name does not match the registry's ``storyline_*`` glob). Pure functions
of their arguments: no wall clock, no randomness, no I/O.

TWO JOBS, deliberately kept apart:

  1. ``Host`` / ``Proc`` -- the BUILDER's own key generator. It mints Sysmon-shaped ProcessGuid
     values ({machine-part-time-part-sequence}) and writes them into the RAW Sysmon records
     (EventID 1 ``ProcessGuid`` / ``ParentProcessGuid``, EventID 3 ``ProcessGuid``, EventID 10
     ``SourceProcessGUID``). It does NOT import ``services/shared/causal_keys.py``: the truth
     must not share code with the thing it will later grade.

  2. ``derive_links`` -- reads the finished RAW payloads and returns the process-tree links they
     carry, as step pairs. It looks only at the key fields of the records, never at parser output,
     rules or alerts, so an oracle's ``causal_links`` derived from it is independent of WS-2 / WS-4 /
     WS-8. ``test_*`` of every keyed storyline pins the oracle to this derivation.

LINK DEFINITION (the one this harness grades; ADR-012 table row ``process_tree``, parent -> child):

    spawn          event B is a Sysmon EID 1 whose ``ParentProcessGuid`` equals the ``ProcessGuid`` of
                   an EID 1 event A on the same ``Computer``                  (A's process is B's parent)
    acting_process event B is a Sysmon EID 3 (``ProcessGuid``) or EID 10 (``SourceProcessGUID``)
                   whose acting process guid equals the ``ProcessGuid`` of an EID 1 event A on the same
                   ``Computer``                                               (B is done BY A's process)

A pair of raw events inside ONE step is a *candidate* but not a step link (a step is the unit the
oracle grades). The ADR table names only ``spawn``; ``acting_process`` is carried with its own ``via``
tag so a consumer that wants the strict table can filter it out.
"""
from __future__ import annotations

import hashlib

__all__ = ["Emitter", "Host", "Proc", "derive_links", "candidate_counts"]


def _h(*parts: str) -> str:
    return hashlib.sha1("\x1f".join(parts).encode("utf-8")).hexdigest()


class Emitter:
    """Collects ``(ChainStepSpec, payload)`` pairs for a builder: ingest ids are
    ``(step ordinal, position within the step)`` so a twin that adds or removes events of ONE step
    never renumbers a later one, and every ``meta`` carries the sending host's address twice --
    ``ip`` (the collector's partition key, via ``scenario_kit.meta``) and ``shipper_ip`` (the
    authenticated sender ADR-012 scope trust keys on)."""

    def __init__(self, seed: int, tag: str, steps: tuple):
        self.seed, self.tag = seed, tag
        self.specs = {s.label: s for s in steps}
        self._ordinal = {s.label: i for i, s in enumerate(steps)}
        self._seen: dict = {}
        self.payloads: list = []

    def add(self, label: str, source_type: str, raw: dict, ts: int, ip: str) -> None:
        from scenario_kit import meta  # noqa: PLC0415 - kept lazy so this module stays import-pure
        k = self._seen.get(label, 0)
        self._seen[label] = k + 1
        m = meta(self.seed, self.tag, self._ordinal[label] * 100 + k, ts, ip)
        m["shipper_ip"] = ip
        self.payloads.append((self.specs[label], {"source_type": source_type, "raw": raw, "meta": m}))


class Host:
    """One monitored machine: owns the machine part of every guid minted on it and a per-host counter."""

    def __init__(self, name: str, ip: str, seed: int):
        self.name = name
        self.ip = ip
        self._machine = _h("machine", name, str(seed))[:8]
        self._seq = 0

    def guid(self, start_ms: int) -> str:
        """``{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}``: machine part, process start time (epoch seconds, the
        two 16-bit halves in Sysmon's order), and a per-host sequence that makes it unique."""
        self._seq += 1
        secs = start_ms // 1000
        lo, hi = secs & 0xFFFF, (secs >> 16) & 0xFFFF
        return f"{{{self._machine}-{lo:04x}-{hi:04x}-{(self._seq >> 16) & 0xFFFF:04x}-{self._seq & 0xFFFFFFFFFFFF:012x}}}"

    def proc(self, image: str, cmd: str, user: str, start_ms: int, parent: "Proc | None" = None) -> "Proc":
        return Proc(self, image, cmd, user, start_ms, parent)


class Proc:
    """A process the builder has decided exists. ``create_record`` is its Sysmon EID 1; the other
    ``*_record`` methods are events done BY it."""

    def __init__(self, host: Host, image: str, cmd: str, user: str, start_ms: int, parent: "Proc | None"):
        self.host, self.image, self.cmd, self.user, self.start_ms, self.parent = host, image, cmd, user, start_ms, parent
        self.guid = host.guid(start_ms)
        self.pid = 1000 + (host._seq * 4) % 60000   # decimal, as Sysmon logs it

    # -- EID 1 -----------------------------------------------------------------
    def create_record(self) -> dict:
        p = self.parent
        rec = {
            "EventID": 1, "TimeCreated": self.start_ms, "Computer": self.host.name,
            "ProcessGuid": self.guid, "ProcessId": str(self.pid),
            "Image": self.image, "CommandLine": self.cmd, "User": self.user,
        }
        if p is not None:
            rec.update({"ParentProcessGuid": p.guid, "ParentProcessId": str(p.pid),
                        "ParentImage": p.image, "ParentCommandLine": p.cmd})
        return rec

    # -- EID 3 -----------------------------------------------------------------
    def connect_record(self, ts: int, dst_ip: str, dst_port: int, src_port: int) -> dict:
        return {
            "EventID": 3, "TimeCreated": ts, "Computer": self.host.name,
            "ProcessGuid": self.guid, "ProcessId": str(self.pid), "Image": self.image, "User": self.user,
            "Protocol": "tcp", "Initiated": "true",
            "SourceIp": self.host.ip, "SourceHostname": self.host.name, "SourcePort": str(src_port),
            "DestinationIp": dst_ip, "DestinationPort": str(dst_port),
        }

    # -- EID 10 ----------------------------------------------------------------
    def access_record(self, ts: int, target_image: str, target_guid: str, target_pid: int, mask: str) -> dict:
        return {
            "EventID": 10, "TimeCreated": ts, "Computer": self.host.name,
            "SourceProcessGUID": self.guid, "SourceProcessId": str(self.pid), "SourceImage": self.image,
            "TargetProcessGUID": target_guid, "TargetProcessId": str(target_pid), "TargetImage": target_image,
            "GrantedAccess": mask, "User": self.user,
        }


# ---------------------------------------------------------------------------
# Derivation from the RAW payloads (no parser, rule, alert or service import)
# ---------------------------------------------------------------------------
def _rec(payload: dict) -> dict:
    raw = payload.get("raw")
    return raw if isinstance(raw, dict) else {}


def _event_links(payloads: list) -> list:
    """Every event-level process-tree link: ``(i, j, via)`` with ``i``/``j`` positions in ``payloads``.
    Scope is the ``Computer`` field (a guid is only compared against records of its own machine)."""
    created: dict = {}      # (Computer, ProcessGuid) -> position of the EID 1 that created that process
    for i, (_spec, p) in enumerate(payloads):
        r = _rec(p)
        if p.get("source_type") == "sysmon" and str(r.get("EventID")) == "1" and r.get("ProcessGuid"):
            created.setdefault((r.get("Computer"), r["ProcessGuid"]), i)
    out = []
    for j, (_spec, p) in enumerate(payloads):
        if p.get("source_type") != "sysmon":
            continue
        r = _rec(p)
        eid = str(r.get("EventID"))
        if eid == "1" and r.get("ParentProcessGuid"):
            parent_pos = created.get((r.get("Computer"), r["ParentProcessGuid"]))
            if parent_pos is not None:
                out.append((parent_pos, j, "spawn"))
        elif eid in ("3", "10"):
            g = r.get("ProcessGuid") if eid == "3" else r.get("SourceProcessGUID")
            actor_pos = created.get((r.get("Computer"), g)) if g else None
            if actor_pos is not None:
                out.append((actor_pos, j, "acting_process"))
    return out


def derive_links(payloads: list, *, strict_table_only: bool = False) -> list:
    """Step-level links ``[{"from", "to", "basis": "process_tree", "via": ...}]`` sorted by
    (from, to, via), duplicates folded. ``strict_table_only`` keeps ``spawn`` only (ADR-012 table)."""
    seen: dict = {}
    for i, j, via in _event_links(payloads):
        a, b = payloads[i][0].label, payloads[j][0].label
        if a == b or (strict_table_only and via != "spawn"):
            continue
        # one link per step pair; ``spawn`` (the ADR table's rule) wins over ``acting_process`` when both hold
        if (a, b) not in seen or via == "spawn":
            seen[(a, b)] = {"from": a, "to": b, "basis": "process_tree", "via": via}
    return [seen[k] for k in sorted(seen)]


def candidate_counts(payloads: list) -> dict:
    """Event-level candidate counts: ``spawn`` / ``acting_process`` pairs, and how many cross a step boundary."""
    ev = _event_links(payloads)
    out = {"spawn": 0, "acting_process": 0, "cross_step": 0}
    for i, j, via in ev:
        out[via] += 1
        if payloads[i][0].label != payloads[j][0].label:
            out["cross_step"] += 1
    return out


# ---------------------------------------------------------------------------
# CLI: derive the ``causal_links:`` block of a storyline's oracle from its builder
# ---------------------------------------------------------------------------
def links_yaml(links: list) -> str:
    """The oracle's ``causal_links:`` block (flow style, one link per line), ending in a newline."""
    if not links:
        return "causal_links: []\n"
    rows = [f"  - {{from: {lk['from']}, to: {lk['to']}, basis: {lk['basis']}, via: {lk['via']}}}" for lk in links]
    return "causal_links:\n" + "\n".join(rows) + "\n"


def main(argv: list | None = None) -> int:  # pragma: no cover - authoring helper
    """``python eval/twin/sysmon_tree.py NAME [--write]``: print (or write into ``oracle_NAME.yaml``, replacing
    everything from its ``causal_links:`` line to the end of file) the links derived from the builder at seed 7."""
    import sys
    from pathlib import Path
    args = list(argv if argv is not None else sys.argv[1:])
    write = "--write" in args
    names = [a for a in args if not a.startswith("--")]
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import scenario_registry as reg  # noqa: PLC0415
    for name in names:
        sdef = reg.get(name)
        links = derive_links(sdef.build(7)[0])
        block = links_yaml(links)
        if not write:
            print(block, end="")
            continue
        path = Path(sdef.oracle_path)
        text = path.read_text(encoding="utf-8")
        i = text.index("\ncausal_links:")
        path.write_text(text[: i + 1] + block, encoding="utf-8")
        print(f"wrote {len(links)} links to {path.name}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
