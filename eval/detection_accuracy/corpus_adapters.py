"""Corpus adapters for the blind-recall lane.

An adapter turns a third-party labelled corpus into ``Scenario`` objects. The
ATT&CK label of every scenario is read from the DATASET'S OWN metadata or path
(never from FENGARDE: no rule id, rule name, oracle output or alert is visible
to an adapter -- ``test_blind_recall.py`` pins that).

Shipped in this first merge (each has a fixture-based positive control):

* ``SplunkAttackData``  -- splunk/attack_data (Apache-2.0). Unit = ONE YAML
  scenario with all of its ``datasets[]`` files merged and replayed together
  (17% of labelled YAMLs declare more than one file; combining Security with
  Sysmon changes which rules can fire). Label = the YAML's ``mitre_technique``
  list; the technique directory name is recorded as a cross-check and is the
  only label for the old-style YAMLs that carry a ``dataset:`` URL list and no
  ``mitre_technique``. Only Windows XML sources (``XmlWinEventLog:*``) are read;
  every other source (CloudTrail, linux_secure, k8s, suricata, ...) is reported
  as unsupported -> NO_PARSER, never silently skipped.
* ``EvtxToMitre``       -- mdecrevoisier/EVTX-to-MITRE-Attack (CC0-1.0). Unit =
  ONE ``.evtx`` file, label inherited from ``TAxxxx-<Tactic>/Txxxx[.yyy|.xxx]-<name>/``.
  ``.xxx`` is a family-level label (``sub_unspecified``); the sub-technique is
  never invented. Anything outside that layout is UNLABELLED.

Deferred (no fixture-backed control yet, so not shipped): linux_secure,
CloudTrail, k8s, OTRF Security-Datasets, EVTX-ATTACK-SAMPLES (tactic-level
labels only).

``python-evtx`` is imported lazily, only when a ``.evtx`` file is actually
read, so the blocking test passes without it.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from technique_match import normalize_technique  # noqa: E402

LFS_MAGIC = b"version https://git-lfs"
WIN_XML_PREFIX = "XmlWinEventLog:"
_TECH_DIR_RE = re.compile(r"^T1\d{3}(?:\.\d{3})?$")
_TACTIC_DIR_RE = re.compile(r"^(TA\d{4})[-_ ](.+)$")
_EVTX_TECH_DIR_RE = re.compile(r"^(T1\d{3})(?:\.(\d{3}|xxx))?(?:[-_ ].*)?$", re.IGNORECASE)


class ReaderUnavailable(RuntimeError):
    """A reader dependency (python-evtx) is not installed."""


def _evtx_module():
    """Lazy import so merely importing this module never needs python-evtx."""
    import evtx_eval as E  # noqa: PLC0415  (heavy: wires the WS-2/WS-4 imports)
    return E


@dataclass
class FileRef:
    path: Path
    rel: str                    # corpus-relative posix path, the stable id
    source: str | None          # dataset-declared source string, if any
    kind: str                   # 'winxml' | 'sniff' | 'evtx' | 'unsupported'
    state: str                  # 'present' | 'missing' | 'empty' | 'lfs_pointer'
    lfs_size: int | None = None

    @property
    def readable(self) -> bool:
        return self.state == "present"


@dataclass
class LoadResult:
    records: list = field(default_factory=list)   # supported records, time-sorted later
    total_records: int = 0                        # records read from supported-format files
    unparsed: dict = field(default_factory=dict)  # 'Channel:EID' -> n (no parser class)
    files_read: int = 0
    files_unsupported: int = 0
    unsupported_sources: list = field(default_factory=list)
    read_errors: int = 0
    reader_ok: bool = True


@dataclass
class Scenario:
    dataset_id: str
    corpus: str
    labels: list
    label_source: str
    files: list
    fetch_state: str            # present|partial|none_present|no_files_declared|yaml_error
    label_flags: dict = field(default_factory=dict)   # label -> [flags]
    dir_label: str | None = None
    label_dir_disagree: bool = False
    tactics: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    _loader: object = None

    @property
    def files_declared(self) -> int:
        return len(self.files)

    @property
    def files_present(self) -> int:
        return sum(1 for f in self.files if f.readable)

    @property
    def fetched(self) -> bool:
        return self.fetch_state in ("present", "partial", "yaml_error")

    def load(self) -> LoadResult:
        return self._loader(self) if self._loader else LoadResult()


# --------------------------------------------------------------- file helpers

def inspect_file(path: Path) -> tuple:
    """(state, lfs_size). A git-lfs pointer or an empty file is NOT data."""
    try:
        if not path.is_file():
            return "missing", None
        size = path.stat().st_size
        if size == 0:
            return "empty", None
        with path.open("rb") as fh:
            head = fh.read(256)
    except OSError:
        return "missing", None
    if head.startswith(LFS_MAGIC):
        m = re.search(rb"size\s+(\d+)", head)
        return "lfs_pointer", int(m.group(1)) if m else None
    return "present", None


def _file_ref(path: Path, rel: str, source, kind: str) -> FileRef:
    state, lfs_size = inspect_file(path)
    return FileRef(path=path, rel=rel, source=source, kind=kind, state=state,
                   lfs_size=lfs_size)


def _fetch_state(files: list) -> str:
    if not files:
        return "no_files_declared"
    present = sum(1 for f in files if f.readable)
    if present == 0:
        return "none_present"
    return "present" if present == len(files) else "partial"


def route_records(raw_records, result: LoadResult) -> None:
    """Fold raw extracted records into ``result`` with the same Channel routing
    evtx_eval.py / splunk_eval.py use: Security -> E.SUPPORTED, Sysmon ->
    E.SYSMON_IDS; everything else counts toward ``total_records`` and the
    ``unparsed`` histogram (so an unparseable-but-technique-relevant event id
    is visible in the result row instead of becoming a silent MISS)."""
    E = _evtx_module()
    for rec in raw_records:
        if rec is None:
            continue
        result.total_records += 1
        chan, eid = rec.get("Channel"), rec.get("EventID")
        ok = rec.get("TimeCreated") is not None and (
            (chan == "Security" and eid in E.SUPPORTED)
            or (chan == E.SYSMON_CHANNEL and eid in E.SYSMON_IDS))
        if ok:
            result.records.append(rec)
        else:
            key = f"{chan or '?'}:{eid}"
            result.unparsed[key] = result.unparsed.get(key, 0) + 1


def _xml_records(path: Path):
    import splunk_eval as S  # noqa: PLC0415
    E = _evtx_module()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    for block in S.iter_xml_events(text):
        yield E.extract_record(block)


def _sniff_is_xml(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            return fh.read(64).lstrip().startswith("<Event")
    except OSError:
        return False


# ------------------------------------------------------------- Splunk adapter

def _splunk_load(sc: Scenario) -> LoadResult:
    res = LoadResult()
    unsupported = set()
    for f in sorted(sc.files, key=lambda x: x.rel):
        if not f.readable:
            continue
        kind = f.kind
        if kind == "sniff":
            kind = "winxml" if _sniff_is_xml(f.path) else "unsupported"
        if kind != "winxml":
            res.files_unsupported += 1
            unsupported.add(f.source or "unknown_format")
            continue
        res.files_read += 1
        route_records(_xml_records(f.path), res)
    res.unsupported_sources = sorted(unsupported)
    return res


class SplunkAttackData:
    """splunk/attack_data adapter (Windows XML sources only)."""

    name = "splunk-attack-data"

    def __init__(self, root: Path):
        self.root = Path(root)
        self.base = self.root / "datasets" / "attack_techniques"

    def available(self) -> bool:
        return self.base.is_dir()

    def scenarios(self):
        if not self.base.is_dir():
            return
        ymls = sorted(self.base.rglob("*.yml"),
                      key=lambda p: p.relative_to(self.base).as_posix())
        for yml in ymls:
            yield self._scenario(yml)

    def _scenario(self, yml: Path) -> Scenario:
        rel = yml.relative_to(self.base)
        sid = rel.as_posix()
        dir_label = next((normalize_technique(p) for p in rel.parts[:-1]
                          if _TECH_DIR_RE.match(p)), None)
        try:
            doc = yaml.safe_load(yml.read_text(encoding="utf-8", errors="replace"))
        except (OSError, yaml.YAMLError):
            doc = None
        if not isinstance(doc, dict):
            return Scenario(dataset_id=sid, corpus=self.name, labels=[],
                            label_source="none", files=[], fetch_state="yaml_error",
                            dir_label=dir_label, notes=["yaml_unparseable"],
                            _loader=_splunk_load)

        raw_labels = doc.get("mitre_technique")
        if isinstance(raw_labels, str):
            raw_labels = [raw_labels]
        labels, flags = [], {}
        invalid = []
        for raw in raw_labels if isinstance(raw_labels, list) else []:
            n = normalize_technique(raw if isinstance(raw, str) else None)
            if n is None:
                invalid.append(str(raw))
            elif n not in labels:
                labels.append(n)
        label_source = "yaml:mitre_technique"
        disagree = False
        if labels:
            disagree = bool(dir_label) and dir_label not in labels
        elif dir_label:
            labels, label_source = [dir_label], "dirname"
        else:
            label_source = "none"
        notes = [f"invalid_label:{x}" for x in invalid]

        files = self._files(doc, yml)
        return Scenario(dataset_id=sid, corpus=self.name, labels=sorted(labels),
                        label_source=label_source, files=files,
                        fetch_state=_fetch_state(files), label_flags=flags,
                        dir_label=dir_label, label_dir_disagree=disagree,
                        notes=notes, _loader=_splunk_load)

    def _files(self, doc: dict, yml: Path) -> list:
        files = []
        root_res = self.root.resolve()
        entries = doc.get("datasets")
        if isinstance(entries, list):
            for e in entries:
                if not isinstance(e, dict) or not isinstance(e.get("path"), str):
                    continue
                p = (self.root / e["path"].lstrip("/")).resolve()
                try:
                    rel = p.relative_to(root_res).as_posix()
                except ValueError:
                    continue            # path escapes the corpus root: ignore
                src = e.get("source") if isinstance(e.get("source"), str) else None
                kind = "winxml" if src and src.startswith(WIN_XML_PREFIX) else "unsupported"
                files.append(_file_ref(p, rel, src, kind))
            return files
        urls = doc.get("dataset")
        if isinstance(urls, list):          # old-style: URL list, no source field
            for u in urls:
                if not isinstance(u, str) or not u.strip():
                    continue
                p = yml.parent / u.rstrip("/").rsplit("/", 1)[-1]
                try:
                    rel = p.resolve().relative_to(root_res).as_posix()
                except ValueError:
                    continue
                files.append(_file_ref(p, rel, None, "sniff"))
        return files


# --------------------------------------------------------- EVTX-to-MITRE adapter

def parse_evtx_to_mitre_path(parts) -> dict:
    """Label from a corpus-relative path split into parts.

    ``TA0006-Credential Access/T1110.xxx-Brut force/x.evtx`` ->
    technique 'T1110' with flag ``sub_unspecified``. Returns
    ``{technique, tactic, tactic_name, flags}``; ``technique`` is None when
    the path does not follow the layout (never guessed)."""
    out = {"technique": None, "tactic": None, "tactic_name": None, "flags": []}
    if len(parts) < 2:
        return out
    m = _TACTIC_DIR_RE.match(parts[0])
    if not m:
        return out
    out["tactic"], out["tactic_name"] = m.group(1), m.group(2)
    if len(parts) < 3:
        return out                          # file directly in a tactic folder
    t = _EVTX_TECH_DIR_RE.match(parts[1])
    if not t:
        return out
    base, sub = t.group(1).upper(), t.group(2)
    if sub is None:
        out["technique"] = base
    elif sub.lower() == "xxx":
        out["technique"] = base
        out["flags"].append("sub_unspecified")
    else:
        out["technique"] = f"{base}.{sub}"
    return out


def default_evtx_opener(path: Path):
    """Iterate the XML of every record of an .evtx file (python-evtx, lazy)."""
    try:
        from Evtx.Evtx import Evtx  # noqa: PLC0415
    except ImportError as exc:
        raise ReaderUnavailable("python-evtx not installed (pip install python-evtx)") from exc

    def gen():
        with Evtx(str(path)) as log:
            for rec in log.records():
                try:
                    yield rec.xml()
                except Exception:       # noqa: BLE001 -- one bad record must not kill the file
                    yield None
    return gen()


def _evtx_loader_factory(opener):
    def load(sc: Scenario) -> LoadResult:
        res = LoadResult()
        E = _evtx_module()
        for f in sc.files:
            if not f.readable:
                continue
            try:
                it = opener(f.path)
            except ReaderUnavailable:
                res.reader_ok = False
                return res
            res.files_read += 1
            try:
                recs = (E.extract_record(x) if isinstance(x, str) else None for x in it)
                route_records(recs, res)
            except Exception:           # noqa: BLE001 -- corrupt file: keep what was read
                res.read_errors += 1
        return res
    return load


class EvtxToMitre:
    """mdecrevoisier/EVTX-to-MITRE-Attack adapter."""

    name = "evtx-to-mitre"

    def __init__(self, root: Path, opener=None):
        self.root = Path(root)
        self._loader = _evtx_loader_factory(opener or default_evtx_opener)

    def available(self) -> bool:
        return self.root.is_dir()

    def scenarios(self):
        if not self.root.is_dir():
            return
        paths = [p for p in self.root.rglob("*.evtx")
                 if ".git" not in p.relative_to(self.root).parts]
        paths.sort(key=lambda p: p.relative_to(self.root).as_posix())
        for p in paths:
            rel = p.relative_to(self.root)
            parsed = parse_evtx_to_mitre_path(rel.parts)
            tech = parsed["technique"]
            files = [_file_ref(p, rel.as_posix(), None, "evtx")]
            yield Scenario(
                dataset_id=rel.as_posix(), corpus=self.name,
                labels=[tech] if tech else [],
                label_source="path:TAxxxx-<Tactic>/Txxxx[.yyy]-<name>" if tech else "none",
                files=files, fetch_state=_fetch_state(files),
                label_flags={tech: list(parsed["flags"])} if tech else {},
                dir_label=tech, tactics=[parsed["tactic"]] if parsed["tactic"] else [],
                _loader=self._loader)
