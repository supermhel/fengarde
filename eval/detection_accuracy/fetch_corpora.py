"""Fetch the third-party corpora of the detection-accuracy lanes (on demand).

Nothing is vendored. Each corpus in ``corpus_manifest.json`` is fetched into its
gitignored ``dest`` directory at the manifest ``pin`` (``git fetch --depth 1
origin <sha>`` then a detached checkout: a plain ``--depth 1`` clone cannot
reach an arbitrary pinned commit). The checked-out HEAD is verified against the
pin; a mismatch is a hard failure.

splunk/attack_data stores its data files in git-lfs (> 9 GB in full). The
checkout therefore runs with ``GIT_LFS_SKIP_SMUDGE=1`` (pointer files only) and
only the files chosen by a PRE-REGISTERED selection predicate are pulled with
``git lfs pull --include=<those paths>``. The predicate may use only dataset
metadata (YAML source, label) and the rule technique families -- never whether
anything fires -- so the subset cannot be cherry-picked by outcome.

A pull that did not deliver a file is reported as ``still_pointer`` (the file
stays an un-pulled pointer and blind_recall.py buckets the dataset NOT_FETCHED);
it is never silently treated as data, and any pull failure makes this script
exit 1 so a nightly cannot continue on a half-fetched corpus.

Never part of run_all_tests.sh.

    python eval/detection_accuracy/fetch_corpora.py                 # blind-recall corpora
    python eval/detection_accuracy/fetch_corpora.py --corpus splunk-attack-data --dry-run
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

DEFAULT_MANIFEST = HERE / "corpus_manifest.json"
SHA_LEN = 40


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_manifest(doc)
    return doc


def validate_manifest(doc: dict) -> None:
    """Raise ValueError on a manifest the fetcher cannot trust."""
    if doc.get("_schema") != "1" or not isinstance(doc.get("corpora"), dict):
        raise ValueError("manifest: bad _schema / corpora")
    for name, c in doc["corpora"].items():
        for key in ("url", "dest", "license_spdx", "label_source", "lanes"):
            if not c.get(key):
                raise ValueError(f"manifest[{name}]: missing {key}")
        pin = c.get("pin")
        if pin is not None and not (isinstance(pin, str) and len(pin) == SHA_LEN
                                    and all(ch in "0123456789abcdef" for ch in pin)):
            raise ValueError(f"manifest[{name}]: pin must be a 40-hex commit sha or null")
        if not c["url"].startswith("https://") and not c.get("allow_local_url"):
            raise ValueError(f"manifest[{name}]: url must be https")
        if c.get("redistributable") is False and c.get("vendored"):
            raise ValueError(f"manifest[{name}]: non-redistributable corpus marked vendored")
        dest = str(c["dest"])
        if (dest.startswith(("/", "\\")) or (len(dest) > 1 and dest[1] == ":")
                or ".." in Path(dest).parts):
            raise ValueError(f"manifest[{name}]: dest must be a relative path inside the lane dir")


# ------------------------------------------------------------------- git

def _git(args: list, cwd: Path, env_extra: dict | None = None, run=subprocess.run):
    env = dict(os.environ)
    env.update(env_extra or {})
    return run(["git", *args], cwd=str(cwd), env=env, capture_output=True, text=True)


def head_sha(directory: Path, run=subprocess.run) -> str | None:
    """HEAD of ``directory`` iff it is itself a git work tree root (a fixture
    dir nested in some outer repo must not report the outer repo's HEAD)."""
    d = Path(directory)
    if not (d / ".git").exists():
        return None
    r = _git(["rev-parse", "HEAD"], d, run=run)
    return r.stdout.strip() if r.returncode == 0 else None


def fetch_corpus(name: str, entry: dict, dest: Path, *, run=subprocess.run,
                 dry_run: bool = False) -> dict:
    """Fetch + checkout one corpus. Returns a status dict; ``ok`` False on any
    failure (nothing is swallowed)."""
    ref = entry.get("pin") or "HEAD"
    status = {"corpus": name, "dest": str(dest), "ref": ref, "ok": False,
              "head": None, "pin_matches": None, "errors": []}
    plan = [["init", "-q"],
            ["remote", "add", "origin", entry["url"]],
            ["fetch", "--depth", "1", "origin", ref]]
    if entry.get("sparse_paths"):
        plan.append(["sparse-checkout", "set", "--no-cone", *entry["sparse_paths"]])
    plan.append(["checkout", "-q", "--detach", "FETCH_HEAD"])
    if dry_run:
        status["plan"] = [" ".join(["git", *p]) for p in plan]
        status["ok"] = True
        return status

    dest.mkdir(parents=True, exist_ok=True)
    skip = {"GIT_LFS_SKIP_SMUDGE": "1"}
    if (dest / ".git").exists():
        plan = [p for p in plan if p[0] not in ("init", "remote")]
        _git(["remote", "set-url", "origin", entry["url"]], dest, skip, run)
    for step in plan:
        r = _git(step, dest, skip, run)
        if r.returncode != 0:
            status["errors"].append(f'git {" ".join(step)}: {(r.stderr or r.stdout).strip()[:300]}')
            return status
    status["head"] = head_sha(dest, run)
    if entry.get("pin"):
        status["pin_matches"] = status["head"] == entry["pin"]
        if not status["pin_matches"]:
            status["errors"].append(f'HEAD {status["head"]} != manifest pin {entry["pin"]}')
            return status
    status["ok"] = status["head"] is not None
    if not status["ok"]:
        status["errors"].append("could not read HEAD after checkout")
    return status


# ------------------------------------------------------- LFS selection

def select_splunk_files(dest: Path, rules_dir: Path, selection: dict) -> dict:
    """Pre-registered, outcome-blind selection of splunk/attack_data scenarios.

    Candidate = a scenario with >= 1 not-yet-present (LFS pointer or absent) file
    among its Windows-XML files and a label in a technique family some
    enterprise-ATT&CK rule covers. Per parent technique keep the ``per_technique``
    smallest (known-size scenarios first, then total declared LFS bytes, then
    dataset_id); then cap by ``max_files`` / ``max_bytes`` walking in
    (parent, size, id) order. Returns {'files': [rel,...], 'scenarios': [...],
    'bytes': n, 'skipped': {...}}.
    """
    import corpus_adapters as CA
    import technique_match as TM

    index = TM.load_rule_index(rules_dir)
    families = {TM.parent(info["technique"]) for info in index.values()}
    per_parent: dict = {}
    for sc in CA.SplunkAttackData(dest).scenarios():
        if not sc.labels:
            continue
        parents = sorted({TM.parent(lb) for lb in sc.labels} & families)
        if not parents:
            continue
        # an un-pulled LFS pointer (size known) or a file absent from the work tree (size
        # unknown: some clones lack even the pointers) is a candidate for the pull
        wanted = [f for f in sc.files if f.kind == "winxml" and f.state in ("lfs_pointer", "missing")]
        if not wanted:
            continue
        size = sum(f.lfs_size or 0 for f in wanted)
        unknown = any(f.lfs_size is None for f in wanted)   # unknown size sorts after known
        per_parent.setdefault(parents[0], []).append((size, sc.dataset_id, wanted, unknown))
    chosen, files, total, skipped = [], [], 0, {"comma_in_path": 0, "over_cap": 0}
    for par in sorted(per_parent):
        for size, sid, wanted, _unk in sorted(per_parent[par], key=lambda t: (t[3], t[0], t[1]))[
                :int(selection.get("per_technique", 3))]:
            rels = [f.rel for f in wanted]
            if any("," in r for r in rels):          # --include is comma separated
                skipped["comma_in_path"] += 1
                continue
            if (len(files) + len(rels) > int(selection.get("max_files", 60))
                    or total + size > int(selection.get("max_bytes", 314572800))):
                skipped["over_cap"] += 1
                continue
            chosen.append({"dataset_id": sid, "parent": par, "bytes": size, "files": rels})
            files.extend(rels)
            total += size
    return {"files": sorted(set(files)), "scenarios": chosen, "bytes": total, "skipped": skipped}


def lfs_pull(dest: Path, rel_paths: list, *, run=subprocess.run) -> dict:
    """``git lfs pull --include=<paths>``; afterwards each path is re-inspected
    so a silent failure shows up as still_pointer instead of data."""
    import corpus_adapters as CA

    out = {"requested": len(rel_paths), "pulled": 0, "still_pointer": [], "missing": [],
           "ok": True, "errors": []}
    if not rel_paths:
        return out
    v = _git(["lfs", "version"], dest, run=run)
    if v.returncode != 0:
        out["ok"] = False
        out["errors"].append("git-lfs is not installed / not on PATH (git lfs version failed)")
        return out
    r = _git(["lfs", "pull", "--include=" + ",".join(rel_paths)], dest, run=run)
    if r.returncode != 0:
        out["ok"] = False
        out["errors"].append(f"git lfs pull failed: {(r.stderr or r.stdout).strip()[:300]}")
    for rel in rel_paths:
        state, _ = CA.inspect_file(dest / rel)
        if state == "present":
            out["pulled"] += 1
        elif state == "lfs_pointer":
            out["still_pointer"].append(rel)
        else:
            out["missing"].append(rel)
    if out["still_pointer"] or out["missing"]:
        out["ok"] = False
        out["errors"].append(f'{len(out["still_pointer"])} file(s) still an LFS pointer, '
                             f'{len(out["missing"])} missing after pull')
    return out


# ------------------------------------------------------------------ main

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument("--corpus", action="append", default=None,
                    help="corpus name(s) from the manifest (default: every corpus whose lanes "
                         "include blind_recall)")
    ap.add_argument("--rules-dir", type=Path, default=REPO / "contracts" / "rules")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the git plan and the LFS selection; fetch nothing")
    ap.add_argument("--no-lfs", action="store_true", help="skip the selective LFS pull")
    a = ap.parse_args(argv)

    manifest = load_manifest(a.manifest)
    names = a.corpus or [n for n, c in manifest["corpora"].items() if "blind_recall" in c["lanes"]]
    unknown = [n for n in names if n not in manifest["corpora"]]
    if unknown:
        print(f"[FAIL] unknown corpus: {unknown}")
        return 1
    rc = 0
    for name in names:
        entry = manifest["corpora"][name]
        dest = HERE / entry["dest"]
        print(f'== {name}  ({entry["license_spdx"]}, pin={entry.get("pin") or "UNPINNED"})')
        st = fetch_corpus(name, entry, dest, dry_run=a.dry_run)
        for line in st.get("plan", []):
            print("   plan:", line)
        if not st["ok"]:
            rc = 1
            for e in st["errors"]:
                print("   [FAIL]", e)
            continue
        if st["head"]:
            print(f'   HEAD={st["head"]} pin_matches={st["pin_matches"]}')
        if entry.get("lfs") and not a.no_lfs and dest.is_dir():
            sel = select_splunk_files(dest, a.rules_dir, entry["selection"])
            print(f'   selection: {len(sel["scenarios"])} scenario(s), {len(sel["files"])} file(s), '
                  f'{sel["bytes"]} bytes declared, skipped={sel["skipped"]}')
            if a.dry_run:
                for s in sel["scenarios"][:20]:
                    print("     ", s["parent"], s["dataset_id"], s["bytes"])
            else:
                pull = lfs_pull(dest, sel["files"])
                print(f'   lfs pull: requested={pull["requested"]} pulled={pull["pulled"]} '
                      f'still_pointer={len(pull["still_pointer"])} missing={len(pull["missing"])}')
                if not pull["ok"]:
                    rc = 1
                    for e in pull["errors"]:
                        print("   [FAIL]", e)
    return rc


if __name__ == "__main__":
    sys.exit(main())
