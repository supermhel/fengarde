"""WS-5 triage verdict-quality runner.

Sends every case in `labelled_cases.json` through the REAL WS-5 worker
(`services/ws5-ai/main.py::AiWorker.handle`, which calls `llm_adapter.make_llm()`'s object)
and scores the verdict against the label.

    python eval/llm_triage/run_eval.py                       # StubLLM baseline (zero-infra)
    python eval/llm_triage/run_eval.py --ollama-url http://localhost:11434 --all-local
    python eval/llm_triage/run_eval.py --ollama-url ... --model qwen2.5:0.5b --direct

Two paths for an Ollama model:
  production (default)  the exact FallbackLLM(OllamaLLM, StubLLM) that `make_llm()` returns. After ONE
                        timeout/garbage reply the adapter serves the STUB until the next probe, so a
                        slow CPU host can turn most of a "model" run into stub verdicts. Every row records
                        `engine`; `fallback_rate` is the share the stub silently answered.
  --direct              OllamaLLM alone, no stub: a failure is a recorded `error` row, never a stub
                        verdict. This is the clean read of model quality.

Scoring: model verdict malicious->true_positive, benign->false_positive; suspicious/unknown/anything
else -> needs_review (an abstention: counts as wrong for accuracy, reported separately).
"""
from __future__ import annotations

import argparse
import copy
import datetime
import hashlib
import importlib.util
import json
import math
import os
import platform
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SERVICES = ROOT / "services"
CASES = HERE / "labelled_cases.json"
RESULTS = HERE / "results"
CLASSES = ["true_positive", "false_positive"]
PRED_CLASSES = CLASSES + ["needs_review"]
_PRED = {"malicious": "true_positive", "benign": "false_positive"}
_LEVELS = ["low", "medium", "high", "critical"]


def load_cases(path: Path = CASES) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def cases_sha(path: Path = CASES) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def to_pred(verdict) -> str:
    return _PRED.get(verdict, "needs_review")


def _load_ws5():
    """ws5-ai/main.py by file path under a unique name (several services ship a top-level main.py)."""
    for p in (str(SERVICES / "ws5-ai"), str(SERVICES)):
        if p not in sys.path:
            sys.path.insert(0, p)
    spec = importlib.util.spec_from_file_location("ws5_ai_main_eval", str(SERVICES / "ws5-ai" / "main.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ws5_ai_main_eval"] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------- scoring (pure)
def wilson(k: int, n: int, z: float = 1.96) -> list:
    if n == 0:
        return [None, None]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def _pct(xs: list, q: float):
    if not xs:
        return None
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(math.ceil(q * len(xs))) - 1)], 1)


def _rate(k: int, n: int):
    return round(k / n, 4) if n else None


def score(rows: list[dict]) -> dict:
    """rows: [{label, expected_level, prod_tier, verdict, level, engine, error, latency_ms}]."""
    n = len(rows)
    for r in rows:
        r["pred"] = "error" if r.get("error") else to_pred(r.get("verdict"))
    support = {c: sum(r["label"] == c for r in rows) for c in CLASSES}
    correct = sum(r["pred"] == r["label"] for r in rows)
    decisive = [r for r in rows if r["pred"] in CLASSES]
    cm = {c: {p: 0 for p in PRED_CLASSES + ["error"]} for c in CLASSES}
    for r in rows:
        cm[r["label"]][r["pred"]] += 1
    per_class = {}
    for c in CLASSES:
        tp = cm[c][c]
        predicted = sum(r["pred"] == c for r in rows)
        per_class[c] = {"support": support[c], "predicted": predicted,
                        "precision": _rate(tp, predicted), "recall": _rate(tp, support[c])}
        pr, rc = per_class[c]["precision"], per_class[c]["recall"]
        per_class[c]["f1"] = round(2 * pr * rc / (pr + rc), 4) if pr and rc else (0.0 if pr is not None and rc is not None else None)
    engines: dict = {}
    for r in rows:
        engines[str(r.get("engine"))] = engines.get(str(r.get("engine")), 0) + 1
    lat = [r["latency_ms"] for r in rows if r.get("latency_ms") is not None]
    sev = [r for r in rows if r.get("level") in _LEVELS]
    sev_exact = sum(r["level"] == r["expected_level"] for r in sev)
    sev_w1 = sum(abs(_LEVELS.index(r["level"]) - _LEVELS.index(r["expected_level"])) <= 1 for r in sev)
    model_rows = [r for r in rows if r.get("engine") == "ollama"]
    llm_tier = [r for r in rows if r.get("prod_tier") == "llm"]
    return {
        "n": n,
        "support": support,
        "majority_class_baseline_accuracy": _rate(max(support.values()), n) if n else None,
        "accuracy": _rate(correct, n),
        "accuracy_ci95": wilson(correct, n),
        "abstain_rate": _rate(sum(r["pred"] == "needs_review" for r in rows), n),
        "error_rate": _rate(sum(r["pred"] == "error" for r in rows), n),
        "decisive_coverage": _rate(len(decisive), n),
        "accuracy_when_decisive": _rate(sum(r["pred"] == r["label"] for r in decisive), len(decisive)),
        "per_class": per_class,
        "confusion_matrix": cm,
        "engine_counts": engines,
        "stub_share": _rate(engines.get("stub", 0), n),
        "model_answered": len(model_rows),
        "accuracy_on_model_answered": _rate(sum(r["pred"] == r["label"] for r in model_rows), len(model_rows)),
        "severity": {"scored": len(sev), "exact": _rate(sev_exact, len(sev)), "within_one": _rate(sev_w1, len(sev))},
        "llm_tier_subset": {"n": len(llm_tier), "accuracy": _rate(sum(r["pred"] == r["label"] for r in llm_tier), len(llm_tier))},
        "latency_ms": {"mean": round(sum(lat) / len(lat), 1) if lat else None, "p50": _pct(lat, .5),
                       "p95": _pct(lat, .95), "max": round(max(lat), 1) if lat else None},
    }


# ---------------------------------------------------------------- running
def _ram_gb():
    try:
        if sys.platform == "win32":
            import ctypes

            class MS(ctypes.Structure):
                _fields_ = [("l", ctypes.c_ulong), ("m", ctypes.c_ulong), ("tp", ctypes.c_ulonglong),
                            ("ap", ctypes.c_ulonglong), ("a", ctypes.c_ulonglong), ("b", ctypes.c_ulonglong),
                            ("c", ctypes.c_ulonglong), ("d", ctypes.c_ulonglong), ("e", ctypes.c_ulonglong)]
            ms = MS(); ms.l = ctypes.sizeof(MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
            return round(ms.tp / 2**30, 1)
        for line in open("/proc/meminfo"):
            if line.startswith("MemTotal"):
                return round(int(line.split()[1]) / 2**20, 1)
    except Exception:
        pass
    return None


def hardware() -> dict:
    return {"platform": platform.platform(), "cpu": platform.processor() or platform.machine(),
            "logical_cpus": os.cpu_count(), "ram_gb": _ram_gb(),
            "gpu": "not probed (assume none unless the operator says otherwise)"}


def _ollama_json(url: str, path: str, timeout: float = 5.0):
    with urllib.request.urlopen(url.rstrip("/") + path, timeout=timeout) as r:  # noqa: S310 (operator-given local URL)
        return json.loads(r.read().decode())


def local_models(url: str) -> list[str]:
    return [m["name"] for m in _ollama_json(url, "/api/tags").get("models", [])]


def run_backend(label: str, *, ollama_url: str | None, model: str | None, direct: bool,
                timeout_s: float | None, cases_doc: dict) -> dict:
    os.environ["BUS_BACKEND"] = "memory"
    os.environ["AI_MAX_WORKERS"] = "1"  # one call at a time: latency is per-call, not queue-skewed
    for k in ("OLLAMA_URL", "OLLAMA_MODEL", "OLLAMA_TIMEOUT_SECONDS"):
        os.environ.pop(k, None)
    if ollama_url:
        os.environ["OLLAMA_URL"] = ollama_url
        os.environ["OLLAMA_MODEL"] = model or "qwen2.5"
        if timeout_s:
            os.environ["OLLAMA_TIMEOUT_SECONDS"] = str(timeout_s)
    ws5 = _load_ws5()
    worker = ws5.AiWorker()
    adapter = type(worker.llm).__name__
    if ollama_url and direct:
        from llm_adapter import OllamaLLM
        worker.llm = OllamaLLM()
        adapter = "OllamaLLM(direct)"
    rows = []
    t_start = time.monotonic()
    for c in cases_doc["cases"]:
        req = copy.deepcopy(c["request"])
        req["tier"] = "llm"  # force the LLM tier so every case exercises analyze(); prod_tier is kept for the subset
        row = {"case_id": c["case_id"], "label": c["label"], "expected_level": c["expected_level"],
               "prod_tier": c["prod_tier"], "verdict": None, "level": None, "engine": None, "error": None}
        t0 = time.perf_counter()
        try:
            res = worker.handle(req)
            row.update(verdict=res.get("verdict"), level=res.get("level"), engine=res.get("engine"),
                       model=res.get("model"))
        except Exception as exc:  # direct path: a transport/parse failure is a row, not a crash
            row["error"] = f"{type(exc).__name__}: {str(exc)[:120]}"
        row["latency_ms"] = (time.perf_counter() - t0) * 1000
        rows.append(row)
    wall = time.monotonic() - t_start
    fallbacks = getattr(worker.llm, "fallbacks", None)
    worker.shutdown(wait=True)
    out = {"label": label, "adapter": adapter, "model": model if ollama_url else None,
           "ollama_url": ollama_url, "direct": bool(direct), "timeout_seconds": os.environ.get("OLLAMA_TIMEOUT_SECONDS", "8 (default)") if ollama_url else None,
           "adapter_fallback_counter": fallbacks, "wall_seconds": round(wall, 1), "metrics": score(rows), "rows": rows}
    return out


def build_result(runs: list[dict], cases_doc: dict, blocked: str | None) -> dict:
    return {"schema_version": 1, "date": datetime.date.today().isoformat(),
            "hardware": hardware(), "labelled_set_sha256": cases_sha(),
            "labelled_set_counts": cases_doc["counts"], "ollama_blocked": blocked, "runs": runs}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--ollama-url", help="e.g. http://localhost:11434 (omit for the stub baseline only)")
    ap.add_argument("--model", action="append", default=[], help="Ollama model tag (repeatable)")
    ap.add_argument("--all-local", action="store_true", help="every model `ollama list` reports")
    ap.add_argument("--direct", action="store_true", help="also run each model with no stub fallback")
    ap.add_argument("--timeout", type=float, default=None, help="OLLAMA_TIMEOUT_SECONDS (cap 120)")
    ap.add_argument("--ollama-blocked", default=None,
                    help="record this text as the reason the real-model run did not happen (e.g. a probe done by hand)")
    ap.add_argument("--out", default=None, help="result JSON path (default results/<date>.json)")
    a = ap.parse_args(argv)

    doc = load_cases()
    runs = [run_backend("stub", ollama_url=None, model=None, direct=False, timeout_s=None, cases_doc=doc)]
    blocked = None
    if a.ollama_url:
        try:
            models = a.model or []
            avail = local_models(a.ollama_url)
            if a.all_local:
                models = avail
            for m in models:
                if m not in avail:
                    print(f"skip {m}: not installed locally (will not pull)", file=sys.stderr)
                    continue
                runs.append(run_backend(f"ollama:{m}", ollama_url=a.ollama_url, model=m, direct=False,
                                        timeout_s=a.timeout, cases_doc=doc))
                if a.direct:
                    runs.append(run_backend(f"ollama:{m}:direct", ollama_url=a.ollama_url, model=m, direct=True,
                                            timeout_s=a.timeout, cases_doc=doc))
        except Exception as exc:
            blocked = f"Ollama at {a.ollama_url} unreachable: {type(exc).__name__}: {exc}"
    else:
        blocked = a.ollama_blocked or "no --ollama-url given; Ollama was not probed by this run"
    result = build_result(runs, doc, blocked)
    out = Path(a.out) if a.out else RESULTS / f"{result['date']}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8", newline="\n")
    for r in runs:
        m = r["metrics"]
        print(f"{r['label']:<28} n={m['n']} acc={m['accuracy']} abstain={m['abstain_rate']} "
              f"stub_share={m['stub_share']} p50={m['latency_ms']['p50']}ms")
    if blocked:
        print("OLLAMA:", blocked)
    print("wrote", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
