"""Contract tests for the WS-5 verdict-quality harness. Zero infra: stub + a loopback fake Ollama.

Proves the HARNESS, not the model:
  * the committed labelled set is well-formed, labelled from repo material, leak-free;
  * score() computes accuracy / precision / recall / confusion / abstain correctly;
  * the stub baseline runs through the real WS-5 worker and its numbers equal an independent
    recomputation from the stub's documented score thresholds;
  * an unreachable Ollama is reported as a 100% stub share (the silent-fallback measurement);
  * a model that answers is counted as `ollama`, `--direct` records failures as errors, not stub rows;
  * RESULTS.md is the render of the committed results and they match the committed labelled set.
"""
from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run_eval  # noqa: E402
import render_results  # noqa: E402
import variants  # noqa: E402
import stats  # noqa: E402

DOC = run_eval.load_cases()


def _row(label, verdict, level="high", exp="high", engine="stub", error=None, tier="llm", lat=1.0):
    return {"label": label, "verdict": verdict, "level": level, "expected_level": exp,
            "engine": engine, "error": error, "prod_tier": tier, "latency_ms": lat}


class _Fake(BaseHTTPRequestHandler):
    reply = {"verdict": "malicious", "level": "high", "summary": "x"}
    raw = None  # when set, sent verbatim as the model text

    def log_message(self, *a):
        pass

    def do_GET(self):
        body = json.dumps({"models": [{"name": "fake:1b"}]}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        text = type(self).raw if type(self).raw is not None else json.dumps(type(self).reply)
        body = json.dumps({"response": text, "done": True}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)


class LabelledSet(unittest.TestCase):
    def test_shape_and_provenance(self):
        cases = DOC["cases"]
        self.assertGreaterEqual(len(cases), 30)
        self.assertEqual(DOC["counts"]["n"], len(cases))
        ids = [c["case_id"] for c in cases]
        self.assertEqual(len(ids), len(set(ids)), "duplicate case_id")
        eids = [c["request"]["event_id"] for c in cases]
        self.assertEqual(len(eids), len(set(eids)), "duplicate event_id: WS-5 would serve one case the other's cached verdict")
        self.assertEqual({c["label"] for c in cases}, set(run_eval.CLASSES), "both classes must be present")
        for c in cases:
            self.assertIn(c["expected_level"], run_eval._LEVELS)
            self.assertTrue(c["provenance"]["source"] and c["provenance"]["group"], c["case_id"])
            self.assertTrue(c["request"]["reason"], f"{c['case_id']}: no rule reason (would not reach WS-5)")
            self.assertIsInstance(c["request"]["event"]["siem"]["score"], int)
            self.assertEqual(c["label_leak_words"], [], f"{c['case_id']}: label text leaks into the event the model sees")
        for k in ("true_positive", "false_positive"):
            self.assertEqual(DOC["counts"][k], sum(c["label"] == k for c in cases))


class Scoring(unittest.TestCase):
    def test_known_confusion(self):
        rows = [_row("true_positive", "malicious"), _row("true_positive", "malicious"),
                _row("true_positive", "benign"), _row("true_positive", "suspicious"),
                _row("false_positive", "benign"), _row("false_positive", "malicious"),
                _row("false_positive", "unknown"), _row("false_positive", None, error="TimeoutError: x")]
        m = run_eval.score(rows)
        self.assertEqual(m["n"], 8)
        self.assertEqual(m["accuracy"], round(3 / 8, 6))
        self.assertEqual(m["abstain_rate"], round(2 / 8, 6))
        self.assertEqual(m["error_rate"], round(1 / 8, 6))
        tp, fp = m["per_class"]["true_positive"], m["per_class"]["false_positive"]
        self.assertEqual((tp["predicted"], tp["precision"], tp["recall"]), (3, round(2 / 3, 6), 0.5))
        self.assertEqual((fp["predicted"], fp["precision"], fp["recall"]), (2, 0.5, 0.25))
        self.assertEqual(m["confusion_matrix"]["true_positive"],
                         {"true_positive": 2, "false_positive": 1, "needs_review": 1, "error": 0})
        self.assertEqual(m["confusion_matrix"]["false_positive"]["error"], 1)
        self.assertEqual(m["accuracy_when_decisive"], round(3 / 5, 6))
        self.assertEqual(m["majority_class_baseline_accuracy"], 0.5)

    def test_always_malicious_scores_the_majority_baseline(self):
        m = run_eval.score([_row(c["label"], "malicious") for c in DOC["cases"]])
        self.assertEqual(m["accuracy"], round(m["support"]["true_positive"] / m["n"], 6))
        self.assertEqual(m["per_class"]["true_positive"]["recall"], 1.0)


class StubBaseline(unittest.TestCase):
    def test_matches_independent_recomputation(self):
        r = run_eval.run_backend("stub", ollama_url=None, model=None, direct=False, timeout_s=None, cases_doc=DOC)
        m = r["metrics"]
        self.assertEqual(m["n"], len(DOC["cases"]))
        self.assertEqual(m["engine_counts"], {"stub": len(DOC["cases"])})
        self.assertEqual(m["stub_share"], 1.0)
        self.assertEqual(m["model_answered"], 0)

        def stub_pred(score):  # StubLLM's documented thresholds, restated independently
            return "true_positive" if score >= 80 else "needs_review" if score >= 60 else "false_positive"
        ok = sum(stub_pred(c["request"]["event"]["siem"]["score"]) == c["label"] for c in DOC["cases"])
        self.assertEqual(m["accuracy"], round(ok / len(DOC["cases"]), 6))


class OllamaPaths(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), _Fake)
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        _Fake.raw = None
        _Fake.reply = {"verdict": "malicious", "level": "high", "summary": "x"}

    def test_unreachable_ollama_is_a_full_stub_share(self):
        r = run_eval.run_backend("ollama:ghost", ollama_url="http://127.0.0.1:9", model="ghost", direct=False,
                                 timeout_s=1, cases_doc=DOC)
        m = r["metrics"]
        self.assertEqual(r["adapter"], "FallbackLLM")
        self.assertEqual(m["stub_share"], 1.0, "silent stub replacement must be visible as stub_share")
        self.assertEqual(m["model_answered"], 0)

    def test_answering_model_counts_as_ollama(self):
        r = run_eval.run_backend("ollama:fake", ollama_url=self.url, model="fake:1b", direct=False,
                                 timeout_s=5, cases_doc=DOC)
        m = r["metrics"]
        self.assertEqual(m["engine_counts"], {"ollama": len(DOC["cases"])})
        self.assertEqual(m["stub_share"], 0.0)
        self.assertEqual(m["per_class"]["true_positive"]["recall"], 1.0)  # always "malicious"
        self.assertEqual(m["per_class"]["false_positive"]["recall"], 0.0)

    def test_direct_records_errors_not_stub_rows(self):
        _Fake.raw = "this is not json"
        r = run_eval.run_backend("ollama:fake:direct", ollama_url=self.url, model="fake:1b", direct=True,
                                 timeout_s=5, cases_doc=DOC)
        m = r["metrics"]
        self.assertEqual(m["error_rate"], 1.0)
        self.assertEqual(m["stub_share"], 0.0)

    def test_production_path_hides_the_same_garbage_behind_the_stub(self):
        _Fake.raw = "this is not json"
        r = run_eval.run_backend("ollama:fake", ollama_url=self.url, model="fake:1b", direct=False,
                                 timeout_s=5, cases_doc=DOC)
        self.assertEqual(r["metrics"]["error_rate"], 0.0)
        self.assertEqual(r["metrics"]["stub_share"], 1.0)


class VariantSplit(unittest.TestCase):
    def test_split_is_disjoint_stratified_and_about_a_third(self):
        dev, hold = variants.split(DOC["cases"])
        ids = lambda xs: {c["case_id"] for c in xs}
        self.assertFalse(ids(dev) & ids(hold))
        self.assertEqual(ids(dev) | ids(hold), ids(DOC["cases"]))
        self.assertGreaterEqual(len(hold), len(DOC["cases"]) // 3 - 1)
        self.assertTrue({c["label"] for c in hold} == set(run_eval.CLASSES))
        self.assertEqual(variants.split(DOC["cases"]), (dev, hold), "split must be deterministic")

    def test_no_storyline_is_on_both_sides(self):
        dev, hold = variants.split(DOC["cases"])
        both = {variants.storyline(c) for c in dev} & {variants.storyline(c) for c in hold}
        self.assertEqual(both, set(), "a storyline (attack steps or its decoy) appears in DEV and HOLDOUT")

    def test_definitions_prompt_names_no_scenario(self):
        low = variants.DEFINITIONS.lower()
        for word in ("credential", "privileged", "deletion", "country", "countries", "scan", "maintenance",
                     "scanner", "agent", "login", "group"):
            self.assertNotIn(word, low, f"scenario word {word!r} in the verdict definitions (leaks the holdout)")

    def test_committed_variant_run_used_this_split_and_set(self):
        d = json.loads(variants.OUT.read_text(encoding="utf-8"))
        _dev, hold = variants.split(DOC["cases"])
        self.assertEqual(d["labelled_set_sha256"], run_eval.cases_sha())
        self.assertEqual(d["split"]["holdout"], len(hold))
        held = {r["case_id"] for r in next(iter(d["holdout"].values()))["rows"]}
        self.assertEqual(held, {c["case_id"] for c in hold})
        scored_dev = {r["case_id"] for r in next(iter(d["dev"].values()))["rows"]}
        self.assertFalse(scored_dev & held, "a holdout case was scored during variant selection")
        self.assertFalse(scored_dev & set(d["fewshot_case_ids"]), "few-shot examples must not be scored")

    def test_every_variant_file_matches_the_labelled_set(self):
        files = sorted(variants.HERE.joinpath("results").glob("variants*.json"))
        self.assertTrue(files)
        for f in files:
            self.assertEqual(json.loads(f.read_text(encoding="utf-8"))["labelled_set_sha256"], run_eval.cases_sha(), f.name)

    def test_every_variant_builds_a_prompt(self):
        shots = [c for c in DOC["cases"][:4]]
        for name, (build, *_rest) in variants.VARIANTS.items():
            self.assertIn("alert", build(DOC["cases"][0], shots).lower(), name)


class DerivedNumbers(unittest.TestCase):
    """The figures the docs quote are computed, and the docs that carry them must agree."""
    ROOT = HERE.parents[1]

    def test_label_ceiling_is_computed_and_matches_a_hand_count(self):
        s = stats.label_ceiling(DOC["cases"])
        by_sig = {}
        for c in DOC["cases"]:
            by_sig.setdefault(stats.signature(c), []).append(c["label"])
        self.assertEqual(s["signatures"], len(by_sig))
        self.assertEqual(s["mixed"], sum(len(set(v)) > 1 for v in by_sig.values()))
        self.assertEqual(s["ceiling"], sum(max(v.count("true_positive"), v.count("false_positive")) for v in by_sig.values()))
        self.assertLessEqual(s["ceiling"], s["n"])

    def test_results_md_and_ssot_carry_the_computed_ceiling(self):
        s = stats.label_ceiling(DOC["cases"])
        results = render_results.OUT.read_text(encoding="utf-8")
        self.assertIn(stats.ceiling_phrase(DOC["cases"]), results)
        ssot = (self.ROOT / "SSOT.md").read_text(encoding="utf-8")
        for needle in (f"{s['mixed']} of {s['signatures']}", f"{s['ceiling']}/{s['n']} = {s['ceiling_pct']}"):
            self.assertIn(needle, ssot, f"SSOT.md label-ceiling figure drifted from the computed value ({needle})")

    def test_holdout_baseline_is_computed_not_typed(self):
        _dev, hold = variants.split(DOC["cases"])
        tp = sum(c["label"] == "true_positive" for c in hold)
        expect = f"The always-malicious baseline on these holdout cases is {stats.share(max(tp, len(hold) - tp), len(hold))}."
        self.assertIn(expect, render_results.OUT.read_text(encoding="utf-8"))

    def test_one_percentage_per_run_in_results_md_and_ssot(self):
        d = json.loads((render_results.RESULTS / "2026-10-28.json").read_text(encoding="utf-8"))
        run = next(r for r in d["runs"] if r["label"] == "ollama:qwen2.5:3b")
        m = run_eval.score([dict(r) for r in run["rows"]])
        k = round(m["accuracy"] * m["n"])
        pct = stats.share(k, m["n"])
        self.assertIn(f"**accuracy {pct}** ({k}/{m['n']};", render_results.OUT.read_text(encoding="utf-8"))
        self.assertIn(f"{k}/{m['n']}", (self.ROOT / "SSOT.md").read_text(encoding="utf-8"))


class CommittedResults(unittest.TestCase):
    def test_results_md_is_the_render(self):
        have = render_results.OUT.read_text(encoding="utf-8").replace("\r\n", "\n")
        self.assertEqual(have, render_results.render(), "RESULTS.md stale: run render_results.py")

    def test_results_match_committed_labelled_set(self):
        files = sorted(f for f in render_results.RESULTS.glob("*.json") if not f.name.startswith("variants"))
        self.assertTrue(files, "no committed results")
        latest = json.loads(files[-1].read_text(encoding="utf-8"))
        self.assertEqual(latest["labelled_set_sha256"], run_eval.cases_sha(),
                         "labelled set changed since the last committed run: re-run run_eval.py")
        self.assertTrue(latest["ollama_blocked"] or any(r["label"].startswith("ollama:") for r in latest["runs"]))

    def test_cli_writes_a_result_file(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "r.json"
            self.assertEqual(run_eval.main(["--out", str(out), "--ollama-blocked", "test"]), 0)
            self.assertEqual(json.loads(out.read_text())["runs"][0]["label"], "stub")


if __name__ == "__main__":
    unittest.main(verbosity=1)
