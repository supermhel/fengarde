# eval/llm_triage: WS-5 verdict-quality harness

Measures whether WS-5 AI triage gives the right verdict, and how often the stub silently answered
instead of the model. Results and caveats: [`RESULTS.md`](RESULTS.md) (generated, do not edit).

| File | Role |
|---|---|
| `build_labelled_set.py` | Builds `labelled_cases.json` from repo material (twin storyline attack steps, curated adversarial corpus, storyline decoys, twin negative controls) through the real WS-2 -> WS-4 path. `--check` fails if the committed file is stale. Slow (~70 s), so it runs in the `eval-twin` gate tier. |
| `labelled_cases.json` | 54 cases: label, expected level, provenance, the exact `ai.requests` payload. Committed. |
| `run_eval.py` | Sends each case through the real `AiWorker.handle()`; scores accuracy (Wilson CI), per-class precision/recall, confusion matrix, abstain/error/stub share, severity, latency. |
| `render_results.py` | Renders `RESULTS.md` from `results/*.json`. |
| `test_llm_triage_eval.py` | Zero-infra contract tests (stub + loopback fake Ollama). Wired in `run_all_tests.sh`. |

```sh
python eval/llm_triage/run_eval.py                                   # stub baseline, zero infra
python eval/llm_triage/run_eval.py --ollama-url http://localhost:11434 --all-local --direct --timeout 120
python eval/llm_triage/render_results.py                             # then commit results/ + RESULTS.md
```

Rules of reading a result: look at `stub share` first (a high value means the "model" run was mostly the
stub), then `n` and the interval, then the always-malicious baseline, then accuracy. Without `--direct`
you measure the production path including its silent fallback; with it you measure the model alone.
The harness never pulls a model.

## The bar (WP-4.6: "seam, not a feature" until cleared)

AI triage ships with a labelled **stub** as the default. A model may be called
"the triage feature" only when it clears ALL of these on the committed
54-case set, measured with `run_eval.py --all-local --direct` and rendered
into `RESULTS.md` (owner chooses/buys the model; this repo only states the
bar; the thresholds below are a maintainer-chosen policy, not derived from the data):

1. accuracy strictly better than the **always-malicious baseline**;
2. accuracy strictly better than the **score-driven stub**;
3. **abstain < 20 %** and **error < 5 %** (abstentions and errors are honest
   answers, but a model that mostly abstains is not a triage feature);
4. **stub share = 0 %** under `--direct` (the run must be the model alone —
   a production run may still fall back silently, which is exactly why the
   console and the alert report name the engine per verdict).

Until then the console (Alarms view) and the per-alert incident report name
the engine — `stub` vs `ollama/<model>` — on every verdict, and the feature
is documented as a seam: the number that counts is the labelled-set result,
not the engine's existence.
