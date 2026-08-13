"""atheris fuzz harness: services/ws2-normalization/parsers/k8s_audit.py.

Unlike the text-line parsers, K8sAuditParser.parse() requires raw['raw'] to
already be a dict (no string/json.loads fallback), so this uses run_json
(fuzzed bytes -> JSON decode -> only calls parse() on a dict result).

Run:  python tools/fuzz/fuzz_k8s_audit.py -atheris_runs=200000
      python tools/fuzz/fuzz_k8s_audit.py -max_total_time=600   # nightly CI (10 min)
Corpus (optional, speeds convergence): pass a directory as the last arg.
"""
from __future__ import annotations

from _common import run_json
from parsers.k8s_audit import K8sAuditParser

if __name__ == "__main__":
    run_json(K8sAuditParser(), "k8s_audit")
