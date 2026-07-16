"""M4.6 ops lifecycle: versioned OpenSearch template migration tests.

Same "fake transport" pattern as services/ws3-indexer/test_storage_cas.py:
OpenSearchStore._request is patched with a scripted stand-in, so the
request CONSTRUCTION and plan/apply DECISION LOGIC are what's under test
-- not a live cluster (same standing caveat as the rest of the OpenSearch
storage adapter).

Run: python tools/test_migrate_opensearch.py
"""
from __future__ import annotations

import io
import sys
import urllib.error
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(ROOT / "services" / "ws3-indexer"))

import migrate_opensearch as mig  # noqa: E402
from storage.opensearch import OpenSearchStore  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class _FakeTransport:
    """Scripted (method, path) -> response/exception, keyed in the order
    calls happen; records every call for assertion."""

    def __init__(self, responses_by_path: dict[str, object]):
        self._responses = dict(responses_by_path)
        self.calls: list[tuple[str, str, dict | None]] = []
        self.puts: list[tuple[str, dict]] = []

    def __call__(self, method, path, body=None):
        self.calls.append((method, path, body))
        if method == "PUT":
            self.puts.append((path, body))
            return {"acknowledged": True}
        result = self._responses.get(path, _http_404())
        if isinstance(result, Exception):
            raise result
        return result


def _http_404():
    return urllib.error.HTTPError("http://x", 404, "Not Found", {}, io.BytesIO(b"{}"))


def _installed_response(mapping_version: int) -> dict:
    return {"index_templates": [{"name": "x", "index_template": {
        "template": {"mappings": {"_meta": {"mapping_version": mapping_version}}}}}]}


# -- _mapping_version -----------------------------------------------------

def test_mapping_version_extraction():
    check(mig._mapping_version({"template": {"mappings": {"_meta": {"mapping_version": 3}}}}) == 3,
          "must extract a present mapping_version")
    check(mig._mapping_version({"template": {"mappings": {}}}) == 0,
          "a template with no _meta must default to version 0")
    check(mig._mapping_version({}) == 0, "a totally empty dict must default to version 0, not raise")


# -- load_templates (real repo sanity) -------------------------------------

def test_load_templates_reads_the_real_repo_and_skips_ilm():
    templates = mig.load_templates()
    check("ilm-policies" not in templates, "the ILM policies file must never be treated as a template")
    expected = {"alerts", "assets", "events-bank", "events-common", "events-dc"}
    check(expected.issubset(set(templates)), f"the real 5 template files must all load, got {set(templates)}")
    for name in expected:
        version = mig._mapping_version(templates[name])
        check(version >= 1, f"{name}.json must carry a real mapping_version >= 1, got {version}")


# -- plan() decision logic (fake transport) ---------------------------------

def test_plan_marks_nothing_installed_as_apply():
    store = OpenSearchStore(url="http://fake:9200")
    store._request = _FakeTransport({})  # every GET 404s -> nothing installed
    steps = mig.plan(store)
    check(len(steps) == 5, f"must plan for all 5 real templates, got {len(steps)}")
    check(all(s["action"] == "apply" for s in steps),
          f"nothing installed yet must mean 'apply' for everything, got {steps}")
    check(all(s["installed_version"] is None for s in steps),
          "installed_version must be None when nothing is installed")


def test_plan_skips_already_current_and_applies_stale():
    store = OpenSearchStore(url="http://fake:9200")
    real_versions = {name: mig._mapping_version(t) for name, t in mig.load_templates().items()}

    responses = {}
    for name, version in real_versions.items():
        # alerts: pretend it's already at the correct version -> skip
        # everything else: pretend it's stuck at version 0 -> apply
        installed = version if name == "alerts" else 0
        responses[f"/_index_template/{name}"] = _installed_response(installed)
    store._request = _FakeTransport(responses)

    steps = {s["name"]: s for s in mig.plan(store)}
    check(steps["alerts"]["action"] == "skip", f"an already-current template must be skipped, got {steps['alerts']}")
    for name in real_versions:
        if name == "alerts":
            continue
        check(steps[name]["action"] == "apply",
              f"a stale-version template must be planned for apply, got {steps[name]}")


# -- apply() only touches "apply" steps -------------------------------------

def test_apply_only_puts_the_apply_steps():
    store = OpenSearchStore(url="http://fake:9200")
    fake = _FakeTransport({})
    store._request = fake

    steps = [
        {"name": "alerts", "desired_version": 1, "installed_version": 1, "action": "skip"},
        {"name": "assets", "desired_version": 1, "installed_version": 0, "action": "apply"},
        {"name": "events-common", "desired_version": 1, "installed_version": None, "action": "apply"},
    ]
    applied = mig.apply(store, steps)
    check(set(applied) == {"assets", "events-common"}, f"only the apply-marked templates must be applied, got {applied}")
    put_names = {path.rsplit("/", 1)[-1] for path, _body in fake.puts}
    check(put_names == {"assets", "events-common"}, f"exactly those templates must have been PUT, got {put_names}")
    check(len(fake.puts) == 2, "the skipped template must never be PUT")


def main():
    test_mapping_version_extraction()
    test_load_templates_reads_the_real_repo_and_skips_ilm()
    test_plan_marks_nothing_installed_as_apply()
    test_plan_skips_already_current_and_applies_stale()
    test_apply_only_puts_the_apply_steps()

    if FAILS:
        print(f"[FAIL] migrate_opensearch: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] M4.6 OpenSearch template migration: mapping_version extraction, real repo's "
          "5 template files all carry a real version and ilm-policies.json is correctly "
          "excluded, plan() correctly distinguishes nothing-installed/stale/current, apply() "
          "only PUTs the templates actually marked for it -- fake-transport wire-format level, "
          "same standing caveat as the rest of the OpenSearch storage adapter")


if __name__ == "__main__":
    main()
