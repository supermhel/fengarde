"""Live end-to-end proof of the companion rules, against the real Docker stack.

The unit tests (services/ws4-detection/test_companion_rules.py) prove each
companion fires on the split attack its sibling cannot see, using real parsers and
the real engine in one process. They cannot prove that the DEPLOYED stack does the
same: that the rules shipped in the ws4 image, that Redis Streams deliver the
events, that WS-2 -> WS-4 -> WS-3 index the alert, and that the sibling-suppression
and tenant plumbing behave on real infrastructure. This script does, using the
same drive-it-from-inside-a-container pattern as tools/ot_new_device_e2e.py.

Three scenarios, each in its own throw-away tenant:

  A. SPLIT brute force (12 failures for ONE account over TWO source addresses):
     the account-keyed companion alerts; the source-keyed sibling does NOT
     (this is the evasion the harness measured, now proven closed live).
  B. PLAIN brute force (12 failures, ONE address, ONE account): the sibling
     alerts and the companion is SUPPRESSED -- an ordinary attack must not raise
     two alerts.
  C. SPLIT port scan (20 distinct denied ports on one target from TWO sources):
     the target-keyed companion alerts; the source-keyed sibling does not.

Waiting model (no fixed sleeps): for each scenario the script first establishes a
POSITIVE ANCHOR -- the alert that must exist, polled until it appears or
FENGARDE_E2E_TIMEOUT_S (default 120) elapses -- which proves the pipeline actually
processed the events. Only then does it settle (the tenant's alert set unchanged
across FENGARDE_E2E_STABLE_POLLS consecutive polls, default 3) and evaluate the
negative assertions. If the anchor never appears the scenario FAILS with the elapsed
time and the alerts seen; a negative assertion is never allowed to pass on an empty,
not-yet-indexed result.

Live-only by design (needs `docker compose -f infra/docker-compose.yml up -d`).
Without a reachable stack it prints an explicit [SKIP] and exits 0, unless
FENGARDE_E2E_STRICT=1, where a skip is a failure.

Run:       python tools/live_companion_e2e.py
Selfcheck: python tools/live_companion_e2e.py --selfcheck   (no stack needed; tests the wait helpers)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

SIBLING_BRUTE = "6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01"
COMPANION_BRUTE = "d83b71c3-93eb-439f-86f9-5985ebcc38cb"
SIBLING_SCAN = "1d2c3b4a-5e6f-4708-8a91-0b1c2d3e4f05"
COMPANION_SCAN = "aaa9dc23-8550-41ae-acbc-0ae50837d8d6"

REPO_ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILE = REPO_ROOT / "infra" / "docker-compose.yml"
_POLL_S = 3.0
_STRICT = os.getenv("FENGARDE_E2E_STRICT", "").strip().lower() in ("1", "true", "yes")
FAILS: list = []


def _env_num(name, default, cast=float):
    try:
        v = cast(os.getenv(name, "").strip())
        return v if v > 0 else default
    except ValueError:
        return default


def _anchor_timeout_s():
    return _env_num("FENGARDE_E2E_TIMEOUT_S", 120.0)


def _stable_polls():
    return _env_num("FENGARDE_E2E_STABLE_POLLS", 3, int)


def sh(*args, timeout=120):
    return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout, cwd=str(REPO_ROOT))


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _skip(msg):
    print(f"{'[FAIL: unexpected skip]' if _STRICT else '[SKIP]'} companion live e2e: {msg}")
    return 1 if _STRICT else 0


def _container(service):
    out = sh("docker", "compose", "-f", str(COMPOSE_FILE), "ps", "--format",
             "{{.Name}}", service).stdout.strip()
    return out.splitlines()[-1] if out else None


def _produce(container, events):
    code = (
        "import json,sys;from shared.bus import Bus;b=Bus();"
        "evs=json.loads(sys.stdin.read());"
        "[b.produce('raw.events',key=e['meta'].get('ip'),payload=e) for e in evs];"
        "print('ok',len(evs))"
    )
    r = subprocess.run(["docker", "exec", "-i", container, "python", "-c", code],
                       input=json.dumps(events), capture_output=True, text=True, timeout=120)
    return r.returncode == 0 and "ok" in r.stdout, (r.stderr or r.stdout)[:300]


def _alerts(container, tenant):
    q = {"size": 100, "query": {"term": {"tenant_id": tenant}}}
    search = (
        "import json,os,urllib.request;"
        "url=os.environ.get('OPENSEARCH_URL','http://opensearch:9200').split(',')[0];"
        f"body=json.dumps({q!r}).encode();"
        "req=urllib.request.Request(url+'/alerts-*/_search',data=body,"
        "headers={'Content-Type':'application/json'},method='POST');"
        "print(urllib.request.urlopen(req,timeout=10).read().decode())"
    )
    r = sh("docker", "exec", container, "python", "-c", search)
    if r.returncode != 0:
        return None
    try:
        return [h["_source"] for h in json.loads(r.stdout).get("hits", {}).get("hits", [])]
    except ValueError:
        return None


# --- wait helpers (pure: search/clock/sleep are injected so --selfcheck can test them) -----------

def _signature(alerts):
    """Order-insensitive identity of an alert set (alert ids when present, else rule ids)."""
    return tuple(sorted(str(a.get("alert_id") or a.get("rule_id")) for a in alerts))


def wait_for_anchor(search, want_rule, timeout_s, poll_s=_POLL_S, clock=time.monotonic, sleep=time.sleep):
    """Poll until an alert with rule_id == want_rule is indexed, or timeout_s elapses.

    `search()` returns a list of alert dicts, or None on a transient query error (treated as
    "nothing learned yet", never as an empty result). Returns (found, alerts_seen, elapsed_s).
    """
    t0 = clock()
    seen: list = []
    while True:
        a = search()
        if a is not None:
            seen = a
            if any(x.get("rule_id") == want_rule for x in seen):
                return True, seen, clock() - t0
        if clock() - t0 >= timeout_s:
            return False, seen, clock() - t0
        sleep(poll_s)


def settle(search, stable_polls, max_s, poll_s=_POLL_S, clock=time.monotonic, sleep=time.sleep):
    """Poll until the alert set is unchanged across `stable_polls` consecutive successful polls.

    Replaces a fixed sleep: a late co-emitted alert changes the set and restarts the count.
    A failed query (None) also restarts the count. Returns (alerts, settled, elapsed_s);
    settled is False if max_s ran out first.
    """
    t0 = clock()
    last = None
    alerts: list = []
    run = 0
    while True:
        a = search()
        if a is not None:
            sig = _signature(a)
            run = run + 1 if sig == last else 1
            last, alerts = sig, a
            if run >= stable_polls:
                return alerts, True, clock() - t0
        else:
            run = 0
        if clock() - t0 >= max_s:
            return alerts, False, clock() - t0
        sleep(poll_s)


def evaluate(label, search, anchor_rule, must_not, timeout_s, stable_polls, poll_s=_POLL_S,
             clock=time.monotonic, sleep=time.sleep, fails=None):
    """Anchor -> settle -> negative assertions. `must_not` maps rule_id -> failure message.

    Returns the final alert list. Strict: a missing anchor or an unsettled alert set is a
    failure, and the negative assertions are then NOT evaluated (they would be vacuous).
    """
    fails = FAILS if fails is None else fails
    found, seen, elapsed = wait_for_anchor(search, anchor_rule, timeout_s, poll_s, clock, sleep)
    if not found:
        fails.append(f"{label}: anchor alert {anchor_rule} never appeared within {elapsed:.0f}s "
                     f"(FENGARDE_E2E_TIMEOUT_S={timeout_s:.0f}); alerts seen: "
                     f"{sorted(str(x.get('rule_id')) for x in seen)} -- the pipeline did not process the events, "
                     f"negative assertions NOT evaluated (they would pass vacuously)")
        return seen
    alerts, settled, s_el = settle(search, stable_polls, timeout_s, poll_s, clock, sleep)
    if not settled:
        fails.append(f"{label}: alert set did not stabilise over {stable_polls} polls in {s_el:.0f}s "
                     f"(still changing); negative assertions NOT evaluated")
        return alerts
    rules = {x.get("rule_id") for x in alerts}
    print(f"[live {label}] anchor in {elapsed:.0f}s, settled in {s_el:.0f}s -> alert rule ids: "
          f"{sorted(str(r) for r in rules)}")
    for rule, msg in must_not.items():
        if rule in rules:
            fails.append(f"{label}: {msg}")
    return alerts


def _env(tenant, i, t_ms, tag):
    return {"ingest_id": f"live-{tag}-{i}", "tenant_id": tenant, "trace_id": f"live-{tag}",
            "received_at": t_ms}


def main():
    if sh("docker", "version", "--format", "{{.Server.Version}}").returncode != 0:
        return _skip("docker engine not reachable")
    ws2, ws3 = _container("ws2-normalization"), _container("ws3-indexer")
    if not ws2 or not ws3:
        return _skip("stack not up (ws2-normalization / ws3-indexer containers not found)")

    timeout_s, stable = _anchor_timeout_s(), _stable_polls()
    run = uuid.uuid4().hex[:8]
    now = int(time.time() * 1000)

    # --- A: split brute force ------------------------------------------------
    ta = f"livecomp-a-{run}"
    ips = ["203.0.113.21", "192.0.2.44"]
    ev = []
    for i in range(12):
        t = now - 40_000 + i * 3_000
        m = _env(ta, i, t, "a")
        m["ip"] = ips[i % 2]
        ev.append({"source_type": "linux_ssh",
                   "raw": f"Jun 10 13:55:{i:02d} db01 sshd[{2000 + i}]: Failed password for deploy "
                          f"from {ips[i % 2]} port {51000 + i} ssh2", "meta": m})
    ok, err = _produce(ws2, ev)
    if not ok:
        return _skip(f"could not produce to raw.events: {err}")
    evaluate("A", lambda: _alerts(ws3, ta), COMPANION_BRUTE, {
        SIBLING_BRUTE: "the source-keyed sibling must NOT alert (each address is under its threshold) "
                       "-- otherwise this scenario does not exercise the gap"}, timeout_s, stable)

    # --- B: plain brute force -> sibling only ---------------------------------
    tb = f"livecomp-b-{run}"
    ev = []
    for i in range(12):
        t = now - 40_000 + i * 3_000
        m = _env(tb, i, t, "b")
        m["ip"] = "203.0.113.77"
        ev.append({"source_type": "linux_ssh",
                   "raw": f"Jun 10 13:55:{i:02d} db01 sshd[{2100 + i}]: Failed password for deploy "
                          f"from 203.0.113.77 port {52000 + i} ssh2", "meta": m})
    ok, err = _produce(ws2, ev)
    if ok:
        evaluate("B", lambda: _alerts(ws3, tb), SIBLING_BRUTE, {
            COMPANION_BRUTE: "the companion must be SUPPRESSED when its sibling already alerted "
                             "(one attack, one alert)"}, timeout_s, stable)
    else:
        check(False, f"B: produce failed: {err}")

    # --- C: split port scan -----------------------------------------------------
    tc = f"livecomp-c-{run}"
    ev = []
    for i in range(20):
        t = now - 45_000 + i * 2_000
        src = ips[i % 2]
        m = _env(tc, i, t, "c")
        m["ip"] = src
        ev.append({"source_type": "cisco_asa",
                   "raw": f"%ASA-4-106023: Deny tcp src outside:{src}/{40000 + i} "
                          f"dst inside:10.0.0.10/{20 + i * 7} by access-group acl_out", "meta": m})
    ok, err = _produce(ws2, ev)
    if ok:
        evaluate("C", lambda: _alerts(ws3, tc), COMPANION_SCAN, {
            SIBLING_SCAN: "the source-keyed sibling must NOT alert (each source is under its threshold)"},
            timeout_s, stable)
    else:
        check(False, f"C: produce failed: {err}")

    if FAILS:
        print(f"\n[FAIL] companion live e2e: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        return 1
    print("\n[OK] companion live e2e PASS -- on the real Redis/WS-2/WS-4/WS-3/OpenSearch stack: "
          "split attacks alert via the companion only, an ordinary attack alerts once via the sibling.")
    return 0


# --- --selfcheck: unit-test the wait helpers with injected fake search/clock/sleep ----------------

class _FakeTime:
    def __init__(self):
        self.t = 0.0

    def clock(self):
        return self.t

    def sleep(self, s):
        self.t += s


def _seq_search(seq):
    """search() that yields successive entries of seq, repeating the last one forever."""
    it = iter(seq)
    last = [None]

    def search():
        try:
            last[0] = next(it)
        except StopIteration:
            pass
        return last[0]
    return search


def _a(rule, n=None):
    return {"rule_id": rule, "alert_id": f"{rule}-{n}" if n is not None else rule}


def selfcheck():
    bad: list = []

    def expect(cond, msg):
        if not cond:
            bad.append(msg)

    def run_eval(seq, must_not, timeout_s=30, stable=3, anchor="ANCHOR"):
        ft, fails = _FakeTime(), []
        out = evaluate("T", _seq_search(seq), anchor, must_not, timeout_s, stable, 3.0,
                       ft.clock, ft.sleep, fails)
        return fails, out, ft.t

    # wait_for_anchor: immediate, delayed (with a transient None), never
    ft = _FakeTime()
    found, _, el = wait_for_anchor(_seq_search([[_a("ANCHOR")]]), "ANCHOR", 30, 3.0, ft.clock, ft.sleep)
    expect(found and el == 0, "anchor: immediate hit should return at t=0")
    ft = _FakeTime()
    found, _, el = wait_for_anchor(_seq_search([[], [], None, [_a("ANCHOR")]]), "ANCHOR", 30, 3.0,
                                   ft.clock, ft.sleep)
    expect(found and el == 9.0, f"anchor: delayed hit (with a transient None) should be found at 9s, got {el}")
    ft = _FakeTime()
    found, seen, el = wait_for_anchor(_seq_search([[_a("OTHER")]]), "ANCHOR", 30, 3.0, ft.clock, ft.sleep)
    expect(not found and el >= 30 and [x["rule_id"] for x in seen] == ["OTHER"],
           "anchor: never-appearing anchor must time out and report the alerts seen")

    # settle: a late co-emitted alert must restart the stability count (the vacuous-pass bug)
    ft = _FakeTime()
    seq = [[_a("ANCHOR")], [_a("ANCHOR")], [_a("ANCHOR"), _a("BAD")], [_a("ANCHOR"), _a("BAD")],
           [_a("ANCHOR"), _a("BAD")]]
    alerts, settled, _ = settle(_seq_search(seq), 3, 60, 3.0, ft.clock, ft.sleep)
    expect(settled and {x["rule_id"] for x in alerts} == {"ANCHOR", "BAD"},
           "settle: must wait out the late second alert, not stop after two identical polls")
    ft = _FakeTime()
    growing = [[_a("ANCHOR", n) for n in range(k)] for k in range(1, 40)]
    _, settled, _ = settle(_seq_search(growing), 3, 20, 3.0, ft.clock, ft.sleep)
    expect(not settled, "settle: a perpetually changing set must report settled=False")
    ft = _FakeTime()
    _, settled, _ = settle(_seq_search([[_a("A")], None, [_a("A")], [_a("A")], [_a("A")]]), 3, 60, 3.0,
                           ft.clock, ft.sleep)
    expect(settled, "settle: a transient query error must restart the count, then still settle")

    # evaluate: positive control (forbidden alert lands late -> caught), negative control (clean -> pass)
    fails, _, _ = run_eval([[_a("ANCHOR")], [_a("ANCHOR"), _a("BAD")], [_a("ANCHOR"), _a("BAD")],
                            [_a("ANCHOR"), _a("BAD")]], {"BAD": "bad must not alert"})
    expect(len(fails) == 1 and "bad must not alert" in fails[0],
           f"evaluate: late forbidden alert must be caught after settling, got {fails}")
    fails, _, _ = run_eval([[_a("ANCHOR")]], {"BAD": "bad must not alert"})
    expect(not fails, f"evaluate: clean run must pass, got {fails}")
    # vacuous-pass guard: nothing ever indexed -> FAIL with elapsed time; negatives not evaluated
    fails, _, t = run_eval([[]], {"BAD": "bad must not alert"}, timeout_s=30)
    expect(len(fails) == 1 and "never appeared" in fails[0] and "30s" in fails[0] and t >= 30,
           f"evaluate: missing anchor must FAIL strictly with elapsed time, got {fails}")
    fails, _, _ = run_eval([None], {"BAD": "x"}, timeout_s=9)
    expect(len(fails) == 1 and "never appeared" in fails[0], "evaluate: persistent query errors must FAIL")
    # anchor present but the set never stabilises -> FAIL
    growing = [[_a("ANCHOR", n) for n in range(k)] for k in range(1, 40)]
    fails, _, _ = run_eval(growing, {"BAD": "x"}, timeout_s=20)
    expect(len(fails) == 1 and "stabilise" in fails[0], f"evaluate: unsettled set must FAIL, got {fails}")

    # compose path must not depend on the cwd
    expect(COMPOSE_FILE.is_absolute() and COMPOSE_FILE.name == "docker-compose.yml",
           "compose file path must be absolute, resolved from the script location")
    cwd = os.getcwd()
    try:
        os.chdir(os.path.abspath(os.sep))
        expect(COMPOSE_FILE.exists(), f"compose file must resolve from any cwd: {COMPOSE_FILE}")
    finally:
        os.chdir(cwd)

    if bad:
        print(f"[FAIL] live_companion_e2e selfcheck: {len(bad)} problem(s)")
        for b in bad:
            print("   -", b)
        return 1
    print("[OK] live_companion_e2e selfcheck PASS (anchor/settle/evaluate helpers, compose path)")
    return 0


if __name__ == "__main__":
    sys.exit(selfcheck() if "--selfcheck" in sys.argv[1:] else main())
