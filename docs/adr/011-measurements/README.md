# ADR 011 measurement aids

Scripts behind the `[MEASURED]` numbers in `docs/adr/011-ws8-edge-time-direction.md`.
They are **manual measurement aids**: not named `test_*`, not wired into
`run_all_tests.sh` or CI, and they change no file in the repo. The four proposed
`incident.graph` edge fields are computed inside the scripts only.

Run from the repo root (no Docker, no Redis, no network). Seed 7, all 11
registered storylines, in-process memory bus; the scripts import the real WS-2,
WS-4 and WS-8 code and put `eval/twin`, `eval/adversarial` and `services` on
`sys.path` themselves (`cap.py`).

| script | what it prints | runtime |
|---|---|---|
| `a1.py` | gradable-pair funnel per storyline (ADR Measurements, item 1) | ~30 s |
| `a2.py` | candidate predicate under identity, mirror, swap, shift_1h (item 5) | ~2.5 min |
| `a3.py` | payload growth with the four fields (item 2) | ~30 s |
| `a4.py` | does any graded value move with the fields present (inert check) | ~1 min |
| `a5.py OUT.json` | edge dump; run once normally and once with `FENGARDE_WINDOW_TIME_SOURCE=event`, then compare the two files (`cmp`) | ~30 s each |

```sh
python docs/adr/011-measurements/a1.py
python docs/adr/011-measurements/a2.py
python docs/adr/011-measurements/a3.py
python docs/adr/011-measurements/a4.py
python docs/adr/011-measurements/a5.py /tmp/default.json
FENGARDE_WINDOW_TIME_SOURCE=event python docs/adr/011-measurements/a5.py /tmp/event.json
cmp /tmp/default.json /tmp/event.json
```

Expect warning lines from WS-2 (dead-lettered `web_access` records) and the
geoip sample-map notice on stderr/stdout; they are the twin's normal noise.
Last full reproduction: 2026-11-07 at `39dd67c`, see the ADR's "Reproduction".
If a number differs after a change to `services/`, `eval/` or `contracts/`, the
ADR numbers are stale, not the scripts.
