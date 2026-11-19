# Integration branch 2026-11-19

Branch `integration/2026-11-19`, cut from `origin/main` at `182a4ab`. It merges every
open PR branch with `git merge --no-ff -s ort --signoff origin/<branch> -m "merge: <branch>"`,
in the order below. Nothing here is merged into `main`; the PR branches are untouched.
This file records, per merge, every conflicted file and how it was resolved, so each
resolution can be replayed on the PR branch when it is rebased/merged onto the new `main`.

Resolution conventions used throughout:

- **CHANGELOG.md** (`## [Unreleased]`): every conflict was two blocks inserted at the same
  spot. Keep both; the incoming PR's section(s) are placed first (newest merge on top),
  the already-merged sections follow, blank line between. No section dropped or edited.
- **SSOT.md** (status table): keep every row. The incoming PR's new row goes on top of the
  already-merged rows. Several PRs also carry a stale copy of the WP-1.3 shipper-adapters
  row (from the base); the copy already on the integration branch (the newer text, from #152)
  is kept and the stale one dropped, so that row appears exactly once.
- **run_all_tests.sh**: keep every stanza, in merge order, with a bare `echo` line between
  stanzas (the file's own separator). After each conflict `python tools/test_gate_tiers.py`
  and `python tools/check_lane_coverage.py` were run and pass.

## Merges

| # | Branch (PR) | Conflicted files |
|---|---|---|
| 1 | `wp/1.5-zeek-suricata` (#152) | none |
| 2 | `wp/1.4-shipper-recipes-v2` (#153) | `SSOT.md` |
| 3 | `wp/2.1-homelab-profile` (#154) | `CHANGELOG.md`, `SSOT.md` |
| 4 | `wp/2.3-fp-report` (#160) | `CHANGELOG.md`, `SSOT.md` |
| 5 | `wp/2.2-labelling` (#161) | `.gitignore`, `CHANGELOG.md`, `SSOT.md`, `run_all_tests.sh` |
| 6 | `wp/3.1-tls` (#162) | `CHANGELOG.md`, `SSOT.md`, `run_all_tests.sh` |
| 7 | `wp/3.2-secure-defaults` (#163) | `CHANGELOG.md`, `SSOT.md`, `run_all_tests.sh` |
| 8 | `wp/4.6-triage-honesty` (#164) | `CHANGELOG.md`, `SSOT.md` |
| 9 | `wp/6.1-gh2-sessions` (#165) | `CHANGELOG.md`, `SSOT.md` |
| 10 | `wp/6.2-dashboard-tenant-scope-v2` (#178) | `CHANGELOG.md`, `services/ws7-dashboard/app/src/demo/fixtures-ai-ot.json` |
| 11 | `wp/http-spool-drain` (#166) | `CHANGELOG.md`, `SSOT.md`, `run_all_tests.sh`, `infra/docker-compose.homelab.yml` (add/add) |
| 12 | `wp/3.3-backup-restore` (#167) | `CHANGELOG.md`, `SSOT.md` |
| 13 | `wp/3.4-sizing-retention` (#168) | `CHANGELOG.md`, `SSOT.md` |
| 14 | `wp/4.4-gh3-reverify` (#169) | `CHANGELOG.md`, `SSOT.md`, `docs/gap-hunt-status.md` |
| 15 | `wp/4.5-public-labelled-data` (#170) | `CHANGELOG.md`, `SSOT.md` |
| 16 | `docs/ws8-edge-time-adr` (#176) | `CHANGELOG.md`, `SSOT.md` |
| 17 | `docs/ws8-causal-evidence-adr-v2` (#177) | none |

### Per-merge detail

1. **#152** clean.
2. **#153** `SSOT.md`: #152 added the WP-1.5 row, #153 added the WP-1.4 row and rewrote the
   WP-1.3 row (adds "3,039-mutation totality sweep, boundary timestamps ...; `adapt_record`
   is exception-total"). Result, top to bottom: WP-1.5, WP-1.4, WP-1.3 (the #153 text of WP-1.3).
   Note: this is the only merge where the updated WP-1.3 text came from the incoming side; in
   every later merge the incoming copy is the old text and is dropped (see conventions).
3. **#154** `CHANGELOG.md`: #154 sections (WP-2.1 review fixes, WS1_SEED_MOCK, WP-2.1) above the
   WP-1.5 sections. `SSOT.md`: WP-2.1 row on top; incoming stale WP-1.3 row dropped.
4. **#160** `CHANGELOG.md`: WP-2.3 section on top. `SSOT.md`: WP-2.3 row on top.
5. **#161**
   - `.gitignore`: both sides appended after `tools/console_e2e/out/`. #161's block is a
     superset (`eval/real/review/`, `labels.jsonl`, `out/`, `*.labels.jsonl`, `latest.json`,
     `latest.md`); #160 only added `eval/real/out/`. Kept #161's block and re-attached #160's
     comment as a note on `eval/real/out/` (it is also where `alert_fp_report.py --out` writes).
   - `run_all_tests.sh`: kept the #160 `alert_fp_report` stanza then the #161 labelling stanza
     (`test_alert_labeller.py`), `echo` between them.
   - `CHANGELOG.md`, `SSOT.md`: WP-2.2 on top.
6. **#162** `run_all_tests.sh`: kept #160, #161 stanzas, then `test_tls_profile.py`.
   `CHANGELOG.md`/`SSOT.md`: WP-3.1 on top.
7. **#163** `run_all_tests.sh`: kept all of the above, then the WP-3.2 stanza
   (`test_prodcheck.py` + `test_compose_prod_env.py`). `CHANGELOG.md`/`SSOT.md`: WP-3.2 on top.
8. **#164** `CHANGELOG.md`/`SSOT.md`: WP-4.6 on top.
9. **#165** `CHANGELOG.md`/`SSOT.md`: WP-6.1 section/row. In `CHANGELOG.md` git anchored the
   conflict below the WP-1.3 sections, so the WP-6.1 section sits between the WP-1.3 and
   WP-1.4 sections rather than at the very top (order only; nothing lost).
10. **#178** `CHANGELOG.md`: WP-6.2 Security section on top.
    `services/ws7-dashboard/app/src/demo/fixtures-ai-ot.json` is a generated file: took the
    `--ours` side to finish the merge, then regenerated after the last merge with
    `python tools/build_ai_ot_fixtures.py` and committed it
    (`chore(ws7): regenerate ai-ot demo fixtures ...`; belongs to #178).
11. **#166**
    - `infra/docker-compose.homelab.yml` (add/add: #154 adds the full profile, #166 adds only
      the HTTP-spool enablement and says so in its header): kept the #154 file whole and added
      to `ws1-collectors.environment`
      `INGEST_HTTP_SPOOL_PATH=/var/lib/fengarde/spool/http-spool.jsonl` (same `ws1-spool` volume,
      which #154 already declares) plus one header comment bullet. #166's own header comment
      (the add/add warning) is dropped because it no longer applies.
      `python tools/test_homelab_compose.py` passes on the result.
    - `run_all_tests.sh`: `test_http_spool_drain.py` stanza appended after WP-3.2.
    - `CHANGELOG.md`/`SSOT.md`: spool-drain section/row on top.
12. **#167**, 13. **#168**, 15. **#170**, 16. **#176**: `CHANGELOG.md`/`SSOT.md` only,
    incoming section/row on top.
14. **#169** `docs/gap-hunt-status.md`, the open-tasks table: #165 rewrote the `GH-2` row
    (implemented on PR #165, option C) and #169 rewrote the `GH-3` row (closed as a sample,
    pointer to the WP-4.4 section) and also still carried the old `GH-2` row. Resolution: the
    #165 `GH-2` row plus the #169 `GH-3` row. `CHANGELOG.md`/`SSOT.md`: WP-4.4 on top.
17. **#177** clean.

## PR heads merged

These are the exact branch tips merged (12-char sha). Commits pushed to the PR branches after
this date are NOT in the integration branch.

| PR | Branch | Merged head |
|---|---|---|
| #152 | `wp/1.5-zeek-suricata` | `3db6bd77b652` |
| #153 | `wp/1.4-shipper-recipes-v2` | `f766452d10cf` |
| #154 | `wp/2.1-homelab-profile` | `c4b7fc971d70` |
| #160 | `wp/2.3-fp-report` | `68b0ba013959` |
| #161 | `wp/2.2-labelling` | `2424b8976d36` |
| #162 | `wp/3.1-tls` | `1693f3489893` |
| #163 | `wp/3.2-secure-defaults` | `906fe5345cf8` |
| #164 | `wp/4.6-triage-honesty` | `366895d0576e` |
| #165 | `wp/6.1-gh2-sessions` | `8bfc7c88b9de` |
| #178 | `wp/6.2-dashboard-tenant-scope-v2` | `3bf722ee9e41` |
| #166 | `wp/http-spool-drain` | `6da09a3c0bd9` |
| #167 | `wp/3.3-backup-restore` | `882d0a54acd1` |
| #168 | `wp/3.4-sizing-retention` | `4613c54b5196` |
| #169 | `wp/4.4-gh3-reverify` | `35c4996b0c89` |
| #170 | `wp/4.5-public-labelled-data` | `c7b17253e22f` |
| #176 | `docs/ws8-edge-time-adr` | `b1880d8b1579` |
| #177 | `docs/ws8-causal-evidence-adr-v2` | `456423f2bb61` |

## Combination fixes

None needed: no test, lint or type failure appeared only in combination. The one extra commit on the
branch is the regeneration of `fixtures-ai-ot.json` (belongs to #178, see merge 10).

## Verification

On the branch head before this file was added:

- `PY=python PYTHON=python bash run_all_tests.sh`: exit 0, final line `ALL TESTS PASS` (the deliberate
  negative-control output, e.g. `[FAIL] fengarde-bench`, is expected).
- `ruff check services/ tools/`: all checks passed.
- mypy loop from `.github/workflows/ci.yml` (quality job), all 11 targets: no issues.
- `python tools/check_dco.py $(git merge-base HEAD origin/main)`: 94/94 commits signed off.
- `python tools/test_gate_tiers.py` and `python tools/check_lane_coverage.py`: pass.
