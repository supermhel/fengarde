<!--
Thanks for contributing to FENGARDE! Please fill this out so reviewers can move fast.
See CONTRIBUTING.md. For a new parser, see docs/adding-a-parser.md.
-->

## What this PR does

A short description of the change.

## Related issue

<!-- e.g. Closes #123 -->

## Type of change

- [ ] New parser (new log source)
- [ ] Bug fix
- [ ] Feature / enhancement
- [ ] Docs / infra / developer experience
- [ ] Other:

## Verification

- [ ] `make test` (i.e. `./run_all_tests.sh`) passes locally.
- [ ] If evaluation inputs or atom values changed: `python eval/twin/ratchet.py refresh --reason "..."`
      was run from a clean, full-gate artifact set; no baseline number was edited by hand.
- [ ] Any accepted drop uses `eval/twin/ratchet_waivers.json` with an owner,
      issue/PR evidence, a reason, and an expiry no more than 45 days away.
- [ ] `python eval/twin/ratchet.py guard --base origin/main` and
      `python eval/twin/test_ratchet.py` pass for Phase 6 changes.
- [ ] For a parser: `cd services/ws2-normalization && python test_contract.py` passes,
      and I added a sample + an `expected` entry that exercises it.
- [ ] New behavior is covered by a contract test or sample.

```
paste the relevant passing test output here
```

## Checklist

- [ ] One logical change (no unrelated refactors bundled in).
- [ ] I did not hand-set `type_uid` (it's derived via `base_event()`).
- [ ] Output still validates against Contract A (OCSF).
- [ ] No real secrets, credentials, or real PII/IPs committed (samples are redacted).
- [ ] Status claims are accurate — nothing is described as working if it's stubbed.
- [ ] If this adds/changes a rule: I understand the engine executes rule files
      (SECURITY.md) and the `condition` is safe.
- [ ] By submitting, I agree my contribution is licensed under Apache-2.0 (LICENSE).
- [ ] Every commit in this PR carries a `Signed-off-by:` trailer
      (DCO v1.1 — `git commit -s`); the `DCO` workflow enforces this on PRs.
