# OSS-Fuzz submission package (prepared 2026-10-20, NOT submitted)

You submit this yourself: it needs a Google-account-linked contact email, and OSS-Fuzz
decides acceptance case by case.

## What exists
- `projects/fengarde/{project.yaml,Dockerfile,build.sh}` on local branch `feat/phase5-ossfuzz-wip`
  (worktree `SIEM App - ossfuzz`). 19 Atheris targets, one per parser, built from
  `tools/fuzz/fuzz_<name>.py` on `main`.
- Verified: all 19 target files exist on `main` and match the build.sh list (checked 2026-10-20).
- NOT verified: the 17 targets compiled and passed `check_build` against a local oss-fuzz clone
  on 2026-10-14; the 2 added since (`fuzz_m365_audit`, `fuzz_mail_gateway`) have never been
  built by OSS-Fuzz's image. Run `python infra/helper.py build_fuzzers fengarde` and
  `check_build fengarde` in a google/oss-fuzz clone (needs Docker) before submitting.
- Also unverified: the Dockerfile clones `main` at build time (no pin); the base image installs
  atheris latest.

## Before you submit (your steps)
1. Pick the primary contact. The address must be tied to a Google account (it receives
   ClusterFuzz crash reports). `project.yaml` currently says dylandjomou@yahoo.de, which needs a
   Google account created with that address, or replace it with a gmail address.
2. Fork github.com/google/oss-fuzz, copy `projects/fengarde/` into it, run the local build and
   check_build above, then open the PR.

## Suggested PR description (edit freely)
> Adds FENGARDE (github.com/supermhel/fengarde), an Apache-2.0 self-hosted security log pipeline.
> Its WS-2 parsers turn untrusted raw log input (syslog, Windows Event Log XML, Sysmon, CEF,
> CloudTrail JSON, Kubernetes audit, DNS, OPC UA/Modbus audit, mail/M365 audit and others) into
> OCSF events, so every parser sits on an attacker-controlled input path: anyone who can get a
> line into a monitored log can reach it. 19 pure-Python parsers, one Atheris harness each
> (`tools/fuzz/`), already fuzzed in CI via `.github/workflows/fuzz.yml`. We are a small project
> (single maintainer, early-stage, 12 stars), so the case is exposure, not popularity.

## Honest eligibility note
OSS-Fuzz asks for a significant user base or criticality. FENGARDE has neither today. A
rejection is plausible. Fallback if declined: keep `fuzz.yml` (already runs the 19 targets) and
add ClusterFuzzLite for PR fuzzing, which has no acceptance gate. (I have not verified
ClusterFuzzLite is not already configured: check `.github/workflows`.)
