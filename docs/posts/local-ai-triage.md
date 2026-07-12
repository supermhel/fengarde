# AI triage that never leaves your network

*Draft technical write-up — v0.4.*

Every SIEM vendor now has an "AI analyst" feature. Almost all of them mean:
your alert — rule name, source IP, username, whatever raw log text triggered
it — gets serialized into a prompt and sent to a cloud LLM API. For an
observability tool (traces, metrics) that's a defensible trade-off. For a
*security* tool, it's a harder sell: you're piping the exact data an attacker
would want — who got compromised, from where, doing what — through a
third-party API, during the incident you're trying to keep quiet about.

ARGIEM's WS-5 AI-triage service defaults to
[Ollama](https://ollama.com/) — a local LLM runtime. Set `OLLAMA_URL` to a
model running on your own hardware (or your own VPC) and every triage verdict
is generated without a single byte leaving your network. No `OLLAMA_URL` set?
The service degrades to a documented passthrough stub — the pipeline still
produces real alerts with zero AI dependency at all
(`services/ws5-ai/llm_adapter.py::make_llm()`).

## The blast-radius argument, made concrete

Normalized event content — including attacker-controlled log fields — goes
into the triage prompt, so a crafted log line can attempt prompt injection
against the model. Two things bound what that can actually do:

1. **The verdict is advisory.** WS-5's output annotates an alert that
   detection *already* raised; it never gates or suppresses an alert. A
   compromised model can produce a bad summary — it cannot make a real
   detection disappear.
2. **Output is coerced to a fixed enum.** `verdict`/`level` are validated
   against a closed set with a safe default; malformed or hostile model
   output cannot inject arbitrary data downstream (`SECURITY.md` §6).

## v0.4's addition: a report draft, still local-first by default

v0.4 adds an incident-report hook (`contracts/reporting.md`) — an alert
becomes a structured markdown draft on request. The **builtin backend is a
plain template renderer, zero AI, zero network call** — every report is
demoable and functional with no LLM at all. A paid, optional backend
(argiem-sec) can plug in richer regulatory content later via the same
contract, but the open pipeline was never designed to require it.

## What's still honest to say is missing

Prompt-injection *defenses* (beyond the enum-coercion above) are still an
open item — documented as such, not claimed as solved. "Local-first" is a
network-topology guarantee, not a content-safety one.

*Read the adapter at
[`services/ws5-ai/llm_adapter.py`](../../services/ws5-ai/llm_adapter.py) and
the reporting contract at [`contracts/reporting.md`](../../contracts/reporting.md).*
