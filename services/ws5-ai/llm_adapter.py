"""WS-5 layer-3 LLM adapter (Ollama).

The LLM only ever sees the fine tip of the funnel (events WS-4 enqueued to
ai.requests). Three pieces behind one `analyze(event, reasons) -> verdict` interface:

* `OllamaLLM`     -> POSTs to a local Ollama server (env OLLAMA_URL, OLLAMA_MODEL).
                     Local for log confidentiality. Uses stdlib urllib + json only.
* `StubLLM`       -> deterministic offline verdict, used by the contract test and
                     when no Ollama server is configured.
* `FallbackLLM`   -> wraps a primary LLM and degrades to a backup (the stub) when
                     the primary raises (connection refused / timeout / bad output).
                     A runtime LLM failure must never crash the worker.

Interface: `analyze(event, reasons) -> {verdict, summary, level}`.
verdict in {benign, suspicious, malicious} (+ "unknown" safe default);
level   in {low, medium, high, critical}.

Selection (`make_llm()`):
  * OLLAMA_URL set AND reachable -> FallbackLLM(OllamaLLM, StubLLM)
  * otherwise                    -> StubLLM

NOTE: this module has been exercised only against mocked HTTP responses
(urllib.request.urlopen monkeypatched). It has NOT been run against a live Ollama
server in this environment; the network-success path is covered by mocks only.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

try:  # logging is best-effort; tests import this module standalone
    from shared.log import get_logger
    _log = get_logger("ws5-ai")
except Exception:  # pragma: no cover - fallback when shared not importable
    class _NullLog:
        def info(self, *a, **k):
            pass

        warn = error = info
    _log = _NullLog()


# Allowed enum values for a deterministic, downstream-safe verdict.
_VERDICTS = {"benign", "suspicious", "malicious", "unknown"}
_LEVELS = {"low", "medium", "high", "critical"}
_SAFE_VERDICT = {"verdict": "unknown", "summary": "", "level": "low"}

# Upper bound on the Ollama HTTP response we will read into memory. A triage JSON
# verdict is tiny; 1 MiB is generous headroom while still capping a runaway response.
_MAX_RESPONSE_BYTES = 1_048_576

# Upper bounds on the request side. `event` and `reasons` derive from attacker-
# influenced log data (WS-4 -> ai.requests). Bounding what we serialize into the
# prompt stops a pathological event/reason list from inflating the POST body to
# Ollama without limit (memory + a slow, oversized model call).
_MAX_EVENT_CHARS = 4000
_MAX_REASONS_CHARS = 2000


PROMPT_TEMPLATE = (
    "You are a SIEM tier-1 analyst triaging a single security alert.\n"
    "Decide whether the alert is a true positive worth escalating or benign noise.\n"
    "Classify it and reply with STRICT JSON ONLY (no prose, no markdown fences) "
    "of exactly this shape:\n"
    '{{"verdict": "benign|suspicious|malicious", '
    '"level": "low|medium|high|critical", '
    '"summary": "one-line rationale"}}\n'
    "Guidance: benign=noise/expected, suspicious=needs review, malicious=clear "
    "true positive. Match level to verdict severity.\n"
    "Normalized event (JSON): {event}\n"
    "Detection rules it triggered: {reasons}\n"
)


def _normalize_verdict(raw: dict) -> dict:
    """Coerce arbitrary model output into the strict {verdict,summary,level} shape.

    Unknown / missing fields fall back to the safe default rather than raising, so
    malformed model output never propagates a bad enum downstream (WS-3 routing).
    """
    if not isinstance(raw, dict):
        return dict(_SAFE_VERDICT)
    verdict = str(raw.get("verdict", "")).strip().lower()
    level = str(raw.get("level", "")).strip().lower()
    summary = raw.get("summary", "")
    if not isinstance(summary, str):
        summary = json.dumps(summary)
    return {
        "verdict": verdict if verdict in _VERDICTS else "unknown",
        "level": level if level in _LEVELS else "low",
        "summary": summary[:500],
    }


class StubLLM:
    """Deterministic offline analyst. No network, used by tests and as fallback."""

    def analyze(self, event: dict, reasons: list[str]) -> dict:
        score = event.get("siem", {}).get("score", 0)
        sector = event.get("siem", {}).get("sector", "common")
        if score >= 80:
            verdict, level = "malicious", "critical"
        elif score >= 60:
            verdict, level = "suspicious", "high"
        else:
            verdict, level = "benign", "low"
        summary = (f"{sector} event scored {score}; triggered: "
                   f"{', '.join(reasons) or 'none'}.")
        return {"verdict": verdict, "summary": summary, "level": level}


class OllamaLLM:
    """Local-LLM analyst backed by an Ollama server over its HTTP API.

    Uses the stable, non-streaming /api/generate endpoint with format=json so the
    model is constrained to emit a JSON object we can parse deterministically.
    """

    def __init__(self, url: str | None = None, model: str | None = None,
                 timeout: float = 8.0):
        self.url = (url or os.getenv("OLLAMA_URL") or "http://localhost:11434").rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL", "qwen2.5")
        self.timeout = timeout

    def ping(self) -> bool:
        """Cheap reachability probe (GET /api/tags). Never raises."""
        try:
            req = urllib.request.Request(f"{self.url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout):  # noqa: S310
                return True
        except Exception:
            return False

    def analyze(self, event: dict, reasons: list[str]) -> dict:
        """Call the model and return a strict verdict. Raises on transport error
        (caller — FallbackLLM — is responsible for degrading)."""
        # Bound both interpolated fields: `event` and `reasons` are attacker-
        # influenced, so cap the serialized length to keep the prompt (and the
        # POST body to Ollama) from growing without limit.
        event_json = json.dumps(event)[:_MAX_EVENT_CHARS]
        reasons_str = json.dumps(reasons)[:_MAX_REASONS_CHARS]
        prompt = PROMPT_TEMPLATE.format(event=event_json, reasons=reasons_str)
        body = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "format": "json",
            "stream": False,
        }).encode()
        req = urllib.request.Request(
            f"{self.url}/api/generate", data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            # Cap the read: a triage verdict is a few hundred bytes, so bound it so a
            # runaway/hostile response can't exhaust memory. An over-cap response is
            # truncated -> json.loads fails -> FallbackLLM degrades to the stub.
            data = json.loads(resp.read(_MAX_RESPONSE_BYTES).decode())
        # Ollama wraps the model text in {"response": "..."}; that text is the JSON.
        text = data.get("response", "") if isinstance(data, dict) else ""
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            # Model ignored the JSON contract — degrade to a safe default verdict
            # but keep its prose as the summary for the analyst.
            _log.warn("ollama returned non-JSON output", model=self.model)
            return {"verdict": "unknown", "level": "low",
                    "summary": (text or "")[:500]}
        return _normalize_verdict(parsed)


class FallbackLLM:
    """Try the primary LLM; on ANY exception, log and fall back to the backup.

    This is what keeps a flaky/absent Ollama from crashing the worker loop.
    """

    def __init__(self, primary, backup):
        self.primary = primary
        self.backup = backup

    def analyze(self, event: dict, reasons: list[str]) -> dict:
        try:
            return self.primary.analyze(event, reasons)
        except (urllib.error.URLError, OSError, TimeoutError,
                json.JSONDecodeError, ValueError) as exc:
            _log.warn("llm primary failed; degrading to backup",
                         error=str(exc), backup=type(self.backup).__name__)
            return self.backup.analyze(event, reasons)
        except Exception as exc:  # pragma: no cover - defensive catch-all
            _log.error("llm primary raised unexpected error; degrading",
                       error=str(exc))
            return self.backup.analyze(event, reasons)


def make_llm():
    """Pick the LLM per the env contract.

    OLLAMA_URL set AND server reachable -> Ollama (with stub fallback at runtime).
    Otherwise -> StubLLM. The reachability probe means a misconfigured URL still
    boots cleanly on the stub instead of failing every request.
    """
    if os.getenv("OLLAMA_URL"):
        ollama = OllamaLLM()
        if ollama.ping():
            _log.info("ai triage using local Ollama", url=ollama.url, model=ollama.model)
            return FallbackLLM(ollama, StubLLM())
        _log.warn("OLLAMA_URL set but server unreachable; using StubLLM",
                     url=ollama.url)
    return StubLLM()
