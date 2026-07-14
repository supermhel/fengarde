"""Base parser contract for WS-2 Normalization.

Each source type gets ONE parser, isolated in its own module and registered in
``parsers/__init__.py``. A parser turns a raw bus payload
(``{source_type, raw, meta}`` from ``raw.events``, Contract B) into a single OCSF
event that validates against Contract A.

Invariants every parser MUST honour:

* ``type_uid`` is **derived**, never hand-set — use
  :func:`shared.ocsf.make_type_uid`.
* The ``siem.*`` block (``sector``, ``source_type``, ``ingest_id``) is always set.
* ``category_uid`` is ``class_uid // 1000`` (floored), per Contract A.
* The output validates: ``shared.ocsf.validate(event) == []``.

Adding a new source = adding one ``Parser`` subclass module and registering it.
No existing parser is touched.
"""
from __future__ import annotations

import uuid
from typing import Optional

from shared.ocsf import make_type_uid

# Octet-bounded IPv4 (0-255 per octet). A loose ``\d{1,3}`` accepts 999.999.999.999,
# which parses fine but then FAILS Contract A's endpoint pattern -> the whole event
# is dead-lettered. Attacker-controllable via a "from <ip>" field in a log line, so
# an out-of-range address must simply not be captured (fall back to meta.ip / none).
IPV4 = r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"


# OCSF severity_id values (Contract A).
SEV_UNKNOWN = 0
SEV_INFO = 1
SEV_LOW = 2
SEV_MEDIUM = 3
SEV_HIGH = 4
SEV_CRITICAL = 5
SEV_FATAL = 6


# Outcome-token vocabularies for status_from_outcome(). Kept broad on purpose:
# a security-relevant event (a failed login) recorded as "Success" suppresses the
# very rules that watch for it, so an explicit failure signal must win.
_SUCCESS_TOKENS = frozenset({
    "success", "succeeded", "succeed", "ok", "true", "allow", "allowed",
    "pass", "passed", "complete", "completed", "granted", "200", "201", "204",
})
_FAILURE_TOKENS = frozenset({
    "failure", "failed", "fail", "error", "denied", "deny", "false", "invalid",
    "unauthorized", "forbidden", "reject", "rejected", "401", "403", "500",
})


def status_from_outcome(rec: dict,
                        keys=("status", "result", "outcome", "success"),
                        default: str = "Success") -> str:
    """Derive an OCSF ``status`` ("Success"/"Failure") from a record's real outcome
    field instead of hardcoding it. Robust to the shapes real logs use: bool,
    HTTP-ish numbers, and success/failure word tokens (incl. the string ``"false"``
    and ``"succeeded"`` that naive truthiness / exact-match checks get wrong).
    Returns ``default`` when no recognized outcome field is present -- so absence
    never fabricates a failure, but an explicit failure signal is always honored."""
    val = None
    if isinstance(rec, dict):
        for k in keys:
            if rec.get(k) is not None:
                val = rec.get(k)
                break
    if val is None:
        return default
    if isinstance(val, bool):
        return "Success" if val else "Failure"
    if isinstance(val, (int, float)):
        n = int(val)
        if 200 <= n < 400:
            return "Success"
        if 400 <= n < 600:
            return "Failure"
        return "Success" if n else "Failure"
    s = str(val).strip().lower()
    if s in _SUCCESS_TOKENS:
        return "Success"
    if s in _FAILURE_TOKENS:
        return "Failure"
    return default


class Parser:
    """Abstract per-source parser.

    Subclasses set ``SOURCE_TYPE``, ``SECTOR`` and ``ORIGINAL_FORMAT`` and
    implement :meth:`parse`.
    """

    #: Source type string this parser handles (matches ``raw["source_type"]``).
    SOURCE_TYPE: str = ""
    #: Routing sector for the ``siem.*`` block: bank | datacenter | common.
    SECTOR: str = "common"
    #: metadata.original_format enum value for this source.
    ORIGINAL_FORMAT: str = "json"
    #: metadata.product describing the source product.
    PRODUCT: dict = {"name": "unknown"}

    def parse(self, raw: dict) -> Optional[dict]:
        """Parse one raw bus payload into a single OCSF event.

        :param raw: ``{"source_type": str, "raw": <str|dict>, "meta": dict}``.
        :returns: an OCSF event (Contract A) or ``None`` if the line is not
            relevant / unparseable (caller drops ``None``).
        """
        raise NotImplementedError

    # ---- helpers shared by every parser -------------------------------

    def base_event(
        self,
        class_uid: int,
        activity_id: int,
        severity_id: int,
        time_ms: int,
        ingest_id: Optional[str] = None,
        logged_time: Optional[int] = None,
        status: Optional[str] = None,
        message: Optional[str] = None,
    ) -> dict:
        """Build the common OCSF scaffold with a derived ``type_uid``.

        Parsers fill in ``src_endpoint`` / ``dst_endpoint`` / ``actor`` on the
        returned dict.
        """
        category_uid = class_uid // 1000  # floored, per Contract A
        event = {
            "metadata": {
                "version": "1.1.0",
                "product": dict(self.PRODUCT),
                "original_format": self.ORIGINAL_FORMAT,
            },
            "class_uid": class_uid,
            "category_uid": category_uid,
            "activity_id": activity_id,
            "type_uid": make_type_uid(class_uid, activity_id),  # derived, never hand-set
            "severity_id": severity_id,
            "time": time_ms,
            "siem": {
                "sector": self.SECTOR,
                "source_type": self.SOURCE_TYPE,
                "ingest_id": ingest_id or str(uuid.uuid4()),
            },
        }
        if logged_time is not None:
            event["metadata"]["logged_time"] = logged_time
        if status is not None:
            event["status"] = status
        if message is not None:
            event["message"] = message
        return event

    @staticmethod
    def partition_key(event: dict) -> str:
        """Bus partition key for ``normalized.events`` = ``src_endpoint.ip``."""
        return (event.get("src_endpoint") or {}).get("ip", "0.0.0.0")
