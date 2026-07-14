"""Linux SSH/PAM parser: sshd syslog -> OCSF Authentication (3002).

OpenSSH ``sshd`` is the most common interactive-auth source on Linux hosts and
the canonical brute-force target named by ``contracts/rules/common_bruteforce.yml``
("AD, LDAP, RADIUS, SSH"). This parser turns its syslog lines into OCSF
Authentication events so that rule fires on SSH exactly as it does on AD.

Activity_id mapping (Contract A / ocsf-classes.md):

    "Accepted password|publickey for ..."     -> activity_id 1 (Logon),   Success
    "session closed for user ..."             -> activity_id 2 (Logoff),  Success
    "Failed password ..." / "authentication   -> activity_id 4 (Failure), Failure
        failure" / "Invalid user ..."

Typical lines (``raw`` is the syslog string, ``meta`` may carry ip/received_at)::

    Jun 10 13:55:36 db01 sshd[2154]: Failed password for invalid user admin from 203.0.113.5 port 51000 ssh2
    Jun 10 13:55:40 db01 sshd[2160]: Accepted publickey for deploy from 10.0.0.6 port 50022 ssh2
    Jun 10 14:01:02 db01 sshd[2154]: pam_unix(sshd:session): session closed for user jdoe

Syslog RFC3164 timestamps carry no year, so event time comes from
``meta.received_at`` when present (consistent with the Cisco ASA parser), falling
back to now.
"""
from __future__ import annotations

import re
import time
from typing import Optional

from .base import Parser, SEV_HIGH, SEV_INFO, IPV4

_CLASS = 3002  # Authentication

# Only act on sshd / pam_unix(sshd:...) lines.
_SSHD = re.compile(r"sshd(?:\[\d+\])?:|pam_unix\(sshd:")

# "Accepted password for jdoe from 10.0.0.5 port 50022 ssh2"
# "Accepted publickey for deploy from 10.0.0.6 port 50022 ssh2"
# The IP is captured loosely (\d{1,3}) so a line with a malformed octet still
# MATCHES (we keep the user + the fact of a failed login); the address is then
# validated in parse() and dropped if out of range, rather than emitting an event
# that fails Contract A's endpoint pattern and gets dead-lettered (see IPV4).
_ACCEPTED = re.compile(
    r"Accepted\s+\S+\s+for\s+(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?:\s+port\s+(?P<port>\d+))?"
)
# "Failed password for [invalid user ]admin from 203.0.113.5 port 51000 ssh2"
_FAILED = re.compile(
    r"Failed\s+\S+\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?:\s+port\s+(?P<port>\d+))?"
)
# "Invalid user admin from 203.0.113.5 port 51000"
_INVALID = re.compile(
    r"Invalid user\s+(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?:\s+port\s+(?P<port>\d+))?"
)

_IPV4_FULL = re.compile(IPV4 + r"\Z")


def _valid_ip(ip):
    """True if ``ip`` is a well-formed 0-255-octet IPv4 (else it must be dropped
    so it can't fail Contract A's endpoint pattern downstream)."""
    return isinstance(ip, str) and bool(_IPV4_FULL.match(ip))
# "pam_unix(sshd:session): session closed|opened for user jdoe"
_SESSION = re.compile(
    r"session\s+(?P<state>opened|closed)\s+for user\s+(?P<user>\S+)"
)
# generic "authentication failure ... rhost=203.0.113.5 ... user=admin"
_PAM_FAIL = re.compile(r"authentication failure")
_RHOST = re.compile(r"rhost=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
_PAMUSER = re.compile(r"user=(?P<user>\S+)")


class LinuxSshParser(Parser):
    SOURCE_TYPE = "linux_ssh"
    SECTOR = "common"
    ORIGINAL_FORMAT = "syslog"
    PRODUCT = {"name": "OpenSSH", "vendor_name": "OpenBSD"}

    def parse(self, raw: dict) -> Optional[dict]:
        line = raw.get("raw")
        if not isinstance(line, str) or not _SSHD.search(line):
            return None
        meta = raw.get("meta") or {}

        activity_id, status, severity_id, user, ip, port = self._classify(line)
        if activity_id is None:
            return None  # an sshd line we don't model (e.g. "Connection closed")

        if not _valid_ip(ip):
            ip = None  # malformed octet in the log line -> drop, fall back to meta.ip
        ip = ip or meta.get("ip")
        verb = {1: "Logon", 2: "Logoff", 4: "Failed logon"}[activity_id]
        message = f"SSH {verb.lower()} for user {user or '?'}"
        if ip:
            message += f" from {ip}"

        event = self.base_event(
            class_uid=_CLASS,
            activity_id=activity_id,
            severity_id=severity_id,
            time_ms=self._time_ms(meta),
            ingest_id=meta.get("ingest_id"),
            logged_time=self._logged_time(meta),
            status=status,
            message=message,
        )

        if ip:
            sep: dict = {"ip": ip}
            if port is not None:
                sep["port"] = port
            event["src_endpoint"] = sep
        if user:
            event["actor"] = {"user": {"name": user}}

        return event

    # ---- classification ------------------------------------------------

    @staticmethod
    def _classify(line: str):
        """Return (activity_id, status, severity_id, user, ip, port) or Nones."""
        m = _ACCEPTED.search(line)
        if m:
            return (1, "Success", SEV_INFO, m.group("user"),
                    m.group("ip"), _as_int(m.group("port")))

        m = _FAILED.search(line)
        if m:
            return (4, "Failure", SEV_HIGH, m.group("user"),
                    m.group("ip"), _as_int(m.group("port")))

        m = _INVALID.search(line)
        if m:
            return (4, "Failure", SEV_HIGH, m.group("user"),
                    m.group("ip"), _as_int(m.group("port")))

        if _PAM_FAIL.search(line):
            um = _PAMUSER.search(line)
            rm = _RHOST.search(line)
            return (4, "Failure", SEV_HIGH,
                    um.group("user") if um else None,
                    rm.group("ip") if rm else None, None)

        m = _SESSION.search(line)
        if m and m.group("state") == "closed":
            return (2, "Success", SEV_INFO, m.group("user"), None, None)
        # "session opened" is a low-signal duplicate of Accepted -> skip.

        return (None, None, None, None, None, None)

    @staticmethod
    def _time_ms(meta: dict) -> int:
        ra = meta.get("received_at")
        if isinstance(ra, (int, float)):
            return int(ra * 1000) if ra < 1e12 else int(ra)
        return int(time.time() * 1000)

    @staticmethod
    def _logged_time(meta: dict) -> Optional[int]:
        ra = meta.get("received_at")
        if isinstance(ra, (int, float)):
            return int(ra * 1000) if ra < 1e12 else int(ra)
        return None


def _as_int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
