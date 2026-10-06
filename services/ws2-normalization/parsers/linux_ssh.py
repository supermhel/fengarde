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

from .base import Parser, SEV_HIGH, SEV_INFO
from .timeutil import to_epoch_ms
from shared.ocsf import valid_ip

_CLASS = 3002  # Authentication

# The server-written tag. OpenSSH 9.8+ splits the daemon into ``sshd-session`` /
# ``sshd-auth`` (and some distros ship other ``sshd-<x>`` helpers), each optionally
# ``[pid]``-suffixed; a PAM line may also arrive WITHOUT any sshd tag
# (``pam_sss(sshd:auth): ...``, RFC 5424 forwarders), so ANY ``pam_<module>(sshd:``
# counts. The bounded ``{1,N}`` quantifiers keep the scan linear on adversarial runs
# such as ``pam_pam_pam_...``.
_SSHD = re.compile(r"sshd(?:-[a-z]{1,16})?(?:\[\d{1,10}\])?:|pam_\w{1,40}\(sshd:")

# Solaris / illumos decorate the message: ``sshd[7]: [ID 800047 auth.info] Failed ...``.
_SOLARIS_ID = re.compile(r"\[ID\s+\d+\s+\w+\.\w+\]\s*")

# IP token: hex, dots and colons only -> captures BOTH IPv4 (10.0.0.5) and IPv6
# (2001:db8::1). Captured loosely so a line with a malformed address still MATCHES
# (we keep the user + the fact of the login); the address is then validated with
# ipaddress in parse() and dropped if it isn't a real IP, rather than emitting an
# event that fails Contract A's endpoint pattern and gets dead-lettered.
_IPTOKEN = r"[0-9A-Fa-f:.]+"

# ---- grammar (F3 2026-10-02, rewritten after the ssh-differential review) -----------------
# The account name in these lines is text the CLIENT sent, and sshd echoes it verbatim in
# the MIDDLE of the line; the server writes the peer address and port AFTER it. So:
#   * the TAG is the LEFTMOST match of _SSHD (the server-written tag always precedes
#     client-chosen text) and the message KIND must be the very start of the body after
#     it -- never a phrase found somewhere inside it;
#   * the account is the text between the kind prefix and the real source, and the real
#     source is the RIGHTMOST ``from <ip>`` clause, so a ``from 198.18.9.9 port 1`` typed
#     into the name stays in the name;
#   * PAM failures: ``rhost=`` precedes ``user=`` (the client-chosen, LAST field), so the
#     first ``user=`` starts the account (the whole remainder) and the source is the
#     ``rhost=`` BEFORE it.
# NO regex here backtracks on client-controlled text: each kind prefix is a short anchored
# regex, and everything after it is a linear scan (finditer / search / rfind). The previous
# ``(?P<user>.+) from <ip> ... \s*\Z`` forms were quadratic-to-cubic on whitespace runs
# (26-40 s for one 64 KB line).
#
# Residual ambiguity that no grammar can remove: text the SERVER echoes AFTER the real
# source and that a client can influence (the key ID of an SSH certificate login) could
# itself contain an IP-shaped ``from <ip>``; and a username that itself begins with
# ``invalid user `` is indistinguishable from the server's own marker.
_ACCEPTED = re.compile(r"Accepted\s+\S+\s+for\s+")
_FAILED = re.compile(r"Failed\s+\S+\s+for\s+(?:invalid user\s+)?")
_INVALID = re.compile(r"Invalid user\s+")
# one candidate source clause; the optional ``%zone`` of an IPv6 link-local peer is
# consumed but kept out of the stored address.
_FROM = re.compile(r"\sfrom\s+(?P<ip>" + _IPTOKEN + r")(?:%\S*)?")
_PORT = re.compile(r"\s+port\s+(\d+)")
# "IP-shaped": a digit next to a dot (IPv4, including 999.999.999.999) or two colons
# (IPv6). A hex WORD such as ``feed`` or ``a.b`` after a ``from`` is not a source clause.
_IPSHAPE = re.compile(r"\d\.|\.\d|:[^:]*:")


# FIX 7: the local _valid_ip() was replaced by shared.ocsf.valid_ip, which
# additionally collapses IPv4-mapped IPv6 ("::ffff:10.0.0.5") to its dotted-quad
# form ("10.0.0.5") so dual-stack auth events no longer fail Contract A's
# endpoint pattern and get dead-lettered downstream. (The ipaddress.ip_address
# it replaced accepted the mapped form but passed it through unnormalized.)
# "pam_unix(sshd:session): session closed|opened for user jdoe"
_SESSION = re.compile(
    r"pam_\w{1,40}\(sshd:session\):\s+session\s+(?P<state>opened|closed)\s+for user\s+"
)
# "pam_unix(sshd:auth): authentication failure; ... rhost=203.0.113.5  user=admin"
# "PAM 2 more authentication failures; ... rhost=203.0.113.5  user=root"
_PAM_FAIL = re.compile(
    r"(?:pam_\w{1,40}\(sshd:auth\):\s+authentication failure|PAM\s+\d+\s+more authentication failures?)"
)
# ``ruser=`` is not ``user=``; the lookbehind keeps it out.
_PAMUSER = re.compile(r"(?<!\S)user=")
_RHOST = re.compile(r"(?<!\S)rhost=(?P<ip>" + _IPTOKEN + r")(?:%\S*)?")


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

        # FIX 7: valid_ip collapses ::ffff:10.0.0.5 -> 10.0.0.5 and returns the
        # normalized form; assign the result (not just test it).
        ip = valid_ip(ip)
        if not ip:
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
            meta=meta,
            sector=self.resolve_sector(meta),
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
        body = _body(line)
        if body is None:
            return (None, None, None, None, None, None)

        for rx, activity_id, status, severity in (
            (_ACCEPTED, 1, "Success", SEV_INFO),
            (_FAILED, 4, "Failure", SEV_HIGH),
            (_INVALID, 4, "Failure", SEV_HIGH),
        ):
            m = rx.match(body)
            if m:
                parts = _account_and_source(body[m.end():])
                if parts:
                    return (activity_id, status, severity, *parts)

        if _PAM_FAIL.match(body):
            um = _PAMUSER.search(body)
            # the server writes rhost= BEFORE user=; only the account can carry client text
            rm = _RHOST.search(body, 0, um.start() if um else len(body))
            user = body[um.end():].strip() if um else ""
            return (4, "Failure", SEV_HIGH, user or None,
                    rm.group("ip") if rm else None, None)

        m = _SESSION.match(body)
        if m and m.group("state") == "closed":
            user = _session_account(body[m.end():])
            if user:
                return (2, "Success", SEV_INFO, user, None, None)
        # "session opened" is a low-signal duplicate of Accepted -> skip.

        return (None, None, None, None, None, None)

    @staticmethod
    def _time_ms(meta: dict) -> int:
        # FIX 15: route through to_epoch_ms so FILETIME / epoch-seconds / ISO
        # strings all normalize the same way (the old `int(ra*1000) if ra<1e12`
        # one-liner mishandled FILETIME < 1e12 daylight and ISO strings).
        parsed = to_epoch_ms(meta.get("received_at"))
        return parsed if parsed is not None else int(time.time() * 1000)

    @staticmethod
    def _logged_time(meta: dict) -> Optional[int]:
        return to_epoch_ms(meta.get("received_at"))


def _body(line: str) -> Optional[str]:
    """The sshd MESSAGE: the text after the LEFTMOST ``sshd[pid]:`` tag (or starting at a
    bare ``pam_*(sshd:...)`` module tag), minus an optional Solaris ``[ID n fac.lvl]``
    decoration. The server writes the tag before any client-chosen text, so the leftmost
    match is the real one; everything the grammar matches is anchored to this start, so
    text inside a client-chosen account name is never read as a message kind."""
    m = _SSHD.search(line)
    if not m:
        return None
    body = line[m.start():] if m.group(0).startswith("pam_") else line[m.end():]
    body = body.lstrip()
    sid = _SOLARIS_ID.match(body)
    return body[sid.end():] if sid else body


def _account_and_source(rest: str):
    """``<account> from <ip>[%zone] [port N] ...`` -> (account, ip, port), or None.

    The real source is the RIGHTMOST IP-shaped ``from`` clause (the server writes it after
    the client-chosen account); non-IP words after it (``from feed``) are skipped. If that
    clause is IP-shaped but not a valid address (``999.999.999.999``), it still decides --
    parse() then drops the address -- so an earlier, forged, valid-looking clause can
    never take its place. Linear: one finditer pass, no backtracking on client text."""
    for c in reversed(list(_FROM.finditer(rest))):
        tok = c.group("ip")
        if not _IPSHAPE.search(tok):
            continue
        account = rest[:c.start()].strip()
        if not account:
            return None
        pm = _PORT.match(rest, c.end())
        return account, tok, _as_int(pm.group(1)) if pm else None
    return None


def _session_account(rest: str) -> str:
    """Account of a ``session closed for user <name>[(uid=N)] [by ...(uid=N)]`` line: cut a
    TRAILING ``by ...(uid=N)`` and ``(uid=N)`` with rfind (no lazy regex on client text)."""
    s = rest.strip()
    if s.endswith(")"):
        b = s.rfind(" by ")
        if b > 0 and "(uid=" in s[b:]:
            s = s[:b].rstrip()
    if s.endswith(")"):
        j = s.rfind("(uid=")
        if j > 0 and s[j + 5:-1].isdigit():
            s = s[:j].rstrip()
    return s


def _as_int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
