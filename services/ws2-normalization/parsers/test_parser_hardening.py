"""P0.5-7 parser hardening regression tests.

  P0.5 - vmware must not crash parse() on a hostile ``port``; main.normalize_one
         must dead-letter a raising parser instead of aborting the batch.
  P0.6 - an out-of-range IP octet in an sshd/ASA line must not dead-letter the
         event; the address is dropped, the event still validates.
  P0.7 - status is derived from the record's real outcome; a failed login/op is
         "Failure", not a hardcoded "Success" (which would suppress detection).

Run: C:/Python313/python.exe services/ws2-normalization/parsers/test_parser_hardening.py
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent.parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(SERVICES))

from shared.ocsf import validate  # noqa: E402
from parsers.vmware_vsphere import VmwareVsphereParser  # noqa: E402
from parsers.db_audit import DbAuditParser  # noqa: E402
from parsers.n8n_audit import N8nAuditParser  # noqa: E402
from parsers.mcp_agent import McpAgentParser  # noqa: E402
from parsers.opcua_audit import OpcUaAuditParser  # noqa: E402
from parsers.linux_ssh import LinuxSshParser  # noqa: E402
from parsers.cisco_asa import CiscoAsaParser  # noqa: E402
from parsers.base import status_from_outcome  # noqa: E402


def _raw(rec, st="x", meta=None):
    return {"source_type": st, "raw": rec, "meta": meta or {}}


class TestPortGuard(unittest.TestCase):
    def test_vmware_hostile_port_does_not_crash(self):
        p = VmwareVsphereParser()
        for bad in ("nope", [], {}, None, "80x"):
            rec = {"operation": "VM.Delete", "vm": "v1", "ipAddress": "10.0.0.1",
                   "userName": "u", "port": bad}
            ev = p.parse(_raw(rec))  # must not raise
            self.assertIsNotNone(ev)
            self.assertEqual(validate(ev), [], f"port={bad!r} produced invalid event")

    def test_vmware_valid_port_kept(self):
        ev = VmwareVsphereParser().parse(_raw(
            {"operation": "VM.Delete", "vm": "v", "ipAddress": "10.0.0.1", "port": "443"}))
        self.assertEqual(ev["src_endpoint"]["port"], 443)

    def test_batch_survives_raising_parser(self):
        # a parser that raises must dead-letter one record, not abort normalize_one
        import main  # ws2 entrypoint (added to path via SERVICES/HERE)
        sys.path.insert(0, str(HERE.parent))

        class _Boom:
            def parse(self, raw):
                raise RuntimeError("kaboom")

        orig = main.resolve
        try:
            main.resolve = lambda payload: _Boom()  # type: ignore[return-value]  # deliberately not a real Parser
            event, errors = main.normalize_one({"source_type": "x", "raw": {}})
            self.assertIsNone(event)
            self.assertTrue(errors and "raised" in errors[0])
        finally:
            main.resolve = orig


class TestIpOctetBounds(unittest.TestCase):
    def test_ssh_out_of_range_ip_still_parses(self):
        line = "Nov 1 10:00:00 h sshd[7]: Failed password for admin from 999.999.999.999 port 5"
        ev = LinuxSshParser().parse(_raw(line, st="linux_ssh"))
        self.assertIsNotNone(ev, "line must still parse (not dead-letter)")
        self.assertEqual(validate(ev), [])
        # the bogus address must NOT be recorded as a source IP
        self.assertNotIn("src_endpoint", ev)

    def test_ssh_valid_ip_captured(self):
        line = "Nov 1 10:00:00 h sshd[7]: Failed password for admin from 203.0.113.5 port 5"
        ev = LinuxSshParser().parse(_raw(line, st="linux_ssh"))
        self.assertEqual(ev["src_endpoint"]["ip"], "203.0.113.5")

    def test_asa_out_of_range_ip_dropped(self):
        line = "%ASA-4-106023: deny tcp src outside:300.1.1.1/55 dst inside:10.0.0.1/80"
        ev = CiscoAsaParser().parse(_raw(line, st="cisco_asa"))
        self.assertIsNotNone(ev)
        self.assertEqual(validate(ev), [])
        # 300.1.1.1 is invalid -> not used as src; 10.0.0.1 is valid -> dst kept
        self.assertNotEqual((ev.get("src_endpoint") or {}).get("ip"), "300.1.1.1")
        self.assertEqual(ev["dst_endpoint"]["ip"], "10.0.0.1")


class TestStatusFromOutcome(unittest.TestCase):
    def test_helper_tokens(self):
        self.assertEqual(status_from_outcome({"status": "succeeded"}), "Success")
        self.assertEqual(status_from_outcome({"status": "false"}), "Failure")
        self.assertEqual(status_from_outcome({"status": False}), "Failure")
        self.assertEqual(status_from_outcome({"result": 403}), "Failure")
        self.assertEqual(status_from_outcome({}), "Success")  # default, no fabrication
        self.assertEqual(status_from_outcome({"outcome": "denied"}), "Failure")

    def test_blocked_and_dropped_are_failures(self):
        """Regression for M1: a blocked/dropped auth attempt must not fall
        through to the "Success" default -- that suppresses the very
        brute-force rules watching for it."""
        self.assertEqual(status_from_outcome({"outcome": "blocked"}), "Failure")
        self.assertEqual(status_from_outcome({"outcome": "BLOCKED"}), "Failure")
        self.assertEqual(status_from_outcome({"act": "drop"}, keys=("act",)), "Failure")
        self.assertEqual(status_from_outcome({"act": "dropped"}, keys=("act",)), "Failure")

    def test_n8n_failed_login_is_failure(self):
        ev = N8nAuditParser().parse(_raw(
            {"eventType": "user.login", "user": "attacker", "status": "failed"}))
        self.assertEqual(ev["status"], "Failure")

    def test_n8n_successful_login_is_success(self):
        ev = N8nAuditParser().parse(_raw({"eventType": "user.login", "user": "alice"}))
        self.assertEqual(ev["status"], "Success")

    def test_mcp_succeeded_token_is_success(self):
        ev = McpAgentParser().parse(_raw(
            {"tool": "read_file", "arguments": {}, "outcome": "succeeded"}))
        self.assertEqual(ev["status"], "Success")

    def test_db_failed_grant_is_failure(self):
        ev = DbAuditParser().parse(_raw(
            {"operation": "GRANT", "object": "t", "user": "u", "status": "denied"}))
        self.assertEqual(ev["status"], "Failure")

    def test_opcua_false_string_is_failure(self):
        ev = OpcUaAuditParser().parse(_raw(
            {"eventType": "AuditActivateSessionEventType", "clientUserId": "x",
             "status": "false"}))
        self.assertEqual(ev["status"], "Failure")


class TestParserTail(unittest.TestCase):
    """P2.5: IPv6 capture + full ASA severity map."""

    def test_ssh_ipv6_source_captured(self):
        line = "Nov 1 10:00:00 h sshd[7]: Failed password for admin from 2001:db8::1 port 5"
        ev = LinuxSshParser().parse(_raw(line, st="linux_ssh"))
        self.assertEqual(validate(ev), [])
        self.assertEqual(ev["src_endpoint"]["ip"], "2001:db8::1")

    def test_ssh_ipv4_still_captured(self):
        line = "Nov 1 10:00:00 h sshd[7]: Failed password for admin from 203.0.113.5 port 5"
        ev = LinuxSshParser().parse(_raw(line, st="linux_ssh"))
        self.assertEqual(ev["src_endpoint"]["ip"], "203.0.113.5")

    def test_ssh_garbage_ip_still_dropped(self):
        # not a valid v4 or v6 -> dropped, event still valid
        line = "Nov 1 10:00:00 h sshd[7]: Failed password for admin from 999.999.999.999 port 5"
        ev = LinuxSshParser().parse(_raw(line, st="linux_ssh"))
        self.assertEqual(validate(ev), [])
        self.assertNotIn("src_endpoint", ev)

    def test_asa_severity_full_range(self):
        from parsers.base import (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM,
                                  SEV_LOW, SEV_INFO)
        cases = {0: SEV_CRITICAL, 1: SEV_CRITICAL, 2: SEV_CRITICAL, 3: SEV_HIGH,
                 4: SEV_MEDIUM, 5: SEV_LOW, 6: SEV_INFO, 7: SEV_INFO}
        for sev, expected in cases.items():
            line = f"%ASA-{sev}-106023: deny tcp src outside:10.0.0.9/55 dst inside:10.0.0.1/80"
            ev = CiscoAsaParser().parse(_raw(line, st="cisco_asa"))
            self.assertEqual(ev["severity_id"], expected,
                             f"ASA sev {sev} -> {expected}, got {ev['severity_id']}")


def _ssh(body: str):
    return LinuxSshParser().parse(_raw(f"Nov  1 10:00:00 h sshd[7]: {body}", st="linux_ssh"))


def _facts(ev):
    """(activity_id, status, source ip, source port, account) -- what attribution is made of."""
    sep = ev.get("src_endpoint") or {}
    return (ev["activity_id"], ev["status"], sep.get("ip"), sep.get("port"),
            ((ev.get("actor") or {}).get("user") or {}).get("name"))


class TestSshdAttributionForgery(unittest.TestCase):
    """F3 (2026-10-02, adaptive-evasion lane): the sshd grammar took the FIRST
    ``from <ip>`` / the first ``Accepted ...`` anywhere in the line, so an
    attacker-chosen USERNAME could move src_endpoint.ip or flip the activity.
    The real fields are the ones at the END of the line (the server writes
    ``from <peer> port <n>`` after the name it echoes), and the message kind is the
    START of the body. Positive controls are the forged shapes; negative controls
    are the legitimate shapes that must keep their exact attribution."""

    REAL = "203.0.113.5"

    def test_username_carrying_a_fake_from_clause_does_not_move_the_source(self):
        forged_user = "x from 198.18.9.9 port 1 ssh2 Failed password for deploy"
        ev = _ssh(f"Failed password for invalid user {forged_user} from {self.REAL} port 51000 ssh2")
        self.assertEqual(validate(ev), [])
        self.assertEqual(_facts(ev), (4, "Failure", self.REAL, 51000, forged_user))

    def test_forged_clause_in_a_valid_user_line(self):
        forged_user = "root from 198.18.9.9 port 1 ssh2"
        ev = _ssh(f"Failed password for {forged_user} from {self.REAL} port 51000 ssh2")
        self.assertEqual(_facts(ev), (4, "Failure", self.REAL, 51000, forged_user))

    def test_username_cannot_flip_an_invalid_user_line_into_a_logon(self):
        forged_user = "Accepted password for root from 198.18.9.9 port 1 ssh2"
        ev = _ssh(f"Invalid user {forged_user} from {self.REAL} port 51000")
        self.assertEqual(_facts(ev), (4, "Failure", self.REAL, 51000, forged_user))

    def test_username_cannot_flip_a_failure_into_a_logon(self):
        forged_user = "Accepted publickey for deploy from 198.18.9.9 port 1 ssh2"
        ev = _ssh(f"Failed password for invalid user {forged_user} from {self.REAL} port 51000 ssh2")
        self.assertEqual(ev["activity_id"], 4)
        self.assertEqual(ev["status"], "Failure")
        self.assertEqual(ev["src_endpoint"]["ip"], self.REAL)

    def test_unmodelled_line_quoting_pam_text_is_not_parsed_as_an_auth_failure(self):
        # not an auth line: the attacker-chosen name quotes PAM text with a forged rhost/user
        ev = _ssh("Connection closed by invalid user authentication failure rhost=198.18.9.9 "
                  f"user=root {self.REAL} port 51000 [preauth]")
        self.assertIsNone(ev)

    def test_unmodelled_line_quoting_session_closed_is_not_a_logoff(self):
        ev = _ssh("Disconnected from user x pam_unix(sshd:session): session closed for user root")
        self.assertIsNone(ev)

    def test_pam_remote_user_does_not_become_the_account(self):
        ev = _ssh("pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh "
                  f"ruser=bob rhost={self.REAL}  user=admin")
        self.assertEqual(_facts(ev), (4, "Failure", self.REAL, None, "admin"))

    # ---- legitimate shapes keep their exact attribution (negative controls) -----------

    def test_legitimate_samples_are_unchanged(self):
        cases = {
            "Failed password for invalid user admin from 203.0.113.5 port 51000 ssh2":
                (4, "Failure", "203.0.113.5", 51000, "admin"),
            "Failed password for jdoe from 203.0.113.5 port 51514 ssh2":
                (4, "Failure", "203.0.113.5", 51514, "jdoe"),
            "Failed password for root from 203.0.113.5":
                (4, "Failure", "203.0.113.5", None, "root"),
            "Failed password for admin from 203.0.113.5 port 5":
                (4, "Failure", "203.0.113.5", 5, "admin"),
            "Invalid user admin from 203.0.113.5 port 51000":
                (4, "Failure", "203.0.113.5", 51000, "admin"),
            "Accepted password for jdoe from 10.0.0.5 port 50022 ssh2":
                (1, "Success", "10.0.0.5", 50022, "jdoe"),
            "Accepted publickey for deploy from 10.0.0.6 port 50022 ssh2":
                (1, "Success", "10.0.0.6", 50022, "deploy"),
            "Accepted publickey for deploy from 10.0.0.6 port 50022 ssh2: RSA SHA256:abcDEF/123":
                (1, "Success", "10.0.0.6", 50022, "deploy"),
            "pam_unix(sshd:session): session closed for user jdoe":
                (2, "Success", None, None, "jdoe"),
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= "
            "rhost=203.0.113.5  user=admin":
                (4, "Failure", "203.0.113.5", None, "admin"),
            "PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= "
            "rhost=203.0.113.5  user=root":
                (4, "Failure", "203.0.113.5", None, "root"),
        }
        for body, want in cases.items():
            with self.subTest(body=body):
                ev = _ssh(body)
                self.assertIsNotNone(ev)
                self.assertEqual(validate(ev), [])
                self.assertEqual(_facts(ev), want)

    def test_ipv6_sources_are_still_captured(self):
        for body, want in (
            ("Failed password for invalid user admin from 2001:db8::1 port 5 ssh2",
             (4, "Failure", "2001:db8::1", 5, "admin")),
            ("Accepted publickey for deploy from 2001:db8::6 port 50022 ssh2",
             (1, "Success", "2001:db8::6", 50022, "deploy")),
            ("Failed password for root from ::ffff:10.0.0.5 port 22 ssh2",
             (4, "Failure", "10.0.0.5", 22, "root")),
        ):
            with self.subTest(body=body):
                self.assertEqual(_facts(_ssh(body)), want)

    def test_usernames_with_spaces_are_kept_whole(self):
        ev = _ssh(f"Failed password for invalid user john smith from {self.REAL} port 51000 ssh2")
        self.assertEqual(_facts(ev), (4, "Failure", self.REAL, 51000, "john smith"))
        ev = _ssh(f"Invalid user domain admin from {self.REAL} port 51000")
        self.assertEqual(_facts(ev), (4, "Failure", self.REAL, 51000, "domain admin"))

    def test_unmodelled_sshd_lines_stay_unmodelled(self):
        for body in (f"Connection closed by {self.REAL} port 51000 [preauth]",
                     "Server listening on 0.0.0.0 port 22.",
                     "pam_unix(sshd:session): session opened for user jdoe(uid=1000) by (uid=0)"):
            with self.subTest(body=body):
                self.assertIsNone(_ssh(body))

    def test_garbage_real_address_is_still_dropped_not_replaced_by_forged_text(self):
        ev = _ssh("Failed password for x from 198.18.9.9 port 1 ssh2 Failed password for admin "
                  "from 999.999.999.999 port 5")
        self.assertEqual(validate(ev), [])
        self.assertNotIn("src_endpoint", ev)


# ---- F3 follow-up (ssh-differential review): the grammar is PINNED here ----------------
# The reviewer found 10 of 19 semantic mutants of linux_ssh.py surviving every parser
# suite. Everything below is literal expected output, so a mutant that changes any
# kind / source / port / account for any of these lines dies.

REAL = "203.0.113.5"
# every spelling of the real sshd tag (OpenSSH 9.8+ splits sshd into sshd-session / sshd-auth)
TAGS = ("sshd[7]", "sshd-session[7]", "sshd-auth[7]", "sshd")


def _line(tag: str, body: str) -> str:
    return f"Nov  1 10:00:00 h {tag}: {body}"


def _parse(line: str):
    return LinuxSshParser().parse(_raw(line, st="linux_ssh"))


_PAM_PFX = "logname= uid=0 euid=0 tty=ssh ruser= "

# (message body, (activity_id, status, ip, port, account)); None = deliberately unmodelled.
# Each row was ALSO checked against the e18e3f2 parser (the last one before the F3
# anchoring) -- the facts are identical there, except where the comment says otherwise.
LEGIT_CORPUS = (
    ("Failed password for invalid user admin from 203.0.113.5 port 51000 ssh2",
     (4, "Failure", "203.0.113.5", 51000, "admin")),
    ("Failed password for jdoe from 203.0.113.5 port 51514 ssh2",
     (4, "Failure", "203.0.113.5", 51514, "jdoe")),
    ("Failed password for root from 203.0.113.5",
     (4, "Failure", "203.0.113.5", None, "root")),
    ("Failed publickey for deploy from 10.0.0.6 port 22 ssh2",
     (4, "Failure", "10.0.0.6", 22, "deploy")),
    ("Failed keyboard-interactive/pam for invalid user guest from 10.0.0.7 port 40000 ssh2",
     (4, "Failure", "10.0.0.7", 40000, "guest")),
    ("Failed password for root from 203.0.113.5 port 51000 ssh2 [preauth]",
     (4, "Failure", "203.0.113.5", 51000, "root")),
    ("Accepted password for jdoe from 10.0.0.5 port 50022 ssh2",
     (1, "Success", "10.0.0.5", 50022, "jdoe")),
    ("Accepted publickey for deploy from 10.0.0.6 port 50022 ssh2: RSA SHA256:abcDEF/123",
     (1, "Success", "10.0.0.6", 50022, "deploy")),
    ("Accepted keyboard-interactive/pam for root from 10.0.0.8 port 1 ssh2",
     (1, "Success", "10.0.0.8", 1, "root")),
    ("Accepted publickey for ops from 10.0.0.9 port 22 ssh2: RSA-CERT SHA256:aaa ID ops-cert (serial 0) CA RSA SHA256:bbb",
     (1, "Success", "10.0.0.9", 22, "ops")),
    ("Invalid user admin from 203.0.113.5 port 51000",
     (4, "Failure", "203.0.113.5", 51000, "admin")),
    ("Invalid user admin from 203.0.113.5",
     (4, "Failure", "203.0.113.5", None, "admin")),
    # accounts with spaces / unicode are kept whole (e18e3f2 took only the first word: intended difference)
    ("Failed password for invalid user john smith from 203.0.113.5 port 51000 ssh2",
     (4, "Failure", "203.0.113.5", 51000, "john smith")),
    ("Invalid user Müller 张伟 from 203.0.113.5 port 51000",
     (4, "Failure", "203.0.113.5", 51000, "Müller 张伟")),
    ("Accepted password for domain admin from 10.0.0.5 port 50022 ssh2",
     (1, "Success", "10.0.0.5", 50022, "domain admin")),
    # IPv6, canonicalised by valid_ip; v4-mapped collapses to the dotted quad
    ("Failed password for invalid user admin from 2001:db8::1 port 5 ssh2",
     (4, "Failure", "2001:db8::1", 5, "admin")),
    ("Accepted publickey for deploy from 2001:DB8::6 port 50022 ssh2",
     (1, "Success", "2001:db8::6", 50022, "deploy")),
    ("Failed password for root from ::ffff:10.0.0.5 port 22 ssh2",
     (4, "Failure", "10.0.0.5", 22, "root")),
    # IPv6 zone id: kept OUT of the stored ip (e18e3f2 matched the address but lost the
    # port behind the '%eth0'; the port is now parsed after the zone: intended difference)
    ("Failed password for root from fe80::a00:27ff:fe4a:b1c2%eth0 port 51000 ssh2",
     (4, "Failure", "fe80::a00:27ff:fe4a:b1c2", 51000, "root")),
    ("Invalid user bob from fe80::1%en0",
     (4, "Failure", "fe80::1", None, "bob")),
    # Solaris / illumos decoration between the tag and the message
    ("[ID 800047 auth.info] Failed password for root from 203.0.113.5 port 51000 ssh2",
     (4, "Failure", "203.0.113.5", 51000, "root")),
    ("[ID 800047 auth.info] Accepted password for jdoe from 10.0.0.5 port 50022 ssh2",
     (1, "Success", "10.0.0.5", 50022, "jdoe")),
    # PAM: any module, rhost before user=
    ("pam_unix(sshd:auth): authentication failure; " + _PAM_PFX + "rhost=203.0.113.5  user=admin",
     (4, "Failure", "203.0.113.5", None, "admin")),
    ("pam_sss(sshd:auth): authentication failure; " + _PAM_PFX + "rhost=203.0.113.5 user=bob",
     (4, "Failure", "203.0.113.5", None, "bob")),
    ("pam_ldap(sshd:auth): authentication failure; " + _PAM_PFX + "rhost=2001:db8::5 user=carol",
     (4, "Failure", "2001:db8::5", None, "carol")),
    ("PAM 2 more authentication failures; " + _PAM_PFX + "rhost=203.0.113.5  user=root",
     (4, "Failure", "203.0.113.5", None, "root")),
    ("PAM 1 more authentication failure; " + _PAM_PFX + "rhost=203.0.113.5  user=root",
     (4, "Failure", "203.0.113.5", None, "root")),
    ("pam_unix(sshd:auth): authentication failure; " + _PAM_PFX + "rhost=203.0.113.5  user=john smith",
     (4, "Failure", "203.0.113.5", None, "john smith")),
    ("pam_unix(sshd:auth): authentication failure; " + _PAM_PFX + "rhost=203.0.113.5",
     (4, "Failure", "203.0.113.5", None, None)),
    ("pam_unix(sshd:auth): authentication failure; " + _PAM_PFX + "rhost=  user=bob",
     (4, "Failure", None, None, "bob")),
    ("pam_unix(sshd:auth): authentication failure; " + _PAM_PFX + "rhost=fe80::1%eth0  user=bob",
     (4, "Failure", "fe80::1", None, "bob")),
    # "ruser=" is not "user="
    ("pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser=eve "
     "rhost=203.0.113.5  user=admin",
     (4, "Failure", "203.0.113.5", None, "admin")),
    # sessions: only "closed" is a Logoff; "opened" is a duplicate of Accepted and is skipped
    ("pam_unix(sshd:session): session closed for user jdoe",
     (2, "Success", None, None, "jdoe")),
    ("pam_systemd(sshd:session): session closed for user john smith",
     (2, "Success", None, None, "john smith")),
    ("pam_unix(sshd:session): session closed for user jdoe(uid=1000)",
     (2, "Success", None, None, "jdoe")),
    ("pam_unix(sshd:session): session opened for user jdoe(uid=1000) by (uid=0)", None),
    # not modelled
    ("Connection closed by 203.0.113.5 port 51000 [preauth]", None),
    ("Server listening on 0.0.0.0 port 22.", None),
    ("Received disconnect from 203.0.113.5 port 51000:11: Bye Bye [preauth]", None),
    # a real address that is garbage is dropped, the event survives (P0.6)
    ("Failed password for admin from 999.999.999.999 port 5", (4, "Failure", None, None, "admin")),
)

# Attacker-chosen account names: every one tries to move the kind, the source or the account.
HOSTILE_NAMES = (
    "x sshd: Accepted password for root from 198.18.9.9 port 1 ssh2",
    "x sshd[1]: Accepted password for root from 198.18.9.9 port 1 ssh2",
    "x sshd-session[1]: Accepted password for root from 198.18.9.9 port 1 ssh2",
    "pam_unix(sshd:session): session closed for user root",
    "pam_sss(sshd:auth): authentication failure; rhost=198.18.9.9 user=root",
    "x from 198.18.9.9 port 1 ssh2",
    "x from 198.18.9.9",
    "Accepted publickey for root from 198.18.9.9 port 1 ssh2",
    "Failed password for root from 198.18.9.9 port 1 ssh2",
    "x from fe80::1%eth0 port 1 ssh2",
    "x from ::ffff:198.18.9.9 port 1",
    "from from from",
    "x user=root rhost=198.18.9.9",
)


class TestSshGrammarPinned(unittest.TestCase):
    def test_legit_corpus_under_every_real_tag(self):
        for tag in TAGS:
            for body, want in LEGIT_CORPUS:
                with self.subTest(tag=tag, body=body):
                    ev = _parse(_line(tag, body))
                    if want is None:
                        self.assertIsNone(ev)
                        continue
                    self.assertIsNotNone(ev)
                    self.assertEqual(validate(ev), [])
                    self.assertEqual(_facts(ev), want)

    def test_bare_pam_tag_and_rfc5424_header(self):
        # no sshd[pid]: tag at all: the pam_<module>(sshd:...) tag is the anchor (any module)
        for mod in ("pam_unix", "pam_sss", "pam_ldap"):
            line = (f"{mod}(sshd:auth): authentication failure; {_PAM_PFX}rhost={REAL} user=bob")
            self.assertEqual(_facts(_parse(line)), (4, "Failure", REAL, None, "bob"), mod)
        rfc5424 = ("<38>1 2026-10-01T10:00:00.000000+00:00 h sshd 2154 - - "
                   f"pam_sss(sshd:auth): authentication failure; {_PAM_PFX}rhost={REAL} user=bob")
        self.assertEqual(_facts(_parse(rfc5424)), (4, "Failure", REAL, None, "bob"))
        self.assertEqual(_facts(_parse("pam_systemd(sshd:session): session closed for user bob")),
                         (2, "Success", None, None, "bob"))

    def test_account_whitespace_is_stripped_not_attributed(self):
        # strip() only removes the separators; the account text itself is untouched
        ev = _ssh(f"Failed password for   padded   from {REAL} port 5 ssh2")
        self.assertEqual(_facts(ev), (4, "Failure", REAL, 5, "padded"))
        ev = _ssh(f"pam_unix(sshd:auth): authentication failure; {_PAM_PFX}rhost={REAL}  user=   spaced  ")
        self.assertEqual(_facts(ev), (4, "Failure", REAL, None, "spaced"))

    def test_hostile_account_names_cannot_change_kind_source_or_account(self):
        for tag in TAGS:
            for name in HOSTILE_NAMES:
                templates = (
                    (f"Failed password for invalid user {name} from {REAL} port 51000 ssh2",
                     (4, "Failure", REAL, 51000, name)),
                    (f"Failed password for {name} from {REAL} port 51000 ssh2",
                     (4, "Failure", REAL, 51000, name)),
                    (f"Invalid user {name} from {REAL} port 51000",
                     (4, "Failure", REAL, 51000, name)),
                    (f"Accepted password for {name} from {REAL} port 51000 ssh2",
                     (1, "Success", REAL, 51000, name)),
                    (f"pam_unix(sshd:auth): authentication failure; {_PAM_PFX}rhost={REAL}  user={name}",
                     (4, "Failure", REAL, None, name)),
                    (f"pam_unix(sshd:session): session closed for user {name}",
                     (2, "Success", None, None, name)),
                )
                for body, want in templates:
                    with self.subTest(tag=tag, body=body):
                        ev = _parse(_line(tag, body))
                        self.assertIsNotNone(ev)
                        self.assertEqual(validate(ev), [])
                        self.assertEqual(_facts(ev), want)

    def test_non_ip_words_in_the_server_tail_are_harmless(self):
        # 'from feed' after the real clause used to become the "source" and swallow the account
        for tail in (" [preauth] from feed", " ssh2: ID cafe from beef", " from a.b", " from dead"):
            ev = _ssh(f"Failed password for root from {REAL} port 51000 ssh2{tail}")
            self.assertEqual(_facts(ev), (4, "Failure", REAL, 51000, "root"), tail)

    def test_the_rightmost_ip_shaped_clause_is_the_source(self):
        # a garbage REAL address is dropped, not replaced by an earlier (forged) valid one
        ev = _ssh("Failed password for x from 198.18.9.9 port 1 ssh2 Failed password for admin "
                  "from 999.999.999.999 port 5")
        self.assertEqual(validate(ev), [])
        self.assertEqual(_facts(ev), (4, "Failure", None, None,
                                      "x from 198.18.9.9 port 1 ssh2 Failed password for admin"))

    def test_first_user_and_first_rhost_win_in_pam_failures(self):
        # the server writes rhost= BEFORE the (last, client-chosen) user= field
        ev = _ssh(f"pam_unix(sshd:auth): authentication failure; {_PAM_PFX}rhost={REAL}  "
                  "user=a user=b rhost=198.18.9.9")
        self.assertEqual(_facts(ev), (4, "Failure", REAL, None, "a user=b rhost=198.18.9.9"))
        # no user= at all: the first rhost= is the server's
        ev = _ssh(f"PAM 3 more authentication failures; {_PAM_PFX}rhost={REAL}  rhost=198.18.9.9")
        self.assertEqual(_facts(ev), (4, "Failure", REAL, None, None))
        # rhost= only counts as a whole field: 'xrhost=' inside another field is not it ...
        ev = _ssh(f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh "
                  f"ruser=xrhost=198.18.9.9 rhost={REAL}  user=a")
        self.assertEqual(_facts(ev), (4, "Failure", REAL, None, "a"))
        # ... and an rhost= that only occurs AFTER user= (client text) is never the source
        ev = _ssh(f"pam_unix(sshd:auth): authentication failure; {_PAM_PFX}user=bob rhost=198.18.9.9")
        self.assertEqual(_facts(ev), (4, "Failure", None, None, "bob rhost=198.18.9.9"))

    def test_session_account_cuts_only_the_servers_trailing_fields(self):
        for tail, want in (("jdoe", "jdoe"), ("jdoe(uid=1000)", "jdoe"), ("jdoe by (uid=0)", "jdoe"),
                           ("jdoe(uid=1000) by (uid=0)", "jdoe"), ("jdoe(uid=1000) by root(uid=0)", "jdoe"),
                           ("a by b", "a by b"), ("x(uid=1)y", "x(uid=1)y"), ("x(uid=)", "x(uid=)")):
            with self.subTest(tail=tail):
                ev = _ssh(f"pam_unix(sshd:session): session closed for user {tail}")
                self.assertEqual(_facts(ev), (2, "Success", None, None, want))

    def test_a_session_or_failure_line_without_an_account_is_not_a_logoff(self):
        self.assertIsNone(_ssh("pam_unix(sshd:session): session closed for user "))
        self.assertIsNone(_ssh("pam_unix(sshd:session): session closed for user"))
        self.assertIsNone(_ssh("Failed password for from 203.0.113.5 port 5 ssh2"))
        self.assertIsNone(_ssh("Invalid user from 203.0.113.5"))

    def test_message_kind_must_start_the_body(self):
        for body in ("Connection closed Accepted password for root from 198.18.9.9 port 1 ssh2",
                     "xx Failed password for root from 198.18.9.9 port 1 ssh2",
                     "Disconnected Invalid user root from 198.18.9.9 port 1",
                     "info: pam_unix(sshd:auth): authentication failure; rhost=198.18.9.9 user=root",
                     "Closed: PAM 2 more authentication failures; rhost=198.18.9.9 user=root",
                     "x pam_unix(sshd:session): session closed for user root"):
            for tag in TAGS:
                with self.subTest(tag=tag, body=body):
                    self.assertIsNone(_parse(_line(tag, body)))

    def test_leftmost_tag_is_the_real_one(self):
        # the server-written tag precedes client text, so text AFTER it can never re-anchor the body
        ev = _parse(_line("sshd-session[9]", "Failed password for invalid user x sshd: Accepted password "
                          f"for root from 198.18.9.9 port 1 ssh2 from {REAL} port 51000 ssh2"))
        self.assertEqual(_facts(ev), (4, "Failure", REAL, 51000,
                                      "x sshd: Accepted password for root from 198.18.9.9 port 1 ssh2"))
        ev = _parse(_line("sshd-session[9]", "Failed password for invalid user pam_unix(sshd:session): "
                          f"session closed for user root from {REAL} port 51000 ssh2"))
        self.assertEqual(_facts(ev), (4, "Failure", REAL, 51000,
                                      "pam_unix(sshd:session): session closed for user root"))

    def test_events_from_hostile_lines_still_validate(self):
        for name in ("a" * 300, "a\tb", "a‮b", "a\rb", "x\x00y", "line1\nAccepted password for root "
                     "from 198.18.9.9 port 1 ssh2"):
            ev = _ssh(f"Failed password for invalid user {name} from {REAL} port 51000 ssh2")
            self.assertIsNotNone(ev, repr(name))
            self.assertEqual(validate(ev), [], repr(name))
            self.assertEqual(_facts(ev)[:4], (4, "Failure", REAL, 51000), repr(name))


class TestSshNoBacktracking(unittest.TestCase):
    """ReDoS: the F3 regexes (``.+`` / ``.*?`` followed by ``\\s*\\Z``) backtracked quadratically or
    cubically on whitespace runs -- 26-40 s for one 64 KB line, > 60 s for the cubic shapes.
    The grammar is now linear scanning. THIS is the one wall-clock assertion in the suite: the bound
    is deliberately generous (2 s for 64 KB; a linear parse takes milliseconds) so it cannot flake,
    but it still separates linear from super-linear by orders of magnitude."""

    BOUND_S = 2.0

    @staticmethod
    def _shapes(n: int):
        sp = " " * n
        ip = "203.0.113.5"
        pam = f"pam_unix(sshd:auth): authentication failure; {_PAM_PFX}rhost={ip}  "
        return {
            "pam user= + spaces + non-space": pam + "user=x" + sp + "!",
            "pam user= + spaces only": pam + "user=" + sp,
            "pam no user= + spaces": pam + sp + "!",
            "pam user= repeated": pam + "user=" * (n // 5),
            "failed for + spaces + x": "Failed password for" + sp + "x",
            "failed for invalid user + spaces + x": "Failed password for invalid user" + sp + "x",
            "failed + spaces + non-space + from x": "Failed password for x" + sp + "!" + " from x",
            "failed name + from + spaces + x": f"Failed password for x from{sp}x",
            "failed many from words": "Failed password for x" + " from" * (n // 5),
            "failed many from f": "Failed password for x" + " from f" * (n // 7),
            "failed hex token": "Failed password for x from " + "f" * n,
            "failed zone": "Failed password for x from fe80::1%" + "z" * n,
            "accepted + spaces + x": "Accepted password for" + sp + "x",
            "accepted name spaces then from": "Accepted password for x" + sp + "!" + " from " + ip,
            "invalid user + spaces + x": "Invalid user" + sp + "x",
            "invalid tabs": "Invalid user x" + "\t" * n + "!",
            "session closed + spaces + !": "pam_unix(sshd:session): session closed for user x" + sp + "!",
            "session closed + uid + spaces": "pam_unix(sshd:session): session closed for user x(uid=1" + sp,
            "session by repeated": "pam_unix(sshd:session): session closed for user x" + " by (uid=0)" * (n // 11),
            "solaris id + spaces": "[ID" + sp + "x",
            "pam_ tag repeats": "pam_" * (n // 4),
            "sshd- tag repeats": "sshd-" * (n // 5),
            "sshd[ tag repeats": "sshd[1" * (n // 6),
        }

    def _run(self, n: int):
        import time
        for name, body in self._shapes(n).items():
            for tag in ("sshd[7]", "sshd-session[7]"):
                line = _line(tag, body)
                t0 = time.perf_counter()
                ev = _parse(line)  # must not raise
                took = time.perf_counter() - t0
                self.assertLess(took, self.BOUND_S, f"{name!r} under {tag}: {took:.2f}s for {len(line)} chars")
                if ev is not None:
                    self.assertEqual(validate(ev), [], name)

    def test_8kb_lines(self):
        self._run(8 * 1024)

    def test_64kb_lines(self):
        self._run(64 * 1024)


if __name__ == "__main__":
    unittest.main(verbosity=1)
