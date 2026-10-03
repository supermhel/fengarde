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


if __name__ == "__main__":
    unittest.main(verbosity=1)
