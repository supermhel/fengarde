"""Self-test for tools/check_dco.py against throwaway git repos.

Pins the PR #96 review findings: the old aggregate count let an unsigned
commit pass when another commit carried two sign-offs; a sign-off line in
the body (not a trailer) counted; a missing base sha was a green SKIP.

Run:  python tools/test_check_dco.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import check_dco as C  # noqa: E402

AUTHOR = "Ada Author"
EMAIL = "ada@example.org"


class TestCheckDco(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.repo = self._td.name
        self._git("init", "-q")
        self.base = self._commit("base")

    def tearDown(self):
        self._td.cleanup()

    def _git(self, *args):
        env = dict(os.environ, GIT_AUTHOR_NAME=AUTHOR, GIT_AUTHOR_EMAIL=EMAIL,
                   GIT_COMMITTER_NAME=AUTHOR, GIT_COMMITTER_EMAIL=EMAIL)
        return subprocess.run(["git", "-c", "commit.gpgsign=false", *args],
                              cwd=self.repo, env=env, check=True,
                              capture_output=True, text=True).stdout.strip()

    def _commit(self, msg):
        self._git("commit", "-q", "--allow-empty", "-m", msg)
        return self._git("rev-parse", "HEAD")

    def _check(self):
        return C.unsigned_commits(self.base, cwd=self.repo)

    def test_signed_by_author_passes(self):
        self._commit(f"feat: x\n\nSigned-off-by: {AUTHOR} <{EMAIL}>")
        self.assertEqual(self._check(), (1, []))

    def test_email_match_is_case_insensitive(self):
        self._commit(f"feat: x\n\nSigned-off-by: {AUTHOR} <{EMAIL.upper()}>")
        self.assertEqual(self._check()[1], [])

    def test_double_signoff_cannot_cover_an_unsigned_commit(self):
        self._commit(f"one\n\nSigned-off-by: {AUTHOR} <{EMAIL}>\n"
                     f"Signed-off-by: Bob <bob@example.org>")
        self._commit("two, unsigned")
        total, bad = self._check()
        self.assertEqual(total, 2)
        self.assertEqual(len(bad), 1)
        self.assertIn("two, unsigned", bad[0])

    def test_someone_elses_signoff_does_not_count(self):
        self._commit("x\n\nSigned-off-by: Bob <bob@example.org>")
        self.assertEqual(len(self._check()[1]), 1)

    def test_signoff_in_body_is_not_a_trailer(self):
        self._commit(f"x\n\nSigned-off-by: {AUTHOR} <{EMAIL}>\nand then more prose\n\n"
                     f"final paragraph without trailers")
        self.assertEqual(len(self._check()[1]), 1)

    def test_missing_base_fails_closed(self):
        import contextlib
        import io
        cwd = os.getcwd()
        os.chdir(self.repo)
        try:
            # expected [FAIL] output swallowed so the gate log stays clean
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(C.main(["check_dco.py", "0" * 40]), 1)
                self.assertEqual(C.main(["check_dco.py"]), 1)
        finally:
            os.chdir(cwd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
