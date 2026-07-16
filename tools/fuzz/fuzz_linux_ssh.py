"""atheris fuzz harness: services/ws2-normalization/parsers/linux_ssh.py.

Run:  python tools/fuzz/fuzz_linux_ssh.py -atheris_runs=200000
      python tools/fuzz/fuzz_linux_ssh.py -max_total_time=600   # nightly CI (10 min)
Corpus (optional, speeds convergence): pass a directory as the last arg.
"""
from __future__ import annotations

from _common import run
from parsers.linux_ssh import LinuxSshParser

if __name__ == "__main__":
    run(LinuxSshParser(), "linux_ssh")
