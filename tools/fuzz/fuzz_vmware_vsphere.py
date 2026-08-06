"""atheris fuzz harness: services/ws2-normalization/parsers/vmware_vsphere.py.

Added in the L8 (2026-08-06) fuzz-matrix expansion. vmware_vsphere is a
high-value API text parser (VM operation classification, FIX-12/FIX-11-adjacent)
worth byte-level coverage. Mirrors fuzz_linux_ssh.py's harness.

Run:  python tools/fuzz/fuzz_vmware_vsphere.py -atheris_runs=200000
      python tools/fuzz/fuzz_vmware_vsphere.py -max_total_time=600   # nightly CI (10 min)
Corpus (optional, speeds convergence): pass a directory as the last arg.
"""
from __future__ import annotations

from _common import run
from parsers.vmware_vsphere import VmwareVsphereParser

if __name__ == "__main__":
    run(VmwareVsphereParser(), "vmware_vsphere")
