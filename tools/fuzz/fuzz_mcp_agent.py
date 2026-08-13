"""atheris fuzz harness: services/ws2-normalization/parsers/mcp_agent.py.

Run:  python tools/fuzz/fuzz_mcp_agent.py -atheris_runs=200000
      python tools/fuzz/fuzz_mcp_agent.py -max_total_time=600   # nightly CI (10 min)
Corpus (optional, speeds convergence): pass a directory as the last arg.
"""
from __future__ import annotations

from _common import run
from parsers.mcp_agent import McpAgentParser

if __name__ == "__main__":
    run(McpAgentParser(), "mcp_agent")
