"""shared/causal_keys.py tests (ADR-012 WP 2).

Covers: canonicalisers, dropped "none" values (negative tests), the injective
key-hash encoding (the ("a|b","c") vs ("a","b|c") collision test), and the
bus-only coupling rule (no ws* import).
"""
from __future__ import annotations

import ast
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from shared import causal_keys as ck  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)
        print(f"  [FAIL] {msg}")


GUID = "3b1f2c4d-5e6a-7b8c-9d0e-1f2a3b4c5d6e"

# --- GUID canonicalisation -------------------------------------------------
check(ck.canon_guid("{3B1F2C4D-5E6A-7B8C-9D0E-1F2A3B4C5D6E}") == GUID, "braces + upper -> lower, no braces")
check(ck.canon_guid(GUID.upper()) == GUID, "uppercase GUID lowercased")
check(ck.canon_guid("  " + GUID + " ") == GUID, "surrounding whitespace stripped")
check(ck.canon_guid("not-a-guid") is None, "non-GUID shape dropped")
check(ck.canon_guid(12345) is None, "non-string GUID dropped")

# --- LogonId canonicalisation ----------------------------------------------
check(ck.canon_logon_id("0x3E7") == "3e7", "0x3E7 -> 3e7")
check(ck.canon_logon_id("0x00003E7") == "3e7", "leading zeros stripped")
check(ck.canon_logon_id("0X1A2B") == "1a2b", "0X prefix accepted")
check(ck.canon_logon_id("3E7") == "3e7", "bare hex accepted")
check(ck.canon_logon_id(999) == "3e7", "int LogonId rendered as hex")
check(ck.canon_logon_id("0xZZ") is None, "non-hex dropped")

# --- flow id canonicalisation ----------------------------------------------
check(ck.canon_flow_id(1234567890123456) == "1234567890123456", "int flow_id -> decimal string")
check(ck.canon_flow_id("1234567890123456") == "1234567890123456", "decimal string kept")
check(ck.canon_flow_id("CYZb5d1Tx9") == "CYZb5d1Tx9", "Zeek uid kept verbatim (case-sensitive)")
check(ck.canon_flow_id(True) is None, "bool is not a flow id")
check(ck.canon_flow_id(1.5) is None, "float is not a flow id")

# --- 128-char cap -----------------------------------------------------------
long = "x" * 500
check(len(ck.canon_flow_id(long) or "") == 128, "flow id capped at 128")
check(len(ck.canon_agent_session(long) or "") == 128, "agent session capped at 128")

# --- negative tests: every dropped value, for every namespace ---------------
NULL_GUIDS = ["00000000-0000-0000-0000-000000000000", "{00000000-0000-0000-0000-000000000000}", "0" * 32]
NONES = [None, "", "   ", "-", "0x0", "0X0", "0x00000000", "0", "{}", "null", "None"]
for v in NULL_GUIDS + NONES:
    check(ck.canon_guid(v) is None, f"canon_guid drops {v!r}")
for v in NONES + [0]:  # type: ignore[assignment]
    check(ck.canon_logon_id(v) is None, f"canon_logon_id drops {v!r}")
for v in NONES + [0]:  # type: ignore[assignment]
    check(ck.canon_flow_id(v) is None, f"canon_flow_id drops {v!r}")
for v in NONES:
    check(ck.canon_agent_session(v) is None, f"canon_agent_session drops {v!r}")
for ns in ("proc", "logon", "flow", "agent"):
    for v in (None, "", "-", "0x0", NULL_GUIDS[0]):
        check(ck.key_hash("t", ns, "10.0.0.1", "hostA", v) is None, f"key_hash({ns}) drops {v!r}")

# --- key hash: injective tuple encoding -------------------------------------
check(ck.canonical_tuple(["a|b", "c"]) != ck.canonical_tuple(["a", "b|c"]), "canonical bytes differ for | shift")
h1 = ck.key_hash("t", "agent", "10.0.0.1", "a|b", "c")
h2 = ck.key_hash("t", "agent", "10.0.0.1", "a", "b|c")
check(h1 is not None and h2 is not None and h1 != h2, "collision test: (a|b, c) vs (a, b|c) hash differently")
check(ck.key_hash("t|x", "agent", "s", "scope", "v") != ck.key_hash("t", "agent", "x|s", "scope", "v"),
      "delimiter cannot be forged across tenant/sender")
check(ck.key_hash("t", "agent", "s|", "scope", "v") != ck.key_hash("t", "agent", "s", "|scope", "v"),
      "delimiter cannot be forged across sender/scope")
check(ck.key_hash("t", "agent", "", "scope", "v") != ck.key_hash("t", "agent", "scope", "", "v"),
      "empty sender vs empty scope differ")
for a, b in [('a","b', "a"), ("a\\", "a"), ("ä", "a"), ("a\n", "a")]:
    check(ck.key_hash("t", "agent", "s", a, "v") != ck.key_hash("t", "agent", "s", b, "v"),
          f"distinct scopes {a!r} vs {b!r}")

# normative encoding: sha256 over canonical JSON array of five strings, first 16 hex
expect = hashlib.sha256(json.dumps(["t", "proc", "10.0.0.1", "hostA", GUID], ensure_ascii=True,
                                   separators=(",", ":")).encode("utf-8")).hexdigest()[:16]
got = ck.key_hash("t", "proc", "10.0.0.1", "hostA", "{" + GUID.upper() + "}")
check(got == expect, f"key_hash matches the ADR encoding ({got} vs {expect})")
check(got is not None and len(got) == 16 and all(c in "0123456789abcdef" for c in got), "16 lowercase hex chars")

# determinism + sensitivity
check(ck.key_hash("t", "proc", "s", "h", GUID) == ck.key_hash("t", "proc", "s", "h", GUID.upper()),
      "canonicalised before hashing")
base = ck.key_hash("t", "proc", "s", "h", GUID)
for args in [("t2", "proc", "s", "h", GUID), ("t", "logon", "s", "h", "3e7"), ("t", "proc", "s2", "h", GUID),
             ("t", "proc", "s", "h2", GUID)]:
    check(ck.key_hash(*args) != base, f"hash changes with {args[:4]}")
check(ck.key_hash("t", "bogus", "s", "h", "v") is None, "unknown namespace -> None")
check(ck.key_hash("t", "proc", None, "h", GUID) == ck.key_hash("t", "proc", "", "h", GUID),
      "None sender treated as empty string")

# --- coupling rule: no ws* import in the shared module ----------------------
tree = ast.parse((HERE / "causal_keys.py").read_text(encoding="utf-8"))
mods: list[str] = []
for n in ast.walk(tree):
    if isinstance(n, ast.Import):
        mods += [a.name for a in n.names]
    elif isinstance(n, ast.ImportFrom):
        mods.append(n.module or "")
check(not any(m.split(".")[0].startswith("ws") for m in mods), f"causal_keys imports no ws* module (saw {mods})")

if FAILS:
    print(f"\nFAILED: {len(FAILS)} check(s)")
    sys.exit(1)
print("OK: shared causal_keys")
