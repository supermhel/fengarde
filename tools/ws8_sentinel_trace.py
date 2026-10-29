"""Summarise the per-alert trace of tools/ws8_sentinel_live_proof.sh.

Input file: lines "<replica> <log line with alert_id>". Prints "<alerts traced> <replicas seen> <split chains>"
and a human summary on stderr. A chain is "split" when its two tactics (b-N-1, b-N-2) were handled by different replicas.
"""
import collections
import re
import sys

seen: dict[str, set] = {}
for line in open(sys.argv[1], encoding="utf-8"):
    rep = line.split(" ", 1)[0]
    m = re.search(r'"alert_id":\s*"([^"]+)"', line) or re.search(r"alert_id=(\S+)", line)
    if m:
        seen.setdefault(m.group(1), set()).add(rep)
per = collections.Counter(r for reps in seen.values() for r in reps)
split = [i for i in range(1, 21)
         if seen.get(f"b-{i}-1") and seen.get(f"b-{i}-2") and seen[f"b-{i}-1"].isdisjoint(seen[f"b-{i}-2"])]
for aid in sorted(a for a in seen if a.startswith("b-")):
    print(f"  {aid} -> {sorted(seen[aid])}", file=sys.stderr)
print(f"alerts traced: {len(seen)}; per replica: {dict(per)}; chains split across replicas: {len(split)} {split}",
      file=sys.stderr)
print(len(seen), len(per), len(split))
