# Adding a parser

This is a real, end-to-end walkthrough for adding a new source parser to ARGIEM. It
takes about 30 minutes and needs **only Python — no Docker, no OpenSearch, no Redis.**

A parser's whole job: turn one raw bus payload (`{source_type, raw, meta}` from the
`raw.events` topic) into a single **OCSF** event that validates against Contract A.
All the source-format heterogeneity lives here, at the edge; the rest of ARGIEM only
ever sees clean OCSF.

The extension point is deliberately small. Adding a source = **add one module +
register it**. You never touch an existing parser.

---

## Before you start

Make sure the existing tests pass, so you have a clean baseline:

```sh
cd services/ws2-normalization && python test_contract.py
# -> [OK] WS-2 contract test PASS
```

---

## The three edits

We'll add a fictional `acme_firewall` parser as the running example. Substitute your
real source type and OCSF mapping.

### Edit 1 — create the parser module

Copy the Linux SSH parser as your template — it's the cleanest example of the full
pattern (regex classification, `base_event()` scaffolding, `src_endpoint`/`actor`):

```sh
cd services/ws2-normalization/parsers
cp linux_ssh.py acme_firewall.py
```

Now edit `acme_firewall.py`. The key pieces of a parser are:

1. **Subclass `Parser`** and set the class attributes that drive the `siem.*` block
   and metadata:

   ```python
   from .base import Parser, SEV_HIGH, SEV_INFO

   class AcmeFirewallParser(Parser):
       SOURCE_TYPE = "acme_firewall"      # matches raw["source_type"]
       SECTOR = "common"                  # bank | datacenter | common
       ORIGINAL_FORMAT = "syslog"         # metadata.original_format enum
       PRODUCT = {"name": "ACME Firewall", "vendor_name": "ACME"}
   ```

2. **Implement `parse(self, raw)`** — return one OCSF event, or `None` if the line
   isn't relevant (the caller drops `None`). Use `self.base_event(...)` to build the
   common OCSF scaffold, then fill in the source-specific endpoints/actor:

   ```python
   def parse(self, raw: dict) -> Optional[dict]:
       line = raw.get("raw")
       if not isinstance(line, str):
           return None
       meta = raw.get("meta") or {}

       # ... your regex / field extraction here ...
       # classify into an OCSF class_uid + activity_id + severity

       event = self.base_event(
           class_uid=4001,          # e.g. Network Activity; pick the right OCSF class
           activity_id=6,           # per contracts/ocsf-classes.md
           severity_id=SEV_HIGH,
           time_ms=...,             # event time in epoch ms
           ingest_id=meta.get("ingest_id"),
           status="...",            # optional
           message="...",           # optional human-readable summary
       )
       event["src_endpoint"] = {"ip": src_ip}   # parser fills these in
       # event["dst_endpoint"] = {...}
       # event["actor"] = {"user": {"name": user}}
       return event
   ```

   **What `base_event()` does for you** (see `parsers/base.py`): it builds the
   `metadata` block (version, product, original_format), sets `category_uid` to
   `class_uid // 1000` (floored), and — importantly — **derives** `type_uid` via
   `make_type_uid(class_uid, activity_id)`. Never hand-set `type_uid`; the contract
   test enforces the invariant `type_uid == class_uid * 100 + activity_id`. It also
   always sets the `siem.*` block (`sector`, `source_type`, `ingest_id`). You only add
   `src_endpoint` / `dst_endpoint` / `actor` on the returned dict.

3. Rename the class and delete the SSH-specific regexes/classification you copied,
   replacing them with your source's logic.

**Invariants every parser must honour** (the contract test checks these):

- `type_uid` is derived, never hand-set — always via `base_event()`.
- The `siem.*` block is always set (handled by `base_event()`).
- `category_uid == class_uid // 1000`.
- The output validates: `shared.ocsf.validate(event) == []`.

### Edit 2 — register the parser

Open `services/ws2-normalization/parsers/__init__.py` and register your class in the
registry (around **line 19**). Add the import and add an instance to the `_REGISTRY`
comprehension:

```python
from .linux_ssh import LinuxSshParser
from .acme_firewall import AcmeFirewallParser     # <- add the import

_REGISTRY: dict[str, Parser] = {
    p.SOURCE_TYPE: p
    for p in (CiscoAsaParser(), ActiveDirectoryParser(), VmwareVsphereParser(),
              LinuxSshParser(), AcmeFirewallParser())   # <- add the instance
}
```

That's all the wiring there is. `get_parser(source_type)` now returns your parser, and
`resolve(...)` will route to it on an exact `source_type` match. (Optionally add a
content-sniff branch in `resolve()` if your source arrives under a generic
`source_type` like `syslog_rfc5424`.)

### Edit 3 — make the contract test exercise it

The WS-2 contract test (`services/ws2-normalization/test_contract.py`) is
sample-driven. Two small additions:

1. Add a raw sample for your source to
   `services/ws2-normalization/mocks/raw_samples.json` (under `"samples"`), shaped like
   the existing entries: `{"source_type": "acme_firewall", "raw": "...", "meta": {...}}`.

2. Add your source to the `expected` map in `test_contract.py` (around **line 39**),
   declaring the `(class_uid, sector)` your parser should produce:

   ```python
   expected = {
       "cisco_asa": (4001, "common"),
       "active_directory": (3002, "bank"),
       "vmware_vsphere": (6003, "datacenter"),
       "linux_ssh": (3002, "common"),
       "acme_firewall": (4001, "common"),   # <- add yours
   }
   ```

The test then parses your sample, validates the OCSF output, checks the `type_uid`
invariant, and confirms the class/sector match — and runs your sample through the full
in-memory bus loop alongside the others.

---

## Verify

One command, no infrastructure:

```sh
cd services/ws2-normalization && python test_contract.py
# -> [OK] WS-2 contract test PASS
```

If it fails, the output lists exactly what's wrong (invalid OCSF with the validation
errors, a class/sector mismatch, or a `type_uid` invariant violation). Fix and re-run.

Finally, run the full gate before opening your PR:

```sh
make test     # or: ./run_all_tests.sh
```

---

## Bonus: see it detect

If your source emits OCSF Authentication failures (`class_uid: 3002`,
`activity_id: 4`), the bundled brute-force rule
(`contracts/rules/common_bruteforce.yml`) will fire on it for free — 10 failures from
one `src_endpoint.ip` within 60 seconds. That's the same source-agnostic path the
Linux SSH and Active Directory parsers already light up. The WS-4 detection contract
test asserts the alert triggers on the 10th attempt — also runnable with zero infra:

```sh
cd services/ws4-detection && python test_contract.py
```

---

## Where to look

- `services/ws2-normalization/parsers/base.py` — the `Parser` contract and
  `base_event()` helper.
- `services/ws2-normalization/parsers/linux_ssh.py` — the template to copy.
- `services/ws2-normalization/parsers/__init__.py` — the registry (Edit 2).
- `contracts/ocsf-classes.md` — OCSF classes and activity_ids you can map to.
- `services/ws2-normalization/test_contract.py` — the zero-infra verifier (Edit 3).
