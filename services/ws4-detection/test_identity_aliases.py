"""F2 (owner decision 2026-10-21): explicit per-tenant realm alias map.

Without a map WS-4 groups accounts exactly as before (strip + casefold; DOMAIN\\name, name@upn and
name stay three accounts). With a map, the spellings of one realm collapse to ONE identity, per
tenant only, so a burst split over CORP\\jdoe / jdoe@corp.example still reaches the threshold of
common_lateral_movement. A malformed map fails closed at rule load.

Run: python services/ws4-detection/test_identity_aliases.py
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "services"))

import engine  # noqa: E402
from engine import load_rules  # noqa: E402
from shared.identity_aliases import IdentityAliasError  # noqa: E402

LATERAL = "2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061"  # 5 distinct hosts / 300 s, by account
BASE = 1_751_500_000_000
FAILS: list[str] = []

MAP = """
version: 1
tenants:
  acme:
    default_realm: corp
    realms:
      - [CORP, corp.example]
"""


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _write(text: str) -> Path:
    fd, name = tempfile.mkstemp(suffix=".yml")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return Path(name)


def _logon(i: int, user: str, tenant: str = "acme") -> dict:
    return {"class_uid": 3002, "activity_id": 1, "status": "Success", "time": BASE + i * 1_000,
            "actor": {"user": {"name": user}}, "dst_endpoint": {"hostname": f"srv{i}"},
            "src_endpoint": {"ip": "192.0.2.50"},
            "siem": {"ingest_id": f"f2a-{tenant}-{i}", "tenant": tenant}}


def _fires(names: list[str], tenant: str = "acme") -> bool:
    rule = next(r for r in load_rules(ROOT / "contracts" / "rules") if r.id == LATERAL)
    fired = False
    for i, n in enumerate(names):
        fired = rule.evaluate(_logon(i, n, tenant))
    return fired


def _expect_error(text: str, needle: str, why: str):
    p = _write(text)
    try:
        engine.configure_identity_aliases(p)
        check(False, f"{why}: must raise IdentityAliasError")
    except IdentityAliasError as exc:
        check(needle in str(exc), f"{why}: error should mention {needle!r}, got: {exc}")
    finally:
        p.unlink()


def run():
    split = ["CORP\\jdoe", "jdoe@corp.example", "CORP\\jdoe", "jdoe@corp.example", "CORP\\jdoe"]
    os.environ.pop("FENGARDE_IDENTITY_ALIASES", None)

    # absent map == unchanged: the shipped contracts/identity_aliases.yaml is empty
    check(not _fires(split), "no map: two spellings stay two accounts (2+3 hosts < 5)")
    check(not _fires(["jdoe", "CORP\\jdoe", "jdoe@corp.example", "jdoe", "CORP\\jdoe"]),
          "no map: bare / DOMAIN\\ / UPN stay distinct (never guess)")
    check(_fires(["Jdoe", "jdoe ", " JDOE", "jdoe", "JDoe"]), "no map: case + whitespace still fold")

    # map collapses the spellings and the rule fires
    mp = _write(MAP)
    try:
        os.environ["FENGARDE_IDENTITY_ALIASES"] = str(mp)
        check(_fires(split), "map: CORP\\jdoe + jdoe@corp.example collapse; 5 hosts fire the rule")
        check(_fires(["CORP\\JDoe", "JDOE@Corp.Example ", " jdoe", "corp\\jdoe", "jdoe@CORP"]),
              "map: case/whitespace preserved on top of the realm collapse; bare name uses default_realm")
        check(not _fires(["CORP\\jdoe", "CORP\\jsmith", "jdoe@corp.example", "CORP\\jsmith", "jdoe@corp.example"]),
              "map: different people in the same realm stay separate")
        check(not _fires(["CORP\\jdoe", "OTHER\\jdoe", "jdoe@other.example", "OTHER\\jdoe", "CORP\\jdoe"]),
              "map: an unlisted realm is not merged")
        # the map is per tenant: tenant 'globex' has no entry so nothing collapses for it
        check(not _fires(split, tenant="globex"), "map for acme must not collapse globex's spellings")
        # alert identity: one id for both spellings, deterministic across redelivery
        rule = next(r for r in load_rules(ROOT / "contracts" / "rules") if r.id == LATERAL)
        a, b = _logon(0, "CORP\\jdoe"), _logon(0, "jdoe@corp.example")
        check(rule.alert_key(a) == rule.alert_key(b) == rule.alert_key(dict(a)),
              "alert_key identical for both spellings and under redelivery")
        g = _logon(0, "CORP\\jdoe", tenant="globex")
        check(rule.alert_key(a) != rule.alert_key(g), "alert_key stays tenant-namespaced")
    finally:
        os.environ.pop("FENGARDE_IDENTITY_ALIASES", None)
        mp.unlink()

    # malformed maps fail closed with a clear error (also through load_rules)
    _expect_error("version: 1\ntenants: [", "valid YAML", "broken YAML")
    _expect_error("version: 2\ntenants: {}", "version", "wrong version")
    _expect_error("version: 1\nrealms: [[a, b]]", "global", "global (non-tenant) entry")
    _expect_error("version: 1\ntenants:\n  '*':\n    realms: [[a, b]]", "tenant id", "wildcard tenant")
    _expect_error("version: 1\ntenants:\n  acme:\n    realms: [[a, 'globex:b']]", "tenant-qualified", "cross-tenant realm")
    _expect_error("version: 1\ntenants:\n  acme:\n    realms: [[a]]", "at least 2", "single-spelling group")
    _expect_error("version: 1\ntenants:\n  acme:\n    realms: [[a, b], [b, c]]", "disjoint", "chained groups")
    _expect_error("version: 1\ntenants:\n  acme:\n    realms: [[a, b]]\n  acme:\n    realms: [[c, d]]",
                  "duplicate", "tenant listed twice")
    _expect_error("version: 1\ntenants:\n  acme:\n    realms: [[a, b]]\n    default_realm: zzz",
                  "default_realm", "default realm outside the groups")
    _expect_error("version: 1\ntenants:\n  acme:\n    realms: [[a, b]]\n    extra: 1", "only", "unknown key")
    # a configured-but-empty / truncated file must FAIL CLOSED (a half-written file on hot reload used to
    # silently drop every alias): zero bytes, only the version line, tenants key with no value
    _expect_error("", "empty", "zero-byte file")
    _expect_error("version: 1\n", "tenants", "version line only (truncated)")
    _expect_error("version: 1\ntenants:\n", "tenants", "tenants key with no value (truncated)")
    _expect_error("? [a]\n: 1\n", "invalid mapping key", "unhashable mapping key raises IdentityAliasError, not TypeError")
    ok = _write("version: 1\ntenants: {}\n")           # an intentionally empty map still loads
    try:
        engine.configure_identity_aliases(ok)
    except IdentityAliasError as exc:
        check(False, f"the explicit empty map must load: {exc}")
    finally:
        ok.unlink()
    # hot reload: a truncated file keeps the PREVIOUS map live and load_rules() raises (Detector.reload keeps old rules)
    good = _write(MAP)
    half = _write("version: 1\ntenants:\n")
    try:
        os.environ["FENGARDE_IDENTITY_ALIASES"] = str(good)
        load_rules(ROOT / "contracts" / "rules")
        check(_fires(split), "precondition: the good map folds the spellings")
        os.environ["FENGARDE_IDENTITY_ALIASES"] = str(half)
        try:
            load_rules(ROOT / "contracts" / "rules")
            check(False, "load_rules must raise on a truncated alias file")
        except IdentityAliasError:
            pass
        from shared.identity_aliases import canonical_account
        check(canonical_account("acme", "CORP" + chr(92) + "jdoe") == "jdoe@corp",
              "after the failed reload the previous map must still be active (not silently emptied)")
    finally:
        os.environ.pop("FENGARDE_IDENTITY_ALIASES", None)
        good.unlink()
        half.unlink()

    # review M1: the DEFAULT file vanishing during a reload (rename-and-replace deploy, ConfigMap swap) must not
    # silently turn the map into "no map": configure() raises and the previous map stays active
    import shared.identity_aliases as ia
    os.environ.pop("FENGARDE_IDENTITY_ALIASES", None)
    default_file = _write(MAP)
    saved_defaults = ia._DEFAULT_FILES
    try:
        ia._DEFAULT_FILES = (default_file,)
        ia.commit((ia.IdentityAliases(), None))
        ia.configure()
        check(ia.canonical_account("acme", "CORP" + chr(92) + "jdoe") == "jdoe@corp", "precondition: default file map loaded")
        default_file.unlink()
        try:
            ia.configure()
            check(False, "a vanished default alias file must raise, not silently drop the map")
        except IdentityAliasError as exc:
            check("missing" in str(exc), f"vanished-file error should say so: {exc}")
        check(ia.canonical_account("acme", "CORP" + chr(92) + "jdoe") == "jdoe@corp",
              "after the vanished-file failure the previous map must still be active")
    finally:
        ia._DEFAULT_FILES = saved_defaults
        ia.commit((ia.IdentityAliases(), None))
        if default_file.exists():
            default_file.unlink()

    # review L3: a file cut in the middle of a multibyte character is an IdentityAliasError, not a raw UnicodeDecodeError
    cut = _write("")
    cut.write_bytes("version: 1\ntenants:\n  acme:\n    realms: [[é, b]]\n".encode("utf-8")[:-4] + b"\xc3")
    try:
        ia.load(cut)
        check(False, "a file with a cut multibyte character must raise")
    except IdentityAliasError:
        pass
    except Exception as exc:
        check(False, f"cut multibyte file must raise IdentityAliasError, got {type(exc).__name__}")
    finally:
        cut.unlink()

    # review L1: a failed RULE reload must keep the previous map too (they swap together)
    import shutil
    new_map = _write("version: 1\ntenants:\n  acme:\n    default_realm: other\n    realms: [[OTHER, other.example]]\n")
    rules_copy = Path(tempfile.mkdtemp())
    try:
        for f in (ROOT / "contracts" / "rules").glob("*.yml"):
            shutil.copy(f, rules_copy / f.name)
        os.environ["FENGARDE_IDENTITY_ALIASES"] = str(_write(MAP))
        load_rules(rules_copy)
        check(ia.canonical_account("acme", "CORP" + chr(92) + "jdoe") == "jdoe@corp", "precondition: first map active")
        (rules_copy / "zz_truncated.yml").write_text("", encoding="utf-8")
        os.environ["FENGARDE_IDENTITY_ALIASES"] = str(new_map)
        try:
            load_rules(rules_copy, strict_empty=True)
            check(False, "a truncated rule file must fail the strict reload")
        except ValueError:
            pass
        check(ia.canonical_account("acme", "CORP" + chr(92) + "jdoe") == "jdoe@corp",
              "a failed rule reload must NOT install the new alias map (previous rules and map stay together)")
    finally:
        os.environ.pop("FENGARDE_IDENTITY_ALIASES", None)
        new_map.unlink()
        shutil.rmtree(rules_copy, ignore_errors=True)
        ia.commit((ia.IdentityAliases(), None))

    bad = _write("version: 1\ntenants:\n  acme:\n    realms: oops\n")
    try:
        os.environ["FENGARDE_IDENTITY_ALIASES"] = str(bad)
        try:
            load_rules(ROOT / "contracts" / "rules")
            check(False, "load_rules must refuse to load with a malformed alias map")
        except IdentityAliasError:
            pass
        os.environ["FENGARDE_IDENTITY_ALIASES"] = str(bad) + ".missing"
        try:
            load_rules(ROOT / "contracts" / "rules")
            check(False, "an env-pointed missing file must fail closed, not run without a map")
        except IdentityAliasError as exc:
            check("cannot read" in str(exc), f"missing-file error should be clear: {exc}")
    finally:
        os.environ.pop("FENGARDE_IDENTITY_ALIASES", None)
        bad.unlink()
    engine.configure_identity_aliases()  # leave the shipped (empty) map active


if __name__ == "__main__":
    run()
    if FAILS:
        for f in FAILS:
            print("[FAIL]", f)
        sys.exit(1)
    print("[OK] F2 identity alias map: collapses mapped realms per tenant, absent map unchanged, "
          "malformed map fails closed")
