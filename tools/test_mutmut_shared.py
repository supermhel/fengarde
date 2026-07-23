"""pytest shim for mutmut (M2, 2026-07-22): mutmut 3.x drives pytest and
instruments mutated code via in-process trampolines keyed by the mutated
module's dotted path as mutmut itself sees it from ``source_paths``
(``services.shared.sessions`` -- an implicit namespace-package import, no
sys.path tricks). Two earlier versions of this file didn't match that:
subprocess-invoking the standalone test script left mutmut with zero
in-process coverage, and importing via ``services/shared`` on sys.path (like
``test_sessions.py`` does for its own standalone `python services/shared/
test_sessions.py` invocation) produced trampoline keys under ``shared.
sessions`` instead of ``services.shared.sessions`` -- mutmut couldn't match
them to any mutant. This version imports the module the same way mutmut's
own rootdir does, so mutant coverage attributes correctly.

Scope (see pyproject.toml [tool.mutmut]): the FIRST mutmut pass is
services/shared/sessions.py only, exercised via SessionStore (the memory
backend -- RedisSessionStore needs a live Redis, out of scope for this
gate). Duplicates services/shared/test_sessions.py's memory-backend check
bodies rather than importing that module directly, specifically to avoid
its own sys.path insertion producing the wrong module key again. Expanding
scope to the rest of services/shared is a real, disclosed follow-up
(SSOT.md), not silently assumed.
"""
from __future__ import annotations

from services.shared.sessions import SessionStore, make_session_store  # noqa: E402


def test_create_resolve_roundtrip() -> None:
    store = SessionStore()
    token = store.create("alice", "admin", "acme")
    session = store.resolve(token)
    assert session is not None
    assert session.username == "alice" and session.role == "admin" and session.tenant_id == "acme"
    assert session.csrf_token


def test_unknown_token_resolves_none() -> None:
    store = SessionStore()
    assert store.resolve("not-a-real-token") is None
    assert store.resolve("") is None


def test_expiry() -> None:
    store = SessionStore(ttl_s=0)
    token = store.create("bob", "viewer", "acme")
    assert store.resolve(token) is None


def test_invalidate() -> None:
    store = SessionStore()
    token = store.create("carol", "admin", "acme")
    assert store.resolve(token) is not None
    store.invalidate(token)
    assert store.resolve(token) is None


def test_count() -> None:
    store = SessionStore()
    before = store.count()
    t1 = store.create("d1", "viewer", "acme")
    store.create("d2", "viewer", "acme")
    assert store.count() == before + 2
    store.invalidate(t1)
    assert store.count() == before + 1


def test_make_session_store_factory(monkeypatch) -> None:
    monkeypatch.delenv("FENGARDE_SESSION_BACKEND", raising=False)
    assert isinstance(make_session_store(), SessionStore)
    monkeypatch.setenv("FENGARDE_SESSION_BACKEND", "memory")
    assert isinstance(make_session_store(), SessionStore)
    monkeypatch.setenv("FENGARDE_SESSION_BACKEND", "bogus")
    try:
        make_session_store()
        assert False, "an unknown backend name must raise, not silently fall back"
    except ValueError:
        pass
