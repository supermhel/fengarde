"""M4.4 outbound webhook tests: HMAC sign/verify, config loading, real HTTP
delivery (ThreadingHTTPServer receiver), retry policy, filtering, and an
end-to-end bus-driven dispatch.

Run: python services/ws3-indexer/test_webhooks.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import webhooks  # noqa: E402
from shared.bus import Bus  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


# -- HMAC sign/verify ------------------------------------------------------

def test_sign_verify_roundtrip():
    secret = b"top-secret-key"
    body = b'{"delivery_id": "abc", "alert": {"alert_id": "x"}}'
    sig = webhooks.sign(secret, body)
    check(sig.startswith("sha256="), "signature must be tagged with its algorithm")
    check(webhooks.verify_signature(secret, body, sig), "a correctly signed body must verify")


def test_verify_rejects_tamper_and_wrong_secret():
    secret = b"top-secret-key"
    body = b'{"delivery_id": "abc", "alert": {"alert_id": "x"}}'
    sig = webhooks.sign(secret, body)
    check(not webhooks.verify_signature(secret, body + b"tampered", sig),
          "a tampered body must fail verification")
    check(not webhooks.verify_signature(b"wrong-secret", body, sig),
          "the wrong secret must fail verification")
    check(not webhooks.verify_signature(secret, body, None),
          "a missing signature header must fail verification, not raise")
    check(not webhooks.verify_signature(secret, body, ""),
          "an empty signature header must fail verification")


# -- config loading ----------------------------------------------------------

def test_load_webhook_configs_valid_and_malformed():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        (d / "good.yml").write_text(
            "id: good\nurl: https://example.com/hook\nsecret_env: MY_SECRET\n"
            "tenant_id: acme\nmin_score: 60\n")
        (d / "minimal.yml").write_text(
            "id: minimal\nurl: http://example.com/hook\nsecret_env: OTHER_SECRET\n")
        (d / "missing_url.yml").write_text("id: bad\nsecret_env: X\n")
        (d / "bad_scheme.yml").write_text(
            "id: bad-scheme\nurl: ftp://example.com/hook\nsecret_env: X\n")
        (d / "not_a_dict.yml").write_text("- just\n- a\n- list\n")

        configs = webhooks.load_webhook_configs(d)
        ids = {c.id for c in configs}
        check(ids == {"good", "minimal"},
              f"only the two well-formed configs must load, got {ids}")

        good = next(c for c in configs if c.id == "good")
        check(good.tenant_id == "acme" and good.min_score == 60,
              "optional fields must be parsed from the config file")
        minimal = next(c for c in configs if c.id == "minimal")
        check(minimal.tenant_id is None and minimal.min_score == 0,
              "omitted optional fields must default to tenant_id=None, min_score=0")


def test_load_webhook_configs_empty_dir_is_a_noop():
    with tempfile.TemporaryDirectory() as d:
        check(webhooks.load_webhook_configs(Path(d)) == [],
              "an empty webhooks dir must yield zero configs (opt-in, no behavior change)")
    check(webhooks.load_webhook_configs(Path("/no/such/dir")) == [],
          "a nonexistent webhooks dir must yield zero configs, not raise")


# -- filtering ----------------------------------------------------------------

def test_matches_tenant_and_score_filters():
    cfg = webhooks.WebhookConfig(id="x", url="https://e.com", secret_env="S",
                                  tenant_id="acme", min_score=60)
    check(webhooks._matches(cfg, {"tenant_id": "acme", "score": 70}), "matching tenant+score must pass")
    check(not webhooks._matches(cfg, {"tenant_id": "globex", "score": 70}), "wrong tenant must not match")
    check(not webhooks._matches(cfg, {"tenant_id": "acme", "score": 10}), "score below floor must not match")

    cfg_any_tenant = webhooks.WebhookConfig(id="y", url="https://e.com", secret_env="S")
    check(webhooks._matches(cfg_any_tenant, {"tenant_id": "anything", "score": 0}),
          "tenant_id=None and min_score=0 must match every alert")
    check(webhooks._matches(cfg_any_tenant, {}),
          "a missing tenant_id/score on the alert must not crash the filter")


# -- real HTTP delivery -------------------------------------------------------

class _CapturingHandler(BaseHTTPRequestHandler):
    received: list[dict] = []
    status_to_return = 200
    fail_count = 0  # how many times to return 500 before succeeding

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        _CapturingHandler.received.append({
            "body": body,
            "signature": self.headers.get(webhooks.SIGNATURE_HEADER),
            "delivery_id": self.headers.get(webhooks.DELIVERY_ID_HEADER),
        })
        if _CapturingHandler.fail_count > 0:
            _CapturingHandler.fail_count -= 1
            self.send_response(500)
            self.end_headers()
            return
        self.send_response(_CapturingHandler.status_to_return)
        self.end_headers()

    def log_message(self, *_):
        pass


def _serve_capturing():
    _CapturingHandler.received = []
    _CapturingHandler.status_to_return = 200
    _CapturingHandler.fail_count = 0
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _CapturingHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def test_deliver_signs_correctly_and_receiver_can_verify():
    srv, port = _serve_capturing()
    os.environ["TEST_WEBHOOK_SECRET"] = "s3cr3t-value"
    try:
        cfg = webhooks.WebhookConfig(id="t", url=f"http://127.0.0.1:{port}/hook",
                                      secret_env="TEST_WEBHOOK_SECRET")
        alert = {"alert_id": "a1", "tenant_id": "acme", "score": 80, "rule_title": "test"}
        ok = webhooks.deliver(cfg, alert)
        check(ok, "delivery to a live 200-returning receiver must succeed")
        check(len(_CapturingHandler.received) == 1, "exactly one request must have been sent")
        received = _CapturingHandler.received[0]
        check(webhooks.verify_signature(b"s3cr3t-value", received["body"], received["signature"]),
              "the receiver must be able to verify the signature with the shared secret")
        parsed = json.loads(received["body"])
        check(parsed["alert"] == alert, "the delivered body must carry the exact alert document")
        check(received["delivery_id"] == parsed["delivery_id"],
              "the delivery-id header and body field must match")
    finally:
        del os.environ["TEST_WEBHOOK_SECRET"]
        srv.shutdown(); srv.server_close()


def test_deliver_missing_secret_env_fails_closed():
    srv, port = _serve_capturing()
    try:
        cfg = webhooks.WebhookConfig(id="t", url=f"http://127.0.0.1:{port}/hook",
                                      secret_env="THIS_ENV_VAR_IS_NOT_SET_ANYWHERE")
        ok = webhooks.deliver(cfg, {"alert_id": "a1"})
        check(not ok, "a missing secret env var must fail the delivery, not send unsigned")
        check(len(_CapturingHandler.received) == 0,
              "no request should even be sent when the secret is missing")
    finally:
        srv.shutdown(); srv.server_close()


def test_deliver_4xx_does_not_retry():
    srv, port = _serve_capturing()
    _CapturingHandler.status_to_return = 400
    os.environ["TEST_WEBHOOK_SECRET"] = "s"
    try:
        cfg = webhooks.WebhookConfig(id="t", url=f"http://127.0.0.1:{port}/hook",
                                      secret_env="TEST_WEBHOOK_SECRET")
        ok = webhooks.deliver(cfg, {"alert_id": "a1"})
        check(not ok, "a 4xx response must be treated as a failed delivery")
        check(len(_CapturingHandler.received) == 1,
              f"a 4xx must NOT be retried (permanent failure), got {len(_CapturingHandler.received)} attempts")
    finally:
        del os.environ["TEST_WEBHOOK_SECRET"]
        srv.shutdown(); srv.server_close()


def test_deliver_5xx_retries_then_succeeds():
    srv, port = _serve_capturing()
    _CapturingHandler.fail_count = 2  # fail twice (500), succeed on the 3rd (final) attempt
    os.environ["TEST_WEBHOOK_SECRET"] = "s"
    try:
        cfg = webhooks.WebhookConfig(id="t", url=f"http://127.0.0.1:{port}/hook",
                                      secret_env="TEST_WEBHOOK_SECRET")
        ok = webhooks.deliver(cfg, {"alert_id": "a1"})
        check(ok, "a transient 500 that clears within the retry budget must eventually succeed")
        check(len(_CapturingHandler.received) == 3,
              f"must have retried up to the 3-attempt budget, got {len(_CapturingHandler.received)}")
    finally:
        del os.environ["TEST_WEBHOOK_SECRET"]
        srv.shutdown(); srv.server_close()


# -- end-to-end: bus -> dispatcher -> real receiver --------------------------

def test_run_dispatches_bus_alerts_to_matching_receiver_only():
    srv, port = _serve_capturing()
    os.environ["TEST_WEBHOOK_SECRET"] = "s3cr3t"
    try:
        cfg = webhooks.WebhookConfig(id="acme-only", url=f"http://127.0.0.1:{port}/hook",
                                      secret_env="TEST_WEBHOOK_SECRET", tenant_id="acme")
        bus = Bus()
        bus.produce("alerts", key="a1", payload={"alert_id": "a1", "tenant_id": "acme", "score": 90})
        bus.produce("alerts", key="a2", payload={"alert_id": "a2", "tenant_id": "globex", "score": 90})

        stats = webhooks.run(bus, configs=[cfg])
        check(stats == {"alerts_seen": 2, "deliveries": 1},
              f"only the acme alert should match and be delivered, got {stats}")
        check(len(_CapturingHandler.received) == 1, "exactly one HTTP delivery must have reached the receiver")
        delivered_alert = json.loads(_CapturingHandler.received[0]["body"])["alert"]
        check(delivered_alert["alert_id"] == "a1", "the delivered alert must be the acme one, not globex's")
    finally:
        del os.environ["TEST_WEBHOOK_SECRET"]
        srv.shutdown(); srv.server_close()


def test_run_with_no_configs_never_touches_the_bus():
    bus = Bus()
    bus.produce("alerts", key="a1", payload={"alert_id": "a1", "score": 100})
    stats = webhooks.run(bus, configs=[])
    check(stats == {"alerts_seen": 0, "deliveries": 0}, "no configs -> a pure no-op")
    # the alert must still be sitting on the topic, untouched (proves run()
    # returned before ever calling bus.consume when configs is empty).
    remaining = bus.drain("alerts")
    check(len(remaining) == 1, "run() with zero configs must not have consumed the topic at all")


def main():
    test_sign_verify_roundtrip()
    test_verify_rejects_tamper_and_wrong_secret()
    test_load_webhook_configs_valid_and_malformed()
    test_load_webhook_configs_empty_dir_is_a_noop()
    test_matches_tenant_and_score_filters()
    test_deliver_signs_correctly_and_receiver_can_verify()
    test_deliver_missing_secret_env_fails_closed()
    test_deliver_4xx_does_not_retry()
    test_deliver_5xx_retries_then_succeeds()
    test_run_dispatches_bus_alerts_to_matching_receiver_only()
    test_run_with_no_configs_never_touches_the_bus()

    if FAILS:
        print(f"[FAIL] webhooks: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] M4.4 outbound webhooks: HMAC sign/verify, config loading (valid+malformed), "
          "tenant/score filtering, real HTTP delivery with receiver-side verification, "
          "4xx-no-retry / 5xx-bounded-retry, bus-driven end-to-end dispatch to the right tenant only")


if __name__ == "__main__":
    main()
