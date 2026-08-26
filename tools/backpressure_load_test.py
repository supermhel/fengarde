"""B2 backpressure under a REAL UDP flood -- live load test.

NOTE (2026-08-26): this test is deliberately NOT wired into run_all_tests.sh
or any make target -- it is a LIVE-STACK load test (it needs the docker
compose stack up: ws1 publishing 5514/udp plus a peer container to flood
from), which CI's zero-infra jobs never have. It is self-contained and
safe to run by hand: every prerequisite (docker reachable, the two named
containers up, /metrics readable, a cap set) is probed up front, and each
absence prints an explicit [SKIP] line and exits 0 -- it can never fail a
tree it was not given the environment to exercise, and it can never be
mistaken for a silent no-op (every [SKIP] names what was missing). Run it
with the stack up: `python tools/backpressure_load_test.py`.

Closes the gap SSOT.md §2 records: "B2 backpressure protects Redis under a real
flood -- **Unit-tested, not load-tested**. Token-bucket shedding + spool replay
have unit/integration tests, but no real high-rate flood against a live Redis
was run -- the 'protects against OOM' claim is by-design, not measured."

What this measures, stated narrowly so the result is not over-read:

  1. **The cap actually binds.** Under a flood far above
     `SYSLOG_MAX_EVENTS_PER_SEC`, the number of datagrams that reach the BUS is
     bounded near the cap rather than tracking the send rate. This is the
     "protects Redis" claim, and it is the one that matters -- an unbounded
     producer is how the broker OOMs.
  2. **Loss is COUNTED, never silent.** Everything the listener did not produce
     must show up in a counter (`events_shed`, `events_dropped`,
     `events_queue_full`, `events_spooled`) or in the kernel's own
     `udp_rcvbuf_errors`. A flood that quietly vanishes reads as a healthy
     `events_shed=0` and is the exact loss class this service's own module
     docstring warns about.
  3. **The service survives.** `/health` still answers after the flood.

What it does NOT claim: that 2000/s is the RIGHT cap, or that the process cannot
OOM under a different traffic shape. The rate default and the depth threshold
remain untuned guesses, exactly as SSOT.md says -- this proves the mechanism
engages and accounts for what it sheds, not that the number is well chosen.

UDP is lossy by design, so "sent" is an upper bound on what the listener ever
saw; the assertions are written around that rather than pretending otherwise.

Run with the stack up (ws1 publishes 5514/udp):
    python tools/backpressure_load_test.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import time

WS1 = "infra-ws1-collectors-1"
# The flood originates INSIDE the docker network, from another container, not
# from the host. Measured 2026-08-11: a host->container flood over Docker
# Desktop's NAT loses ~75% of datagrams in transit before ws1 ever sees them,
# so arrivals stay under the cap and NO shedding mechanism engages -- the test
# passes while proving nothing about backpressure. Sending from a peer
# container removes that bottleneck.
SENDER = "infra-ws2-normalization-1"
TARGET_HOST, PORT = "ws1-collectors", 5514
# One python sender tops out around 950/s in-container, and the aggregate is
# CPU-bound on the sending container, so it varies with host load: 6 senders
# measured 4757/s on an idle host and only 3065/s with other tests running,
# which trips the "was this actually a flood?" guard below and correctly
# refuses to claim evidence. 12 keeps real headroom over the 2x-cap bar rather
# than weakening the guard, which is the thing that makes a pass mean anything.
_SENDERS = 12
_PER_SENDER = 10_000
_SETTLE_S = 6

_FLOOD_SRC = '''
import socket, sys, time
host, port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
p = (b"<134>Aug 11 21:00:00 loadhost sshd[1]: "
     b"Failed password for root from 198.51.100.77 port 22 ssh2")
sent = 0
t0 = time.time()
for _ in range(n):
    try:
        s.sendto(p, (host, port)); sent += 1
    except OSError:
        time.sleep(0.001)
print("SENT %d %.3f" % (sent, time.time() - t0))
'''

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def sh(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout)


def metrics() -> dict | None:
    """ws1's /metrics, read from inside the container (the health port is not
    host-published)."""
    code = ("import json,urllib.request;"
            "print(urllib.request.urlopen('http://127.0.0.1:8001/metrics',"
            "timeout=5).read().decode())")
    r = sh("docker", "exec", WS1, "python", "-c", code)
    if r.returncode != 0:
        return None
    try:
        # The runner nests a metrics_provider's payload under "extra"; reading
        # "syslog_udp" off the top level silently yields {} and every delta
        # below computes as 0, which reads exactly like "the flood never
        # arrived". Cost the first run of this test a false FAIL.
        return json.loads(r.stdout.strip()).get("extra", {}).get("syslog_udp", {})
    except (ValueError, AttributeError):
        return None


def rate_cap() -> float:
    r = sh("docker", "exec", WS1, "sh", "-c", "echo $SYSLOG_MAX_EVENTS_PER_SEC")
    try:
        return float(r.stdout.strip())
    except ValueError:
        return 0.0


def main() -> int:
    if sh("docker", "version").returncode != 0:
        print("[SKIP] backpressure load: docker is not reachable.")
        return 0
    if sh("docker", "inspect", WS1).returncode != 0:
        print(f"[SKIP] backpressure load: {WS1} is not running (make up).")
        return 0

    before = metrics()
    if before is None:
        print("[SKIP] backpressure load: could not read ws1 /metrics -- the "
              "syslog listener may not be bound.")
        return 0
    cap = rate_cap()
    if cap <= 0:
        print("[SKIP] backpressure load: SYSLOG_MAX_EVENTS_PER_SEC is unset in "
              "the container, so there is no cap to measure against.")
        return 0

    if sh("docker", "inspect", SENDER).returncode != 0:
        print(f"[SKIP] backpressure load: sender container {SENDER} is not "
              f"running -- an in-network flood is the only shape that actually "
              f"applies backpressure (see the constants above).")
        return 0

    total = _SENDERS * _PER_SENDER
    print(f"[load] cap={cap:g}/s, flooding {TARGET_HOST}:{PORT} with {total} "
          f"datagrams from {_SENDERS} parallel senders inside {SENDER}")

    # A realistic RFC 3164 line so the generic_syslog parser would accept it --
    # flooding with garbage would exercise the parser's reject path instead of
    # the backpressure path this test is about.
    sh("docker", "exec", SENDER, "sh", "-c",
       f"cat > /tmp/_fengarde_flood.py <<'EOF'\n{_FLOOD_SRC}\nEOF")
    t0 = time.time()
    r = sh("docker", "exec", SENDER, "sh", "-c",
           " ".join(f"python /tmp/_fengarde_flood.py {TARGET_HOST} {PORT} "
                    f"{_PER_SENDER} &" for _ in range(_SENDERS)) + " wait",
           timeout=600)
    elapsed = time.time() - t0
    sent = sum(int(line.split()[1]) for line in r.stdout.splitlines()
               if line.startswith("SENT "))
    if sent == 0:
        print(f"[SKIP] backpressure load: no sender reported progress "
              f"({(r.stderr or r.stdout).strip()[:200]}) -- nothing was flooded.")
        return 0
    send_rate = sent / max(elapsed, 1e-6)
    print(f"[load] sent {sent} datagrams in {elapsed:.2f}s "
          f"({send_rate:.0f}/s, {send_rate / cap:.1f}x the cap)")

    check(send_rate > cap * 2,
          f"send rate {send_rate:.0f}/s was not meaningfully above the "
          f"{cap:g}/s cap -- this run did not actually apply backpressure, so "
          f"nothing below is evidence")

    time.sleep(_SETTLE_S)  # let the worker pool drain before reading counters
    after = metrics()
    if after is None:
        print("[FAIL] backpressure load: ws1 /metrics unreadable after the "
              "flood -- the service may have died, which is itself the failure.")
        return 1

    def delta(key: str) -> int:
        return int(after.get(key, 0)) - int(before.get(key, 0))

    produced = delta("events_produced")
    shed = delta("events_shed")
    dropped = delta("events_dropped")
    spooled = delta("events_spooled")
    queue_full = delta("events_queue_full")
    lost = delta("events_lost")
    kernel = delta("udp_rcvbuf_errors_cumulative") \
        if "udp_rcvbuf_errors_cumulative" in after else 0
    accounted = produced + shed + dropped + spooled + queue_full + lost

    print(f"[load] produced={produced} shed={shed} dropped={dropped} "
          f"spooled={spooled} queue_full={queue_full} lost={lost} "
          f"kernel_rcvbuf_errors={kernel}")
    print(f"[load] accounted={accounted} of {sent} sent "
          f"({sent - accounted} never reached the listener -- UDP/kernel loss)")

    # 1. THE CLAIM: the bus was protected. Produced must be bounded near the
    #    cap, not near the send rate. Generous 3x allowance for burst credit
    #    and the settle window -- the failure being hunted is "no cap at all"
    #    (produced tracking `sent`), not a small accounting difference.
    ceiling = cap * (elapsed + _SETTLE_S) * 3
    check(produced <= ceiling,
          f"events_produced={produced} exceeds {ceiling:.0f} (cap {cap:g}/s over "
          f"{elapsed + _SETTLE_S:.1f}s x3 burst allowance) -- the token bucket is "
          f"NOT bounding what reaches the bus, so a flood reaches Redis unthrottled")
    check(produced < sent,
          f"events_produced={produced} >= sent={sent} -- nothing was shed at "
          f"{send_rate:.0f}/s against a {cap:g}/s cap, so the cap is not engaging")

    # 2. Loss must be COUNTED somewhere -- but not necessarily by the token
    #    bucket. Measured 2026-08-11: under a host->container UDP flood the
    #    kernel receive buffer overflows BEFORE the application-level bucket
    #    ever sees the excess, so `events_shed` stays 0 while
    #    `udp_rcvbuf_errors_cumulative` climbs. That is precisely the loss class
    #    syslog_udp_server.py's own module docstring calls out as reading like a
    #    healthy `events_shed=0 events_dropped=0` at the app layer. Asserting
    #    `shed > 0` alone would therefore fail a correctly-behaving system and,
    #    worse, imply the token bucket is the thing protecting the broker under
    #    this traffic shape. It is not -- the kernel is, and the only reason
    #    that is visible at all is the P0-4 rcvbuf counter.
    shed_or_kernel = shed + dropped + queue_full + kernel
    check(shed_or_kernel > 0,
          f"a {send_rate:.0f}/s flood against a {cap:g}/s cap produced NO "
          f"accounted loss at all (shed={shed} dropped={dropped} "
          f"queue_full={queue_full} kernel_rcvbuf_errors={kernel}) -- traffic "
          f"went somewhere entirely uncounted, the silent-loss class the "
          f"module docstring warns about")
    check(accounted <= sent,
          f"counters account for {accounted} events but only {sent} were sent "
          f"-- double counting somewhere")

    # 3. The service survived.
    health = sh("docker", "exec", WS1, "python", "-c",
                "import urllib.request;print(urllib.request.urlopen("
                "'http://127.0.0.1:8001/health',timeout=5).status)")
    check(health.returncode == 0 and "200" in health.stdout,
          f"ws1 /health did not answer 200 after the flood "
          f"({health.stdout.strip() or health.stderr.strip()})")

    if FAILS:
        print(f"\n[FAIL] B2 backpressure load test: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        return 1
    print(f"\n[OK] B2 backpressure under a real flood PASS -- {sent} datagrams "
          f"at {send_rate:.0f}/s against a {cap:g}/s cap: only {produced} reached "
          f"the bus, and ws1 stayed healthy. Accounted loss: shed={shed} "
          f"dropped={dropped} queue_full={queue_full} "
          f"kernel_rcvbuf_errors={kernel}.")
    if shed == 0 and (queue_full > 0 or kernel > 0):
        print("     MEASURED FINDING: B2's token bucket shed NOTHING "
              "(events_shed=0). What actually bounded the broker was the P0-4 "
              "recv->worker queue (events_queue_full=%d) and the kernel receive "
              "buffer (%d). The ordering explains it: _recv_loop does "
              "queue.put_nowait FIRST and counts events_queue_full on refusal; "
              "the token bucket lives downstream in _worker_loop and only sheds "
              "when datagrams get past the queue. So under sustained overload "
              "the bounded queue is the protection, and the bucket is the "
              "steady-state rate cap -- not the flood defense its name "
              "suggests. Both are counted, so nothing is silently lost."
              % (queue_full, kernel))
    print(f"     Scope: proves the bus is bounded and loss is accounted. Says "
          f"nothing about whether {cap:g}/s is the right cap -- that remains an "
          f"untuned default per SSOT.md.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
