"""WS-1 Collectors entrypoint.

Wires the syslog / SNMP / NetFlow collectors to the message bus (Contract B):
raw payloads -> ``raw.events`` (partition key = source IP), asset observations
-> ``assets.updates`` (partition key = mac, falling back to ip).

Runs offline against the bundled mocks when no real transport is configured.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))  # for `shared`

from shared.bus import Bus  # noqa: E402
from collectors.syslog_collector import SyslogCollector  # noqa: E402
from collectors.snmp_collector import SnmpCollector  # noqa: E402
from collectors.netflow_collector import NetflowCollector  # noqa: E402

MOCKS = HERE / "mocks"


def _int_env(name: str, default: int, log) -> int:
    """int(os.getenv(name)) that degrades to `default` (logged) on a
    malformed value instead of crashing startup over a typo'd env var."""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        log.warn("malformed env var, using default", name=name, value=raw, default=default)
        return default


def build_collectors():
    syslog = SyslogCollector()
    snmp = SnmpCollector(devices_file=str(MOCKS / "sample_snmp.json"))
    netflow = NetflowCollector(flows_file=str(MOCKS / "sample_netflow.json"))
    return syslog, snmp, netflow


def run_once(bus) -> dict:
    """One collection cycle over the mock sources. Returns counts (for tests)."""
    syslog, snmp, netflow = build_collectors()
    raw_count = 0
    asset_count = 0

    # syslog: streaming source
    for line in (MOCKS / "sample_syslog.txt").read_text(encoding="utf-8").splitlines():
        payload = syslog.handle_line(line)
        if payload:
            bus.produce("raw.events", key=payload["meta"]["ip"], payload=payload)
            raw_count += 1

    # snmp + netflow: polling sources
    for collector in (snmp, netflow):
        for payload in collector.poll():
            bus.produce("raw.events", key=payload["meta"]["ip"], payload=payload)
            raw_count += 1

    # drain asset observations
    for collector in (syslog, snmp, netflow):
        for obs in collector.asset_observations():
            key = obs.get("mac") or obs.get("ip") or "unknown"
            bus.produce("assets.updates", key=key, payload=obs)
            asset_count += 1

    return {"raw.events": raw_count, "assets.updates": asset_count}


def main() -> None:
    # Daemon: seed raw.events once from the bundled mock sources (offline-friendly),
    # then start the REAL live ingestion path — a UDP syslog listener — and stay up
    # behind the runner's /health endpoint until SIGTERM. WS-1 is a producer, not a
    # bus consumer, so it uses the runner's health-only mode (empty handler map);
    # the runner owns the signal handling + graceful shutdown loop.
    import threading  # noqa: E402

    from shared.runner import serve  # noqa: E402
    from shared.log import get_logger  # noqa: E402
    from collectors.syslog_udp_server import (  # noqa: E402
        SyslogUDPServer, DEFAULT_HOST, DEFAULT_PORT, DEFAULT_MAX_EVENTS_PER_SEC,
        DEFAULT_WORKERS, DEFAULT_QUEUE_MAXSIZE, DEFAULT_SO_RCVBUF, udp_rcvbuf_errors)
    from collectors.spool import BoundedSpool, DEFAULT_MAX_BYTES as SPOOL_DEFAULT_MAX_BYTES  # noqa: E402

    log = get_logger("ws1-collectors")

    bus = Bus()
    counts = run_once(bus)
    log.info("seeded", raw_events=counts["raw.events"],
             asset_updates=counts["assets.updates"])

    # Live syslog ingestion (env-configurable; 5514 avoids privileged 514).
    syslog_host = os.getenv("SYSLOG_UDP_HOST", DEFAULT_HOST)
    syslog_port = int(os.getenv("SYSLOG_UDP_PORT", str(DEFAULT_PORT)))
    max_events_per_sec = float(os.getenv("SYSLOG_MAX_EVENTS_PER_SEC",
                                        str(DEFAULT_MAX_EVENTS_PER_SEC)))
    # B2 zero-loss-under-flood opt-in (see collectors/spool.py): unset by
    # default (plain shed-and-count, no disk I/O). Set SYSLOG_SPOOL_PATH to
    # enable a bounded on-disk replay buffer for shed/dropped events.
    spool_path = os.getenv("SYSLOG_SPOOL_PATH")
    spool = None
    if spool_path:
        spool_max_bytes = _int_env("SYSLOG_SPOOL_MAX_BYTES", SPOOL_DEFAULT_MAX_BYTES, log)
        spool = BoundedSpool(spool_path, max_bytes=spool_max_bytes)
        log.info("syslog zero-loss spool enabled", path=spool_path, max_bytes=spool_max_bytes)
    # P0-4 (2026-07-21 audit): recv/dispatch decoupling knobs -- see
    # syslog_udp_server.py's module docstring for the live-proven kernel-drop
    # issue these exist to fix.
    udp_workers = _int_env("SYSLOG_UDP_WORKERS", DEFAULT_WORKERS, log)
    udp_queue_maxsize = _int_env("SYSLOG_UDP_QUEUE_MAXSIZE", DEFAULT_QUEUE_MAXSIZE, log)
    udp_so_rcvbuf = _int_env("SYSLOG_UDP_SO_RCVBUF", DEFAULT_SO_RCVBUF, log)

    udp = None
    try:
        udp = SyslogUDPServer(bus, host=syslog_host, port=syslog_port,
                              max_events_per_sec=max_events_per_sec,
                              spool=spool, logger=log,
                              workers=udp_workers, queue_maxsize=udp_queue_maxsize,
                              so_rcvbuf=udp_so_rcvbuf)
        udp.start()
    except OSError as exc:
        # e.g. port in use, or 514 without elevation. Stay up for /health anyway.
        log.error("syslog UDP bind failed", host=syslog_host, port=syslog_port,
                  error=str(exc))

    def _syslog_metrics() -> dict:
        if udp is None:
            return {}
        m = {
            "events_produced": udp.events_produced,
            "events_dropped": udp.events_dropped,
            "events_shed": udp.events_shed,
            "events_spooled": udp.events_spooled,
            "events_lost": udp.events_lost,
            "events_queue_full": udp.events_queue_full,
            # FENGARDE E6: bounded per-source breakdown {ip: {produced,
            # dropped, shed}} -- a dict with a capped (LRU-evicted) map, so
            # /metrics can show which peer IPs are flooding/shedding without
            # the map itself growing without bound. Aggregates above stay
            # authoritative (and lossless); this is a visibility partition.
            "per_source": udp.per_source_metrics(),
        }
        # P0-4: the kernel-level drop counter (RcvbufErrors) -- the loss
        # class that reads as a healthy events_shed=0/events_dropped=0 at the
        # app layer alone (live-proven). None off-Linux / procfs unavailable;
        # omitted rather than reported as a misleading 0.
        kernel_rcvbuf_errors = udp_rcvbuf_errors()
        if kernel_rcvbuf_errors is not None:
            m["udp_rcvbuf_errors_cumulative"] = kernel_rcvbuf_errors
        # Ingestion-edge-redundancy design doc (fengarde-sec) step 2: the
        # "healthy but nothing is arriving" signal /health never had.
        m["seconds_since_last_event"] = round(udp.seconds_since_last_event(), 1)
        return {"syslog_udp": m}

    shutdown = threading.Event()
    depth_thread = _start_depth_watchdog(bus, log, shutdown)
    silence_thread = _start_ingest_silence_watchdog(udp, log, shutdown)
    try:
        serve({}, health_port=int(os.getenv("PORT", "8001")),
              service_name="ws1-collectors", shutdown=shutdown,
              metrics_provider=_syslog_metrics)
    finally:
        if udp is not None:
            udp.stop()
        if depth_thread is not None:
            depth_thread.join(timeout=5)
        if silence_thread is not None:
            silence_thread.join(timeout=5)


def _start_depth_watchdog(bus, log, shutdown, *, topic: str = "raw.events",
                          interval_s: float = 30.0):
    """B2/P2.4: thin wrapper over the shared watchdog (shared.runner) that keeps
    ws1's own env var name (RAW_EVENTS_DEPTH_WARN, default 100000, 0 disables)."""
    from shared.runner import start_depth_watchdog
    warn_at = int(os.getenv("RAW_EVENTS_DEPTH_WARN", "100000"))
    return start_depth_watchdog(bus, log, shutdown, [topic], warn_at=warn_at,
                                interval_s=interval_s)


def _start_ingest_silence_watchdog(udp, log, shutdown, *, interval_s: float = 30.0):
    """Ingestion-edge-redundancy design doc (fengarde-sec, 2026-08-06) step 2:
    "a healthy-but-silent ws1 with no sources looks fine" today -- /health
    only probes the bus, never whether any datagram has actually arrived.
    Same shape as _start_depth_watchdog (periodic check, structured warn log,
    env-configurable threshold, 0 disables) so an operator scanning ws1's
    logs sees one consistent watchdog convention, not two.

    SYSLOG_SILENCE_WARN_S default 300s (5min) -- long enough that a quiet
    network at 3am doesn't page anyone, short enough to catch "the feed died
    an hour ago and nobody noticed" well before an analyst would otherwise.
    No shipped default is a measured number (same "untuned guess, disclosed"
    posture as every other B2-class threshold in this project) -- tune
    against real traffic patterns.

    udp=None (bind failed at startup, main() logs and stays up for /health
    only) disables this: there is nothing to watch, and "silent" would be
    permanently and misleadingly true.
    """
    if udp is None:
        return None
    warn_after_s = float(os.getenv("SYSLOG_SILENCE_WARN_S", "300"))
    if warn_after_s <= 0:
        return None

    import threading  # local: mirrors this module's other lazy imports

    def _loop():
        warned = False
        while not shutdown.is_set():
            silence_s = udp.seconds_since_last_event()
            if silence_s >= warn_after_s:
                if not warned:
                    log.warn("no syslog datagrams received recently",
                            seconds_since_last_event=round(silence_s, 1),
                            threshold_s=warn_after_s)
                    warned = True
                # else: already warned, stay quiet until it recovers -- this
                # loop's own interval_s would otherwise re-warn every 30s for
                # as long as the outage lasts, drowning the one signal that
                # matters (it started) in repeats of itself.
            else:
                warned = False
            shutdown.wait(interval_s)

    t = threading.Thread(target=_loop, name="ingest-silence-watchdog", daemon=True)
    t.start()
    return t


if __name__ == "__main__":
    main()
